package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newFakeDynamic(objs ...runtime.Object) *fake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return fake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			authConfigGVR: "AuthConfigList",
			userGVR:       "UserList",
			secretGVR:     "SecretList",
		}, objs...)
}

func authConfigObj(enabled bool) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "kubeworkspaces.io", Version: "v1alpha1", Kind: "AuthConfig",
	})
	obj.SetName("default")
	obj.Object["spec"] = map[string]interface{}{"enabled": enabled}
	return obj
}

func TestSigningKeyUsesPodNamespace(t *testing.T) {
	for _, namespace := range []string{"", "kube-workspaces-system", "custom-install"} {
		t.Run("namespace="+namespace, func(t *testing.T) {
			t.Setenv("POD_NAMESPACE", namespace)
			ns := namespace
			if ns == "" {
				ns = "kube-workspaces-system"
			}
			config := authConfigObj(true)
			unstructured.SetNestedMap(config.Object, map[string]interface{}{
				"signingKey": map[string]interface{}{"name": "session", "key": "key"},
			}, "spec", "session")
			secret := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1", "kind": "Secret",
				"metadata": map[string]interface{}{"name": "session", "namespace": ns},
				"data":     map[string]interface{}{"key": base64.StdEncoding.EncodeToString([]byte("installation-key"))},
			}}
			client := newFakeDynamic(config, secret)
			cfg, err := NewConfigProvider(client).GetConfig(context.Background())
			if err != nil || string(cfg.SigningKey) != "installation-key" {
				t.Fatalf("namespace=%q config=%+v err=%v", namespace, cfg, err)
			}
			for _, action := range client.Actions() {
				if action.GetResource() == secretGVR && action.GetNamespace() != ns {
					t.Fatalf("looked up signing key in %q, want %q", action.GetNamespace(), ns)
				}
			}
		})
	}
}

func TestSigningKeyDoesNotFallBackFromExplicitPodNamespace(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "custom-install")
	secret := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]interface{}{"name": "session", "namespace": "kube-workspaces-system"},
		"data":     map[string]interface{}{"key": base64.StdEncoding.EncodeToString([]byte("other-installation-key"))},
	}}
	client := newFakeDynamic(secret)
	if key, err := NewConfigProvider(client).getSecret(context.Background(), "session", "key"); err == nil || key != "" {
		t.Fatalf("used another installation's key: %q err=%v", key, err)
	}
	for _, action := range client.Actions() {
		if action.GetResource() == secretGVR && action.GetNamespace() != "custom-install" {
			t.Fatalf("cross-installation Secret lookup in %q", action.GetNamespace())
		}
	}
}

func TestEnabledAuthRejectsUnavailableSigningKey(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "custom-install")
	for _, mode := range []string{"no reference", "no key field", "missing secret", "missing data key", "empty key", "unreadable secret"} {
		t.Run(mode, func(t *testing.T) {
			config := authConfigObj(true)
			if mode != "no reference" {
				ref := map[string]interface{}{"name": "session", "key": "key"}
				if mode == "no key field" {
					delete(ref, "key")
				}
				if err := unstructured.SetNestedMap(config.Object, ref, "spec", "session", "signingKey"); err != nil {
					t.Fatal(err)
				}
			}
			client := newFakeDynamic(config)
			if mode == "missing data key" || mode == "empty key" {
				data := map[string]interface{}{}
				if mode == "empty key" {
					data["key"] = ""
				}
				secret := &unstructured.Unstructured{Object: map[string]interface{}{
					"apiVersion": "v1", "kind": "Secret",
					"metadata": map[string]interface{}{"name": "session", "namespace": "custom-install"},
					"data":     data,
				}}
				if err := client.Tracker().Add(secret); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unreadable secret" {
				client.PrependReactor("get", "secrets", uncatchableBoom(t))
			}
			provider := NewConfigProvider(client)
			cfg, err := provider.GetConfig(context.Background())
			if cfg != nil || !errors.Is(err, ErrConfigUnavailable) {
				t.Fatalf("expected unavailable config, got cfg=%+v err=%v", cfg, err)
			}
			// A token signed with a known empty key must never reach an upstream,
			// even when it claims an administrator role.
			if got := doRequest(t, provider, "/proxy/ns/workspace/", "Bearer "+validToken(nil, "attacker@example.com", "admin")); got != http.StatusServiceUnavailable {
				t.Fatalf("request status=%d, want 503", got)
			}
		})
	}
}

func TestTokenValidationRejectsEmptySigningKey(t *testing.T) {
	if _, err := ValidateSessionToken(validToken(nil, "attacker@example.com", "admin"), nil); err == nil {
		t.Fatal("accepted token signed with an empty key")
	}
}

func TestAuthDisabledRequiresExplicitConfiguration(t *testing.T) {
	malformed := authConfigObj(false)
	malformed.Object["spec"] = map[string]interface{}{"enabled": "false"}
	missing := authConfigObj(false)
	missing.Object["spec"] = map[string]interface{}{}
	for _, obj := range []*unstructured.Unstructured{nil, malformed, missing, authConfigObj(false)} {
		client := newFakeDynamic()
		if obj != nil {
			if err := client.Tracker().Add(obj); err != nil {
				t.Fatal(err)
			}
		}
		cfg, err := NewConfigProvider(client).GetConfig(context.Background())
		if obj != nil && obj.Object["spec"].(map[string]interface{})["enabled"] == false {
			if err != nil || cfg == nil || cfg.Enabled {
				t.Fatalf("explicit disabled config=%+v err=%v", cfg, err)
			}
		} else if cfg != nil || !errors.Is(err, ErrConfigUnavailable) {
			t.Fatalf("invalid config must fail closed: cfg=%+v err=%v", cfg, err)
		}
	}
}

// TestGetConfigFailsClosedOnFirstLoad: a genuine cluster read failure (not
// NotFound) must surface as an error — never as pass-through auth-disabled.
func TestGetConfigFailsClosedOnFirstLoad(t *testing.T) {
	client := newFakeDynamic()
	client.PrependReactor("get", "authconfigs", uncatchableBoom(t))
	p := NewConfigProvider(client)
	cfg, err := p.GetConfig(context.Background())
	if err == nil || !errors.Is(err, ErrConfigUnavailable) {
		t.Fatalf("first-load cluster error must deny with ErrConfigUnavailable, got cfg=%+v err=%v", cfg, err)
	}
	if cfg != nil {
		t.Fatal("a failed first load must not become a usable config")
	}
}

func TestRefreshFailsClosedAndRecoversWithKeyRotation(t *testing.T) {
	config := authConfigObj(true)
	if err := unstructured.SetNestedMap(config.Object, map[string]interface{}{
		"name": "session", "key": "key",
	}, "spec", "session", "signingKey"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POD_NAMESPACE", "kube-workspaces-system")
	secret := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret",
		"metadata": map[string]interface{}{"name": "session", "namespace": "kube-workspaces-system"},
		"data":     map[string]interface{}{"key": base64.StdEncoding.EncodeToString([]byte("installation-key"))},
	}}
	provider := NewConfigProvider(newFakeDynamic(config, secret))
	cfg, err := provider.GetConfig(context.Background())
	if err != nil || !cfg.Enabled {
		t.Fatalf("first load failed: cfg=%+v err=%v", cfg, err)
	}

	// A vanished AuthConfig must deny, not disable authentication or authorize
	// against stale config. Cache failures to avoid hammering Kubernetes.
	provider.lastFetch = time.Now().Add(-time.Hour)
	provider.cacheDuration = time.Second
	client := newFakeDynamic()
	provider.dynamicClient = client

	cfg2, err := provider.GetConfig(context.Background())
	if cfg2 != nil || !errors.Is(err, ErrConfigUnavailable) {
		t.Fatalf("refresh must fail closed: cfg=%+v err=%v", cfg2, err)
	}
	actions := len(client.Actions())
	if cached, err := provider.GetConfig(context.Background()); cached != nil || !errors.Is(err, ErrConfigUnavailable) || len(client.Actions()) != actions {
		t.Fatal("failure was not cached")
	}
	// Recover with a rotated key. The old key is retained for one session
	// lifetime, including across an intervening configuration failure.
	secret.Object["data"] = map[string]interface{}{"key": base64.StdEncoding.EncodeToString([]byte("new-key"))}
	provider.dynamicClient = newFakeDynamic(config, secret)
	provider.lastFetch = time.Now().Add(-time.Hour)
	recovered, err := provider.GetConfig(context.Background())
	if err != nil || string(recovered.SigningKey) != "new-key" || string(recovered.PreviousSigningKey) != "installation-key" {
		t.Fatalf("rotation continuity lost: cfg=%+v err=%v", recovered, err)
	}
	oldToken := validToken([]byte("installation-key"), "user@example.com", "viewer")
	if _, err := ValidateSessionTokenWithKeys(oldToken, recovered.SessionSigningKeys()); err != nil {
		t.Fatalf("retired key should still work: %v", err)
	}
	provider.rotatedAt = time.Now().Add(-25 * time.Hour)
	provider.lastFetch = time.Now().Add(-time.Hour)
	expired, err := provider.GetConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateSessionTokenWithKeys(oldToken, expired.SessionSigningKeys()); err == nil {
		t.Fatal("retired key remained usable after rotation grace period")
	}
}

// uncatchableBoom makes any "get" reaction fail, simulating a cluster outage.
func uncatchableBoom(t *testing.T) func(k8stesting.Action) (bool, runtime.Object, error) {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	}
}
