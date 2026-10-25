package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

func currentUser() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kubeworkspaces.io/v1alpha1", "kind": "User",
		"metadata": map[string]interface{}{"name": "user", "uid": "current-uid"},
		"spec":     map[string]interface{}{"email": "user@example.com", "role": "editor", "localAuth": map[string]interface{}{"enabled": true, "passwordSecretRef": map[string]interface{}{"name": "password", "key": "passwordHash"}}},
		"status":   map[string]interface{}{"personalNamespace": "personal"},
	}}
}

func currentPassword() *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "v1", "kind": "Secret", "metadata": map[string]interface{}{"name": "password", "namespace": deviceNamespace},
		"data": map[string]interface{}{"passwordHash": base64.StdEncoding.EncodeToString([]byte("test-hash"))},
	}}
}

func TestPasswordOwnershipEnforcedAtProxy(t *testing.T) {
	for _, mode := range []string{"legacy", "owned", "wrong-uid", "wrong-owner-reference"} {
		t.Run(mode, func(t *testing.T) {
			secret := currentPassword()
			if mode != "legacy" {
				secret.SetAnnotations(map[string]string{"kubeworkspaces.io/user-uid": "current-uid"})
			}
			if mode == "wrong-uid" {
				secret.SetAnnotations(map[string]string{"kubeworkspaces.io/user-uid": "other-uid"})
			}
			if mode == "wrong-owner-reference" {
				secret.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "kubeworkspaces.io/v1alpha1", Kind: "User", Name: "user", UID: "other-uid"}})
			}
			key := []byte("test-key")
			provider := NewConfigProvider(newFakeDynamic(currentUser(), secret))
			provider.config, provider.lastFetch = &AuthConfig{Enabled: true, SigningKey: key}, time.Now()
			token := signPayload(key, SessionToken{AuthMethod: "local", CredentialVersion: localCredentialVersion("current-uid", "password", "passwordHash", "test-hash"), Email: "user@example.com", Role: "admin", UserUID: "current-uid", ExpiresAt: time.Now().Add(time.Hour).Unix()})
			want := http.StatusOK
			if mode == "wrong-uid" || mode == "wrong-owner-reference" {
				want = http.StatusUnauthorized
			}
			if got := doRequest(t, provider, "/proxy/personal/workspace/", "Bearer "+token); got != want {
				t.Fatalf("ownership status %d, want %d", got, want)
			}
		})
	}
}

func TestCurrentAccountEnforcedBeforeAdminBypass(t *testing.T) {
	for _, tt := range []struct {
		name                         string
		mutate                       func(*unstructured.Unstructured)
		duplicate, missing, override bool
		uid                          string
		want                         int
	}{
		{name: "bound account", uid: "current-uid", want: 200},
		{name: "legacy unbound account", want: 401},
		{name: "replacement account", uid: "old-uid", want: 401},
		{name: "missing token admin", missing: true, want: 403},
		{name: "missing override admin", missing: true, override: true, want: 403},
		{name: "disabled override admin", override: true, mutate: func(u *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(u.Object, true, "spec", "disabled")
		}, want: 403},
		{name: "malformed disabled", mutate: func(u *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(u.Object, "false", "spec", "disabled")
		}, want: 403},
		{name: "deleting", mutate: func(u *unstructured.Unstructured) { now := metav1.Now(); u.SetDeletionTimestamp(&now) }, want: 403},
		{name: "invalid role", override: true, mutate: func(u *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(u.Object, "superuser", "spec", "role")
		}, want: 403},
		{name: "duplicate email", duplicate: true, want: 403},
		{name: "case mismatch", mutate: func(u *unstructured.Unstructured) {
			_ = unstructured.SetNestedField(u.Object, "USER@example.com", "spec", "email")
		}, want: 403},
	} {
		t.Run(tt.name, func(t *testing.T) {
			user := currentUser()
			if tt.mutate != nil {
				tt.mutate(user)
			}
			objs := []runtime.Object{currentPassword()}
			if !tt.missing {
				objs = append(objs, user)
			}
			if tt.duplicate {
				duplicate := user.DeepCopy()
				duplicate.SetName("duplicate")
				duplicate.SetUID("another-uid")
				objs = append(objs, duplicate)
			}
			key := []byte("test-key")
			cfg := &AuthConfig{Enabled: true, SigningKey: key}
			if tt.override {
				cfg.AdminEmails = []string{"user@example.com"}
			}
			provider := NewConfigProvider(newFakeDynamic(objs...))
			provider.config, provider.lastFetch = cfg, time.Now()
			token := signPayload(key, SessionToken{AuthMethod: "local", CredentialVersion: localCredentialVersion("current-uid", "password", "passwordHash", "test-hash"), Email: "user@example.com", Role: "admin", UserUID: tt.uid, ExpiresAt: time.Now().Add(time.Hour).Unix()})
			if got := doRequest(t, provider, "/proxy/personal/workspace/", "Bearer "+token); got != tt.want {
				t.Fatalf("status=%d, want %d", got, tt.want)
			}
		})
	}
}

func TestDeviceRegistrationRequiredAtProxy(t *testing.T) {
	for _, tt := range []struct {
		name                                                         string
		missing, revoked, expired, wrongOwner, malformed, stringData bool
	}{
		{name: "registered"}, {name: "fake client stringData", stringData: true},
		{name: "missing", missing: true}, {name: "revoked", revoked: true},
		{name: "expired", expired: true}, {name: "wrong owner", wrongOwner: true},
		{name: "malformed", malformed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := map[string]interface{}{"email": "user@example.com", "revoked": "false", "expiresAt": strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)}
			if tt.revoked {
				data["revoked"] = "true"
			}
			if tt.expired {
				data["expiresAt"] = "1"
			}
			if tt.wrongOwner {
				data["email"] = "other@example.com"
			}
			if tt.malformed {
				data["expiresAt"] = "invalid"
			}
			field := "data"
			if tt.stringData {
				field = "stringData"
			} else {
				for k, v := range data {
					data[k] = base64.StdEncoding.EncodeToString([]byte(v.(string)))
				}
			}
			secret := &unstructured.Unstructured{Object: map[string]interface{}{
				"apiVersion": "v1", "kind": "Secret",
				"metadata": map[string]interface{}{"name": "kw-device-device-id", "namespace": deviceNamespace}, field: data,
			}}
			objs := []runtime.Object{currentUser(), currentPassword()}
			if !tt.missing {
				objs = append(objs, secret)
			}
			client := newFakeDynamic(objs...)
			provider := NewConfigProvider(client)
			key := []byte("test-key")
			provider.config = &AuthConfig{Enabled: true, SigningKey: key, AdminEmails: []string{"user@example.com"}}
			provider.lastFetch = time.Now()
			token := signPayload(key, SessionToken{AuthMethod: "local", CredentialVersion: localCredentialVersion("current-uid", "password", "passwordHash", "test-hash"), Email: "user@example.com", Role: "admin", UserUID: "current-uid", Type: "device", JTI: "device-id", ExpiresAt: time.Now().Add(time.Hour).Unix()})
			// Use a cookie here as well as Bearer to cover browser-session handoff.
			req := httptest.NewRequest("GET", "/proxy/personal/workspace/", nil)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
			handler := Middleware(provider, "/proxy")(nextOK())
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			want := 200
			if tt.missing || tt.revoked || tt.expired || tt.wrongOwner || tt.malformed {
				want = 401
			}
			if rec.Code != want {
				t.Fatalf("status=%d, want %d: %s", rec.Code, want, rec.Body.String())
			}
			if want == 200 {
				if err := client.Resource(secretGVR).Namespace(deviceNamespace).Delete(context.Background(), secret.GetName(), metav1.DeleteOptions{}); err != nil {
					t.Fatal(err)
				}
				rec = httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				if rec.Code != 401 {
					t.Fatalf("deleted registration still authorized: %d", rec.Code)
				}
			}
		})
	}
}
