package auth

import (
	"context"
	"errors"
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

// TestNotFoundMeansAuthDisabled: no AuthConfig CR means auth is genuinely
// off (opt-in), not a load failure.
func TestNotFoundMeansAuthDisabled(t *testing.T) {
	p := NewConfigProvider(newFakeDynamic())
	cfg, err := p.loadFromCluster(context.Background())
	if err != nil {
		t.Fatalf("loadFromCluster: %v", err)
	}
	if cfg.Enabled {
		t.Fatal("auth must not be considered enabled when the AuthConfig is absent")
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

// TestStaleCacheServedOnRefreshFailure: after a successful first load, a
// refresh error must keep serving the cached config rather than deny or
// downgrade. Notably, serving stale must NOT flip enabled → disabled, and
// NotFound on refresh must never convert a good enabled config into pass-through.
func TestStaleCacheServedOnRefreshFailure(t *testing.T) {
	provider := NewConfigProvider(newFakeDynamic(authConfigObj(true)))
	cfg, err := provider.GetConfig(context.Background())
	if err != nil || !cfg.Enabled {
		t.Fatalf("first load failed: cfg=%+v err=%v", cfg, err)
	}

	// Force staleness; the refresh on the request must also see NotFound (the
	// object vanished), and the cached enabled config is what gets served.
	provider.lastFetch = time.Now().Add(-time.Hour)
	provider.cacheDuration = time.Second
	client := newFakeDynamic()
	provider.dynamicClient = client

	cfg2, err := provider.GetConfig(context.Background())
	if err != nil {
		t.Fatalf("stale cache + refresh NotFound must still serve previous config, got err=%v", err)
	}
	if !cfg2.Enabled {
		t.Fatal("serving stale cache must not lose the enabled flag")
	}
}

// uncatchableBoom makes any "get" reaction fail, simulating a cluster outage.
func uncatchableBoom(t *testing.T) func(k8stesting.Action) (bool, runtime.Object, error) {
	return func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	}
}
