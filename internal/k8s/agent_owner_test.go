package k8s

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
)

func TestAgentOwnerResolutionRejectsOtherWorkloadsAndReleases(t *testing.T) {
	pod := func(name, instance, component string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "Pod",
			"metadata": map[string]any{"name": name, "namespace": "system", "labels": map[string]any{"app.kubernetes.io/name": "kube-workspaces", "app.kubernetes.io/instance": instance, "app.kubernetes.io/component": component}},
			"spec":     map[string]any{"serviceAccountName": "proxy"}, "status": map[string]any{"podIP": "192.0.2.5"},
		}}
	}
	c := &Client{dynamic: fake.NewSimpleDynamicClient(runtime.NewScheme(), pod("self", "a", "proxy"), pod("peer", "a", "proxy"), pod("other-release", "b", "proxy"), pod("workspace", "a", "workspace"))}
	ctx := context.Background()
	if host, err := c.ResolveAgentOwner(ctx, "system", "self", "peer", "8091"); err != nil || host != "192.0.2.5:8091" {
		t.Fatalf("host=%s err=%v", host, err)
	}
	for _, owner := range []string{"other-release", "workspace", "https://external.example"} {
		if _, err := c.ResolveAgentOwner(ctx, "system", "self", owner, "8091"); err == nil {
			t.Fatalf("resolved unrelated owner %s", owner)
		}
	}
}
