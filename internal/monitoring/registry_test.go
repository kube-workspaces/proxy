package monitoring

import (
	"context"
	"testing"
)

func TestAgentHelloSnapshot(t *testing.T) {
	r := New("proxy-test")
	s := r.Start(Metadata{WorkspaceUID: "uid-1", Namespace: "team", Name: "win-0", Transport: "agent"})
	ctx := WithSession(context.Background(), s)

	if got := r.Snapshot(); len(got.Connections) != 1 || got.Connections[0].GuestVersion != "" {
		t.Fatalf("version present before hello: %+v", got.Connections)
	}
	AgentHello(ctx, "0.4.0", "windows", 1920, 1080)
	AgentHello(ctx, "9.9.9", "linux", 800, 600)
	got := r.Snapshot()
	if len(got.Connections) != 1 {
		t.Fatalf("connections = %d, want 1", len(got.Connections))
	}
	c := got.Connections[0]
	if c.GuestVersion != "0.4.0" || c.GuestPlatform != "windows" || c.CaptureWidth != 1920 || c.CaptureHeight != 1080 {
		t.Fatalf("guest = %+v, want first hello kept", c)
	}
	// Nil session is a no-op, never a panic.
	AgentHello(context.Background(), "x", "y", 1, 1)
}
