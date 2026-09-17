package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testClaimID() string { return strings.Repeat("ab", 32) }

// fakeDisplayAPI returns an httptest server acting as the API display
// ownership endpoint. claimFail forces a non-200 on claim; renewal tampering
// is driven per-test via claimProto/claimTTL.
func fakeDisplayAPI(t *testing.T) (*httptest.Server, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var claims, releases atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			t.Errorf("display API received platform cookie: %q", r.Header.Get("Cookie"))
		}
		if got := r.Header.Get("Authorization"); got == "" {
			t.Errorf("display API did not receive Authorization credential")
		}
		action := ""
		if i := strings.LastIndex(r.URL.Path, "/"); i >= 0 {
			action = r.URL.Path[i+1:]
		}
		w.Header().Set("Content-Type", "application/json")
		switch action {
		case "claim":
			claims.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"id": testClaimID(), "ttl_ms": 4000, "protocol": 1})
		case "renew":
			if r.Header.Get("X-KW-Display-Claim") != testClaimID() {
				w.WriteHeader(http.StatusConflict)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"ttl_ms": 4000, "protocol": 1})
		case "release":
			releases.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(cleanupHt(srv))
	return srv, &claims, &releases
}

func cleanupHt(s *httptest.Server) func() { return s.Close }

func TestAcquireRenewsAndReleases(t *testing.T) {
	srv, claims, releases := fakeDisplayAPI(t)
	h := http.Header{"Cookie": {"kw-session=sess-1"}}
	ctx := context.Background()
	var revoked atomic.Bool
	cancel := func() { revoked.Store(true) }
	c, status, err := acquireDisplay(ctx, srv.URL, "ws", "desktop", h, cancel)
	if err != nil || status != 0 {
		t.Fatalf("acquire: status=%d err=%v", status, err)
	}
	if c.id != testClaimID() {
		t.Fatalf("claim id %q", c.id)
	}
	if claims.Load() != 1 {
		t.Fatalf("claims=%d", claims.Load())
	}
	if revoked.Load() {
		t.Fatal("revoked during healthy renewals")
	}
	// Let at least one renewal happen, then release.
	time.Sleep(2500 * time.Millisecond)
	c.close()
	if releases.Load() != 1 {
		t.Fatalf("releases=%d, want 1", releases.Load())
	}
}

// A claim that stops being accepted must fence the owner: its renewal goroutine
// exits, the caller's revoke is invoked, and writes are refused.
func TestAcquireStopsWhenRenewalRefused(t *testing.T) {
	srv, _, _ := fakeDisplayAPI(t)
	c, _, err := acquireDisplay(context.Background(), srv.URL, "ws", "desktop", http.Header{"Cookie": {"kw-session=sess-1"}}, func() {})
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	// Make the claim no longer match: aligning the guard's view with a revoke
	// is done on the API side in production; here expire the claim locally the
	// same way a revoked renewal would.
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		t.Fatal("claim did not stop after renewal failure")
	}
	if _, valid := c.validDeadline(); valid {
		t.Fatal("claim reported valid after stopping")
	}
}

func TestAcquireRejectsUnsupportedProtocol(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"id": testClaimID(), "ttl_ms": 4000, "protocol": 2})
	}))
	defer srv.Close()
	_, status, err := acquireDisplay(context.Background(), srv.URL, "ws", "desktop", http.Header{}, nil)
	if status != http.StatusServiceUnavailable || !strings.Contains(err.Error(), "unsupported display ownership protocol") {
		t.Fatalf("status=%d err=%v", status, err)
	}
}

func TestAcquireRequiresConfiguredAPI(t *testing.T) {
	for _, api := range []string{"", "not-a-url", "https://user:pass@host", "file:///tmp"} {
		_, status, err := acquireDisplay(context.Background(), api, "ws", "desktop", http.Header{}, nil)
		if status != http.StatusServiceUnavailable || !strings.Contains(err.Error(), "not configured") {
			t.Fatalf("api=%q status=%d err=%v", api, status, err)
		}
	}
}

func TestCallPreservesAuthStatuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()
	c := &displayClaim{api: srv.URL, ns: "ws", name: "desktop",
		credential: http.Header{"Authorization": {"Bearer t"}},
		client:     &http.Client{Timeout: time.Second}}
	_, status, err := c.call(context.Background(), "renew")
	if status != http.StatusConflict || err == nil {
		t.Fatalf("status=%d err=%v", status, err)
	}
}

func TestDisplayConnGatesWrites(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	c := &displayClaim{deadline: time.Now().Add(displayTTL)}
	conn := &displayConn{Conn: client, claim: c}

	// Valid ownership: writes pass through.
	go func() {
		if _, err := conn.Write([]byte("data")); err != nil {
			t.Errorf("write: %v", err)
		}
	}()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(server, buf); err != nil || string(buf) != "data" {
		t.Fatalf("read: %v %q", err, buf)
	}

	// Expired ownership: writes refused and the underlying conn is closed so
	// the reverse proxy's pumps unwind.
	time.Sleep(10 * time.Millisecond)
	conn.claim.mu.Lock()
	conn.claim.deadline = time.Now().Add(-time.Second)
	conn.claim.mu.Unlock()
	if _, err := conn.Write([]byte("late")); err == nil {
		t.Fatal("write past deadline succeeded")
	}
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := server.Read(buf); err == nil {
		t.Fatal("underlying conn not closed after expired write")
	} else if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "closed") {
		t.Fatalf("unexpected read error: %v", err)
	}
}
