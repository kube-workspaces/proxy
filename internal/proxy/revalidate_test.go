package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"

	"github.com/kube-workspaces/proxy/internal/auth"
)

// revalidatingProxy serves a proxied WebSocket whose credential is revoked
// after the first revalidation tick.
func revalidatingProxy(t *testing.T, revoke func() bool) *httptest.Server {
	t.Helper()
	guest := httptest.NewServer(websocket.Handler(func(ws *websocket.Conn) {
		defer ws.Close()
		_, _ = io.Copy(io.Discard, ws)
	}))
	t.Cleanup(guest.Close)

	guestAddr := strings.TrimPrefix(guest.URL, "http://")
	h := Handler(&HandlerOptions{
		PathPrefix: "/proxy",
		BackendDial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, guestAddr)
		},
		Revalidate: func(context.Context) error {
			if revoke() {
				return auth.ErrCredentialRevoked
			}
			return nil
		},
		RevalidateInterval: 10 * time.Millisecond,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestProxiedWebSocketEndsWhenCredentialIsRevoked(t *testing.T) {
	var revoked atomic.Bool
	srv := revalidatingProxy(t, revoked.Load)

	ws, err := websocket.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/proxy/ns/ws/socket", "", "http://test")
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	// The stream is open and idle.
	if err := websocket.Message.Send(ws, []byte("ping")); err != nil {
		t.Fatal(err)
	}

	revoked.Store(true)

	ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	var payload []byte
	if err := websocket.Message.Receive(ws, &payload); err == nil {
		t.Fatal("expected the proxied connection to end after the revocation")
	} else {
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			t.Fatalf("connection timed out instead of closing: %v", err)
		}
	}
}

func TestProxiedStreamStaysOpenWhileCredentialIsValid(t *testing.T) {
	srv := revalidatingProxy(t, func() bool { return false })

	ws, err := websocket.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/proxy/ns/ws/socket", "", "http://test")
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	if err := websocket.Message.Send(ws, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	ws.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	var payload []byte
	if err := websocket.Message.Receive(ws, &payload); err == nil {
		t.Fatal("expected no data from the idle stream")
	} else {
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("valid connection closed: %v", err)
		}
	}
}

func TestProxiedEventStreamEndsWhenCredentialIsRevoked(t *testing.T) {
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: ready\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer guest.Close()

	var revoked atomic.Bool
	guestAddr := strings.TrimPrefix(guest.URL, "http://")
	h := Handler(&HandlerOptions{
		PathPrefix: "/proxy",
		BackendDial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, guestAddr)
		},
		Revalidate: func(context.Context) error {
			if revoked.Load() {
				return auth.ErrCredentialRevoked
			}
			return nil
		},
		RevalidateInterval: 10 * time.Millisecond,
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	req, _ := http.NewRequest("GET", srv.URL+"/proxy/ns/ws/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, len("data: ready\n\n"))
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatal(err)
	}

	revoked.Store(true)

	// The stream must end rather than keep delivering events.
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(resp.Body)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the event stream to end after the revocation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event stream did not end after the revocation")
	}
}
