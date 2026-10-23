package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kube-workspaces/proxy/internal/monitoring"
	"golang.org/x/net/websocket"
)

func TestMonitoringHTTPBodiesAndWebSocketTraffic(t *testing.T) {
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" {
			websocket.Handler(func(c *websocket.Conn) {
				defer c.Close()
				for {
					var p []byte
					if err := websocket.Message.Receive(c, &p); err != nil {
						return
					}
					if err := websocket.Message.Send(c, p); err != nil {
						return
					}
				}
			}).ServeHTTP(w, r)
			return
		}
		_, _ = io.Copy(w, r.Body)
	}))
	defer guest.Close()
	reg := monitoring.New("proxy")
	// Redirect the in-cluster dial to the test guest without changing HTTP or
	// WS instrumentation. A test-only transport dial hook is operator-internal.
	guestAddr := strings.TrimPrefix(guest.URL, "http://")
	h := Handler(&HandlerOptions{Monitoring: reg, PathPrefix: "/proxy", WorkspaceInfoLookup: func(string, string) *WorkspaceInfo { return &WorkspaceInfo{UID: "uid", Type: "container"} }, BackendDial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, guestAddr)
	}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/proxy/ns/ws/echo", "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "payload" {
		t.Fatalf("body %q", body)
	}
	snap := reg.Snapshot()
	// Reading EOF on the HTTP body can precede the server handler's deferred
	// session cleanup, especially under race/coverage instrumentation.
	httpDeadline := time.Now().Add(time.Second)
	for len(snap.Connections) != 0 && time.Now().Before(httpDeadline) {
		time.Sleep(time.Millisecond)
		snap = reg.Snapshot()
	}
	if len(snap.Connections) != 0 || len(snap.Traffic) != 1 || snap.Traffic[0].ToWorkspace != 7 || snap.Traffic[0].ToClient != 7 {
		t.Fatalf("HTTP body accounting: %+v", snap)
	}
	c, err := websocket.Dial("ws"+strings.TrimPrefix(srv.URL, "http")+"/proxy/ns/ws/ws", "", "http://test")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = websocket.Message.Send(c, []byte("test"))
	var p []byte
	err = websocket.Message.Receive(c, &p)
	if err != nil || string(p) != "test" {
		t.Fatalf("WS echo: %q %v", p, err)
	}
	snap = reg.Snapshot()
	if len(snap.Connections) != 1 || snap.Connections[0].Category != "application" || snap.Connections[0].ToWorkspace != 10 || snap.Connections[0].ToClient != 6 {
		t.Fatalf("WS framing/handshake accounting: %+v", snap)
	}
	c.Close()
	deadline := time.Now().Add(time.Second)
	for len(reg.Snapshot().Connections) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(reg.Snapshot().Connections) != 0 {
		t.Fatal("disconnect retained connection")
	}
}

func TestAgentRenewContractAndFailureCancellation(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if fail {
					w.WriteHeader(404)
					return
				}
				_, _ = io.WriteString(w, `{"ttl_ms":20,"protocol":1}`)
			}))
			defer api.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			deps := &agentDeps{API: api.URL}
			if !fail {
				if _, _, err := deps.agentCall(ctx, "renew", api.URL, "ns", "ws", nil, "id"); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan struct{})
			go func() {
				agentRenewLoop(ctx, deps, "ns", "ws", nil, agentTicket{ID: "id", TTLMillis: 20}, cancel)
				close(done)
			}()
			if fail {
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("renewal failure did not cancel bridge")
				}
			} else {
				select {
				case <-ctx.Done():
					t.Fatal("valid renew canceled bridge")
				case <-time.After(50 * time.Millisecond):
				}
				cancel()
			}
			<-done
		})
	}
}

func TestMonitoringSSEIsAnEstablishedApplicationStream(t *testing.T) {
	guest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: ready\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer guest.Close()
	reg := monitoring.New("proxy")
	h := Handler(&HandlerOptions{Monitoring: reg, PathPrefix: "/proxy", BackendDial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(guest.URL, "http://"))
	}})
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
	if _, err = io.ReadFull(resp.Body, buf); err != nil {
		t.Fatal(err)
	}
	snap := reg.Snapshot()
	if len(snap.Connections) != 1 || snap.Connections[0].Category != "application" || snap.Connections[0].Transport != "sse" || snap.Connections[0].State != "established" || snap.Connections[0].ToClient != uint64(len(buf)) {
		t.Fatalf("SSE inventory: %+v", snap)
	}
}

func TestMonitoringAgentControlOnlyAndFailedUpgradeCleanup(t *testing.T) {
	var counters agentCounters
	api := fakeAgentAPI(t, false, &counters)
	guest := fakeGuestAgent(t)
	reg := monitoring.New("proxy")
	h := Handler(&HandlerOptions{Monitoring: reg, PathPrefix: "/proxy", AgentAPIURL: api.URL, WorkspaceInfoLookup: func(string, string) *WorkspaceInfo { return &WorkspaceInfo{UID: "uid", Type: "vm", Image: "agent"} }, ConfigLookup: func(string) *Config { return &Config{AgentPort: guestPort(t, guest)} }, AgentDial: func(ctx context.Context, ns, name string, port int32) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", guest.Addr().String())
	}})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c, err := dialAuth(t, "ws"+strings.TrimPrefix(srv.URL, "http")+"/proxy/ns/ws/agent/")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	deadline := time.Now().Add(time.Second)
	for {
		snap := reg.Snapshot()
		if len(snap.Connections) == 1 && snap.Connections[0].State == "established" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent never established")
		}
		time.Sleep(time.Millisecond)
	}
	frame := append([]byte{0}, u32be(len(`{"type":"ping"}`))...)
	frame = append(frame, []byte(`{"type":"ping"}`)...)
	if err = websocket.Message.Send(c, frame); err != nil {
		t.Fatal(err)
	}
	var reply []byte
	if err = websocket.Message.Receive(c, &reply); err != nil {
		t.Fatal(err)
	}
	snap := reg.Snapshot()
	conn := snap.Connections[0]
	if conn.Transport != "agent" || conn.Tier != "1" || conn.MediaObserved || conn.GuestAdmitted || conn.Role != "agent_display" || conn.ToClient == 0 {
		t.Fatalf("control-only bridge mislabeled as media/controller: %+v", conn)
	}
	c.Close()
	deadline = time.Now().Add(time.Second)
	for len(reg.Snapshot().Connections) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(reg.Snapshot().Connections) > 0 {
		t.Fatal("agent connection retained after close")
	}
	before := counters.releases.Load()
	req, _ := http.NewRequest("GET", srv.URL+"/proxy/ns/other/agent/", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Authorization", "Bearer test")
	req.Header.Set("Connection", "Upgrade")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 || counters.releases.Load() != before+1 {
		t.Fatalf("failed upgrade did not release grant: status=%d releases=%d", resp.StatusCode, counters.releases.Load())
	}
}
