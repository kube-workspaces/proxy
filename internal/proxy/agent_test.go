package proxy

// Tests for the agent transport bridge: ticket lifecycle, single-session
// discipline, frame caps, and the full WebSocket-to-TCP path.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

type agentCounters struct {
	attaches atomic.Int32
	renews   atomic.Int32
	releases atomic.Int32
}

// fakeAgentAPI acts as the API agent-ticket endpoint. refuseAttach forces a
// 403 on attach; renewals are counted.
func fakeAgentAPI(t *testing.T, refuseAttach bool, counters *agentCounters) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got == "" {
			t.Errorf("agent API did not receive Authorization credential")
		}
		if r.Header.Get("Cookie") != "" {
			t.Errorf("agent API received platform cookie")
		}
		action := ""
		if i := strings.LastIndex(r.URL.Path, "/"); i >= 0 {
			action = r.URL.Path[i+1:]
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/tier1/") {
			json.NewEncoder(w).Encode(map[string]any{"id": strings.Repeat("a", 64), "ttl_ms": 4000, "protocol": 1, "ok": true})
			return
		}
		// Mirror the real API contract: these POSTs require a JSON body
		// (Goa rejects bodiless posts with missing-payload). The fake
		// enforces it so the client can never regress to nil bodies.
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch action {
		case "attach":
			counters.attaches.Add(1)
			if refuseAttach {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			grant := base64.RawURLEncoding.EncodeToString([]byte(`{"workspaceUid":"ns","workspaceGeneration":"g1","audience":"workspace-agent","role":"controller","expiresAtNs":999999999999999999}`))
			json.NewEncoder(w).Encode(map[string]any{
				"id": "sess-test-1", "ticket": "sess-test-1." + grant + ".signature", "ttl_ms": 60000, "protocol": 1,
			})
		case "renew":
			counters.renews.Add(1)
			if r.Header.Get("X-KW-Agent-Session") != "sess-test-1" {
				w.WriteHeader(http.StatusConflict)
				return
			}
			if payload["session_id"] != "sess-test-1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"ttl_ms": 60000, "protocol": 1})
		case "release":
			counters.releases.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"ok": true})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// fakeGuestAgent is a framed-protocol TCP peer echoing control frames.
func fakeGuestAgent(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hello := []byte(`{"protocol":"kw-agent-v1","type":"hello","sessionId":"s","payload":{"controlOnlyAvailable":true}}`)
				if _, err := c.Write(append(append([]byte{0}, u32be(len(hello))...), hello...)); err != nil {
					return
				}
				for {
					header := make([]byte, 5)
					if _, err := readFull(c, header); err != nil {
						return
					}
					length := int(binary.BigEndian.Uint32(header[1:5]))
					if header[0] != 0x00 || length == 0 || length > agentMaxControl {
						return
					}
					body := make([]byte, length)
					if _, err := readFull(c, body); err != nil {
						return
					}
					var message map[string]any
					if err := json.Unmarshal(body, &message); err != nil {
						return
					}
					reply := map[string]any{
						"protocol": "kw-agent-v1", "protocolVersion": 1, "sessionId": "s",
						"generation": 0, "sequence": 9, "sentAtNs": 9,
						"channel": "control", "type": "echo",
						"payload": map[string]any{"saw": message["type"]},
					}
					raw, _ := json.Marshal(reply)
					frame := append([]byte{0x00}, u32be(len(raw))...)
					frame = append(frame, raw...)
					if _, err := c.Write(frame); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return listener
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func u32be(n int) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(n))
	return out
}

func guestPort(t *testing.T, listener net.Listener) int32 {
	t.Helper()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	num, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return int32(num)
}

// agentTestHandler builds the proxy handler with the agent route pointed at
// a fake TCP guest and fake ticket API.
func agentTestHandler(t *testing.T, apiURL string, guest net.Listener, agentPort int32) http.Handler {
	t.Helper()
	return Handler(&HandlerOptions{
		PathPrefix:  "/proxy",
		AgentAPIURL: apiURL,
		ConfigLookup: func(imageRef string) *Config {
			return &Config{AgentPort: agentPort}
		},
		WorkspaceInfoLookup: func(namespace, name string) *WorkspaceInfo {
			return &WorkspaceInfo{Image: "img"}
		},
		AgentDial: func(ctx context.Context, ns, name string, port int32) (net.Conn, error) {
			t.Helper()
			if port != agentPort {
				t.Fatalf("dialed agent port %d, want %d", port, agentPort)
			}
			return net.Dial("tcp", guest.Addr().String())
		},
	})
}

func TestAgentBridgeEchoesControl(t *testing.T) {
	var counters agentCounters
	api := fakeAgentAPI(t, false, &counters)
	guest := fakeGuestAgent(t)
	handler := agentTestHandler(t, api.URL, guest, guestPort(t, guest))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	ws, err := dialAuth(t, "ws"+strings.TrimPrefix(srv.URL, "http")+"/proxy/ns1/ws1/agent/")
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	defer ws.Close()

	var greeting []byte
	if err := websocket.Message.Receive(ws, &greeting); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"protocol": "kw-agent-v1", "type": "attach", "sessionId": "s", "payload": map[string]any{"ticket": "untrusted"}})
	frame := append([]byte{0x00}, u32be(len(payload))...)
	frame = append(frame, payload...)
	if err := websocket.Message.Send(ws, frame); err != nil {
		t.Fatalf("send: %v", err)
	}
	var reply []byte
	if err := websocket.Message.Receive(ws, &reply); err != nil {
		t.Fatalf("receive: %v", err)
	}
	if len(reply) < 5 || reply[0] != 0x00 {
		t.Fatalf("bad echo frame: %v", reply)
	}
	var decoded map[string]any
	if err := json.Unmarshal(reply[5:], &decoded); err != nil {
		t.Fatalf("echo not JSON: %v", err)
	}
	if decoded["type"] != "echo" {
		t.Fatalf("unexpected echo type %v", decoded["type"])
	}
	if counters.attaches.Load() != 1 {
		t.Fatalf("API attach calls = %d, want 1", counters.attaches.Load())
	}
}

func TestAgentPurposeHonorsSeatAndRevocation(t *testing.T) {
	var counters agentCounters
	base := fakeAgentAPI(t, false, &counters)
	var busy atomic.Bool
	busy.Store(true)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tier1/claim") && busy.Load() || strings.HasSuffix(r.URL.Path, "/tier1/renew") {
			w.WriteHeader(http.StatusConflict)
			return
		}
		base.Config.Handler.ServeHTTP(w, r)
	}))
	defer api.Close()
	guest := fakeGuestAgent(t)
	srv := httptest.NewServer(agentTestHandler(t, api.URL, guest, guestPort(t, guest)))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/proxy/ns1/ws1/agent/"
	if c, err := dialAuth(t, wsURL); err == nil {
		c.Close()
		t.Fatal("display bypassed console seat")
	}
	if counters.attaches.Load() != 0 {
		t.Fatal("busy display minted grant")
	}
	// Helpers can attach alongside RFB without claiming its seat.
	c, err := dialAuth(t, wsURL+"?purpose=v1.clipboard")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	// Use another handler to model a separate proxy replica. It has no local
	// reservation for this workspace; distributed seat renewal still fences it.
	busy.Store(false)
	sibling := httptest.NewServer(agentTestHandler(t, api.URL, guest, guestPort(t, guest)))
	defer sibling.Close()
	c, err = dialAuth(t, "ws"+strings.TrimPrefix(sibling.URL, "http")+"/proxy/ns1/ws1/agent/")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	var greeting []byte
	if err := websocket.Message.Receive(c, &greeting); err != nil {
		t.Fatal(err)
	}
	var reply []byte
	if err := websocket.Message.Receive(c, &reply); err == nil {
		t.Fatal("revoked seat retained stream")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("seat revocation did not close stream promptly")
	}
}

func TestAgentSecondViewerGetsBusy(t *testing.T) {
	var counters agentCounters
	api := fakeAgentAPI(t, false, &counters)
	guest := fakeGuestAgent(t)
	handler := agentTestHandler(t, api.URL, guest, guestPort(t, guest))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/proxy/ns1/ws1/agent/"
	first, err := dialAuth(t, wsURL)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	defer first.Close()

	second, err := dialAuth(t, wsURL)
	if err == nil {
		second.Close()
		t.Fatal("second viewer must get 409 busy, not a session")
	}
	if !strings.Contains(fmt.Sprint(err), "409") && !strings.Contains(fmt.Sprint(err), "bad status") {
		t.Fatalf("unexpected second-dial error: %v", err)
	}
}

// rawUpgradeStatus performs a bare WebSocket handshake over TCP and returns
// the HTTP status line, verifying route-level refusals without a WS library.
// dialAuth dials with a platform session cookie, like an authenticated viewer.
func dialAuth(t *testing.T, wsURL string) (*websocket.Conn, error) {
	t.Helper()
	config, err := websocket.NewConfig(wsURL, "http://localhost/")
	if err != nil {
		t.Fatal(err)
	}
	config.Header = http.Header{"Cookie": {"kw-session=test-session"}}
	return websocket.DialConfig(config)
}

func TestWSAcceptKeyMatchesRFC6455Vector(t *testing.T) {
	// RFC 6455 §1.3 example: SHA-1 (not SHA-256) over key + GUID.
	if got := wsAcceptKey("dGhlIHNhbXBsZSBub25jZQ=="); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Fatalf("accept = %q, want RFC 6455 example", got)
	}
}

func rawUpgradeStatus(t *testing.T, addr, path string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nCookie: kw-session=test-session\r\n\r\n", path)
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}

func TestAgentRouteRefusesWithoutPort(t *testing.T) {
	var counters agentCounters
	api := fakeAgentAPI(t, false, &counters)
	handler := Handler(&HandlerOptions{
		PathPrefix:  "/proxy",
		AgentAPIURL: api.URL,
		ConfigLookup: func(imageRef string) *Config {
			return &Config{}
		},
		WorkspaceInfoLookup: func(namespace, name string) *WorkspaceInfo {
			return &WorkspaceInfo{Image: "img"}
		},
	})
	srv := httptest.NewServer(handler)
	defer srv.Close()

	status := rawUpgradeStatus(t, strings.TrimPrefix(srv.URL, "http://"), "/proxy/ns1/ws1/agent/")
	if !strings.Contains(status, "503") {
		t.Fatalf("status = %q, want 503 (unconfigured image never assumes transport)", status)
	}
	if counters.attaches.Load() != 0 {
		t.Fatalf("API attach calls = %d, want 0 (refuse before ticketing)", counters.attaches.Load())
	}
}

func TestAgentRouteRefusesWhenTicketDenied(t *testing.T) {
	var counters agentCounters
	api := fakeAgentAPI(t, true, &counters)
	guest := fakeGuestAgent(t)
	handler := agentTestHandler(t, api.URL, guest, guestPort(t, guest))
	srv := httptest.NewServer(handler)
	defer srv.Close()

	status := rawUpgradeStatus(t, strings.TrimPrefix(srv.URL, "http://"), "/proxy/ns1/ws1/agent/")
	if !strings.Contains(status, "403") {
		t.Fatalf("status = %q, want 403 (ticket denial surfaces)", status)
	}
	if counters.attaches.Load() != 1 {
		t.Fatalf("API attach calls = %d, want 1", counters.attaches.Load())
	}
}
