package proxy

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func observerTestBridge() *agentBridge {
	b := newAgentBridge(time.Now())
	b.publish(agentWire(0, []byte(`{"protocol":"kw-agent-v1","protocolVersion":1,"sessionId":"s","type":"hello","payload":{"inputAvailable":true,"resizeAvailable":true,"clipboardText":true,"telemetryAvailable":true}}`)))
	b.publish(agentWire(0, []byte(`{"type":"attachResult","payload":{"admitted":true}}`)))
	return b
}

var observerTestIDR = []byte{0, 0, 0, 1, 0x67, 1, 0, 0, 1, 0x68, 2, 0, 0, 1, 0x65, 3}

func TestObserverVideoFactsAreLiveAndWhitelisted(t *testing.T) {
	b := observerTestBridge()
	o, _, err := b.subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer b.unsubscribe(o)
	b.publish(agentWire(1, observerTestIDR))
	<-o.queue
	b.publish(agentWire(0, []byte(`{"type":"telemetry","payload":{"session":{"private":"controller"},"video":{"capture":{"backend":"DXGI","adapter":"Example GPU","software":false,"private":"secret"},"encoder":{"name":"Software encoder","hardware":false}}}}`)))
	select {
	case frame := <-o.queue:
		if strings.Contains(string(frame), "private") || strings.Contains(string(frame), "secret") || !strings.Contains(string(frame), "Example GPU") {
			t.Fatalf("unsafe or missing video facts: %s", frame[5:])
		}
	default:
		t.Fatal("video telemetry did not reach observer")
	}
	b.publish(agentWire(0, []byte(`{"type":"telemetry","payload":{"video":null}}`)))
	late, hello, err := b.subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer b.unsubscribe(late)
	var envelope struct {
		Payload map[string]any `json:"payload"`
	}
	if json.Unmarshal(hello[5:], &envelope) != nil || envelope.Payload["video"] != nil {
		t.Fatalf("late observer received stale facts: %s", hello[5:])
	}
}

func TestAgentFanoutBootstrapIsolationAndBounds(t *testing.T) {
	b := observerTestBridge()
	o, hello, err := b.subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer b.unsubscribe(o)
	var msg struct {
		Payload map[string]any `json:"payload"`
	}
	if json.Unmarshal(hello[5:], &msg) != nil || msg.Payload["inputAvailable"] != false || msg.Payload["resizeAvailable"] != false || msg.Payload["clipboardText"] != false || msg.Payload["observer"] != true {
		t.Fatalf("unsafe observer hello: %s", hello[5:])
	}
	// No media until independently-decodable video; sensitive replies never fan out.
	b.publish(agentWire(1, []byte{0, 0, 1, 0x41, 1}))
	b.publish(agentWire(2, []byte{1}))
	b.publish(agentWire(0, []byte(`{"type":"clipboardResult","payload":{"text":"private"}}`)))
	if len(o.queue) != 0 {
		t.Fatal("observer received pre-keyframe or private data")
	}
	b.publish(agentWire(1, observerTestIDR))
	select {
	case frame := <-o.queue:
		units := annexBNALs(frame[5:])
		if len(units) < 3 || nalType(units[0]) != 7 || nalType(units[1]) != 8 {
			t.Fatal("missing decoder bootstrap")
		}
		o.mu.Lock()
		o.bytes -= len(frame)
		o.mu.Unlock()
	default:
		t.Fatal("missing IDR")
	}
	// A late reader starts on a fresh keyframe with cached decoder config.
	late, _, err := b.subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer b.unsubscribe(late)
	b.publish(agentWire(1, []byte{0, 0, 1, 0x65, 9}))
	if len(late.queue) != 1 {
		t.Fatal("late join not bootstrapped")
	}
	// One reader draining does not stop another from reaching its bounded cap.
	for i := 0; i < agentObserverFrames+1; i++ {
		b.publish(agentWire(2, []byte{1}))
		select {
		case <-late.queue:
		default:
		}
	}
	select {
	case <-o.done:
	default:
		t.Fatal("slow reader was not detached")
	}
	// Byte cap applies even below the frame count cap.
	large := &agentObserver{queue: make(chan []byte, agentObserverFrames), done: make(chan struct{})}
	large.push(make([]byte, agentObserverBytes))
	large.push([]byte{1})
	select {
	case <-large.done:
	default:
		t.Fatal("byte cap not enforced")
	}
}

func TestAgentObserverCannotMutateOrAcquireGuestTicket(t *testing.T) {
	for _, kind := range []string{"input", "resizeRequest", "clipboardGet", "clipboardSet", "telemetry", "encoderConfig", "attach"} {
		t.Run(kind, func(t *testing.T) {
			b := observerTestBridge()
			registry := &agentRegistry{}
			registry.tryHold("ns", "ws", b)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer test" {
					t.Error("observer was not re-authorized")
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/display/join"):
					_, _ = w.Write([]byte(`{"participant":{"id":"observer"}}`))
				case strings.HasSuffix(r.URL.Path, "/display/leave"), strings.HasSuffix(r.URL.Path, "/display/observer"):
					_, _ = w.Write([]byte(`{"ok":true}`))
				default:
					t.Errorf("observer attempted guest authority request: %s", r.URL.Path)
					http.Error(w, "forbidden", 403)
				}
			}))
			defer api.Close()
			deps := &agentDeps{API: api.URL, Registry: registry, Credential: func(*http.Request) string { return "Bearer test" }}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveAgent(deps, w, r, "ns", "ws", 1234) }))
			defer srv.Close()
			ws, err := dialAuth(t, "ws"+strings.TrimPrefix(srv.URL, "http")+"/?purpose=v1.observe")
			if err != nil {
				t.Fatal(err)
			}
			defer ws.Close()
			_ = ws.SetDeadline(time.Now().Add(2 * time.Second))
			var frame []byte
			if err := websocket.Message.Receive(ws, &frame); err != nil {
				t.Fatal(err)
			}
			if err := websocket.Message.Send(ws, agentWire(0, []byte(`{"type":"attach","sessionId":"s","payload":{"ticket":"forged"}}`))); err != nil {
				t.Fatal(err)
			}
			if err := websocket.Message.Receive(ws, &frame); err != nil {
				t.Fatal(err)
			}
			b.publish(agentWire(1, observerTestIDR))
			if err := websocket.Message.Receive(ws, &frame); err != nil || frame[0] != 1 {
				t.Fatalf("missing shared video: %v", err)
			}
			mutation, _ := json.Marshal(map[string]any{"type": kind, "sessionId": "s", "payload": map[string]any{}})
			if err := websocket.Message.Send(ws, agentWire(0, mutation)); err != nil {
				t.Fatal(err)
			}
			if err := websocket.Message.Receive(ws, &frame); err == nil {
				t.Fatal("mutating observer was not disconnected")
			}
		})
	}
}

func TestAgentObserverCapacityAndNotAdmitted(t *testing.T) {
	b := newAgentBridge(time.Now())
	if _, _, err := b.subscribe(); err == nil {
		t.Fatal("subscribed before admission")
	}
	b = observerTestBridge()
	for i := 0; i < agentObserverLimit; i++ {
		if _, _, err := b.subscribe(); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := b.subscribe(); err == nil {
		t.Fatal("observer cap not enforced")
	}
}

func TestObserverKeyframeDemandIsCoalescedWithoutStrandingIdleJoins(t *testing.T) {
	b := observerTestBridge()
	o, _, err := b.subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer b.unsubscribe(o)
	requests := make(chan time.Time, 8)
	b.requestKeyframe = func() error { requests <- time.Now(); return nil }
	if err := b.observerKeyframe(); err != nil {
		t.Fatal(err)
	}
	first := <-requests
	for i := 0; i < 20; i++ {
		if err := b.observerKeyframe(); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case next := <-requests:
		if next.Sub(first) < time.Second {
			t.Fatal("observer demand bypassed the keyframe budget")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("coalesced idle join was stranded without a keyframe")
	}
	select {
	case <-requests:
		t.Fatal("unbounded keyframe requests")
	default:
	}
}

func TestPremiumObserverOwnerHopReauthorizesAndCannotLoop(t *testing.T) {
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer viewer" || r.Header.Get("X-KW-Agent-Hop") != "1" {
			t.Error("peer hop lost authentication or loop guard")
		}
		w.WriteHeader(http.StatusForbidden) // The owner still decides access.
	}))
	defer peer.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer viewer" {
			t.Error("status was not authorized")
		}
		_, _ = w.Write([]byte(`{"inUse":true,"transport":"agent","proxyOwner":"proxy-b"}`))
	}))
	defer api.Close()
	deps := &agentDeps{API: api.URL, Owner: "proxy-a", Credential: func(r *http.Request) string { return r.Header.Get("Authorization") }, ResolveOwner: func(_ context.Context, owner string) (string, error) {
		if owner != "proxy-b" {
			t.Fatalf("resolved untrusted owner %q", owner)
		}
		return strings.TrimPrefix(peer.URL, "http://"), nil
	}}
	request := httptest.NewRequest("GET", "/proxy/ns/ws/agent/?purpose=v1.observe", nil)
	request.Header.Set("Authorization", "Bearer viewer")
	w := httptest.NewRecorder()
	deps.forwardAgentObserver(w, request, "ns", "ws")
	if w.Code != http.StatusForbidden {
		t.Fatalf("peer authorization bypassed: %d", w.Code)
	}
	request.Header.Set("X-KW-Agent-Hop", "1")
	w = httptest.NewRecorder()
	deps.forwardAgentObserver(w, request, "ns", "ws")
	if w.Code != http.StatusConflict {
		t.Fatalf("second hop not refused: %d", w.Code)
	}
}

func TestPremiumFanoutUsesOneGuestAndEndsWithController(t *testing.T) {
	var counters agentCounters
	tickets := fakeAgentAPI(t, false, &counters)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/display/join"):
			_, _ = w.Write([]byte(`{"participant":{"id":"o"}}`))
		case strings.Contains(r.URL.Path, "/display/"):
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			tickets.Config.Handler.ServeHTTP(w, r)
		}
	}))
	defer api.Close()
	var dials atomic.Int32
	deps := &agentDeps{API: api.URL, Registry: &agentRegistry{}, Credential: func(*http.Request) string { return "Bearer test" }, DialAgent: func(context.Context, string, string, int32) (net.Conn, error) {
		dials.Add(1)
		client, guest := net.Pipe()
		go func() {
			defer guest.Close()
			if _, err := guest.Write(agentWire(0, []byte(`{"protocol":"kw-agent-v1","type":"hello","sessionId":"s","payload":{}}`))); err != nil {
				return
			}
			if _, _, err := agentFrame(guest); err != nil {
				return
			}
			if _, err := guest.Write(agentWire(0, []byte(`{"type":"attachResult","payload":{"admitted":true}}`))); err != nil {
				return
			}
			// Unchanged desktop: only a proxy-coalesced keyframe request can
			// produce the fresh IDR that bootstraps this observer.
			for {
				_, body, err := agentFrame(guest)
				if err != nil {
					return
				}
				var msg struct {
					Type string `json:"type"`
				}
				if json.Unmarshal(body, &msg) == nil && msg.Type == "keyframeRequest" {
					if _, err := guest.Write(agentWire(1, observerTestIDR)); err != nil {
						return
					}
				}
			}
		}()
		return client, nil
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveAgent(deps, w, r, "ns", "ws", 1234) }))
	defer srv.Close()
	base := "ws" + strings.TrimPrefix(srv.URL, "http") + "/"
	controller, err := dialAuth(t, base)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	_ = controller.SetDeadline(time.Now().Add(3 * time.Second))
	var frame []byte
	if err := websocket.Message.Receive(controller, &frame); err != nil {
		t.Fatal(err)
	}
	if err := websocket.Message.Send(controller, agentWire(0, []byte(`{"type":"attach","sessionId":"s"}`))); err != nil {
		t.Fatal(err)
	}
	if err := websocket.Message.Receive(controller, &frame); err != nil {
		t.Fatal(err)
	}
	observer, err := dialAuth(t, base+"?purpose=v1.observe")
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	_ = observer.SetDeadline(time.Now().Add(3 * time.Second))
	if err := websocket.Message.Receive(observer, &frame); err != nil {
		t.Fatal(err)
	}
	if err := websocket.Message.Send(observer, agentWire(0, []byte(`{"type":"attach","sessionId":"s"}`))); err != nil {
		t.Fatal(err)
	}
	if err := websocket.Message.Receive(observer, &frame); err != nil {
		t.Fatal(err)
	}
	if err := websocket.Message.Receive(observer, &frame); err != nil || frame[0] != 1 || string(frame[5:]) != string(observerTestIDR) {
		t.Fatalf("observer did not receive the controller's encoded output: %v", err)
	}
	if dials.Load() != 1 || counters.attaches.Load() != 1 {
		t.Fatalf("fan-out opened extra guest authority: dials=%d tickets=%d", dials.Load(), counters.attaches.Load())
	}
	_ = controller.Close()
	for {
		if err := websocket.Message.Receive(observer, &frame); err != nil {
			break
		}
	}
}
