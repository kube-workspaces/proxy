package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestDisplayReplacesHelperButCannotReplaceController(t *testing.T) {
	var counters agentCounters
	api := fakeAgentAPI(t, false, &counters)
	guest := fakeGuestAgent(t)
	srv := httptest.NewServer(agentTestHandler(t, api.URL, guest, guestPort(t, guest)))
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/proxy/ns1/ws1/agent/"
	helper, err := dialAuth(t, url+"?purpose=v1.telemetry")
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	helper.SetDeadline(time.Now().Add(3 * time.Second))
	var hello []byte
	if err := websocket.Message.Receive(helper, &hello); err != nil {
		t.Fatal(err)
	}
	display, err := dialAuth(t, url+"?purpose=v1.display")
	if err != nil {
		t.Fatalf("helper blocked authorized display: %v", err)
	}
	defer display.Close()
	display.SetDeadline(time.Now().Add(3 * time.Second))
	if err := websocket.Message.Receive(display, &hello); err != nil {
		t.Fatalf("replacement did not reach guest: %v", err)
	}
	if err := websocket.Message.Receive(helper, &hello); err == nil {
		t.Fatal("old helper remained open")
	}
	for _, purpose := range []string{"display", "telemetry", "clipboard"} {
		conn, err := dialAuth(t, url+"?purpose=v1."+purpose)
		if err == nil {
			conn.Close()
			t.Fatalf("%s displaced active controller", purpose)
		}
	}
	frame := agentWire(0, []byte(`{"protocol":"kw-agent-v1","type":"attach","sessionId":"s","payload":{"ticket":"untrusted"}}`))
	if err := websocket.Message.Send(display, frame); err != nil {
		t.Fatalf("controller broken by rejected connection: %v", err)
	}
	if err := websocket.Message.Receive(display, &hello); err != nil {
		t.Fatalf("controller no longer usable: %v", err)
	}
}

func TestDeniedDisplayClaimDoesNotCancelHelper(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer api.Close()
	registry := &agentRegistry{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	helper := newAgentBridge(time.Now())
	helper.purpose, helper.cancel = "telemetry", cancel
	registry.tryHold("ns1", "ws1", helper)
	req := httptest.NewRequest(http.MethodGet, "/agent/?purpose=v1.display", nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Authorization", "Bearer test")
	recorder := httptest.NewRecorder()
	serveAgent(&agentDeps{API: api.URL, Registry: registry}, recorder, req, "ns1", "ws1", 44787)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", recorder.Code)
	}
	if ctx.Err() != nil || registry.tryHold("ns1", "ws1", newAgentBridge(time.Now())) {
		t.Fatal("denied request cancelled or released helper")
	}
}

func TestHelperReplacementReservationSurvivesOldCleanup(t *testing.T) {
	registry := &agentRegistry{}
	old := newAgentBridge(time.Now())
	old.purpose, old.cancel = "clipboard", func() {}
	next := newAgentBridge(time.Now())
	next.purpose = "display"
	registry.tryHold("ns1", "ws1", old)
	if previous, ok := registry.replaceHelper("ns1", "ws1", next); !ok || previous != old {
		t.Fatal("helper not replaced")
	}
	registry.release("ns1", "ws1", old)
	if registry.tryHold("ns1", "ws1", newAgentBridge(time.Now())) {
		t.Fatal("old cleanup released new reservation")
	}
}
