package proxy

// Tests for Layer-2 agent bridge telemetry: per-session counters,
// control/media split, disconnect reasons, and registry snapshots.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestAgentSnapshotStartsActiveAndEmpty(t *testing.T) {
	attached := time.Now()
	bridge := newAgentBridge(attached)
	snap := bridge.Snapshot()
	if !snap.Active() {
		t.Fatal("new bridge must hold the seat")
	}
	if !snap.AttachedAt.Equal(attached) {
		t.Fatalf("attachedAt = %v, want %v", snap.AttachedAt, attached)
	}
	if snap.MediaBytes() != 0 || snap.FramesToGuest != 0 || snap.FramesToViewer != 0 {
		t.Fatalf("new bridge must count nothing: %+v", snap)
	}
	if snap.ControlToGuest != 0 || snap.ControlToViewer != 0 {
		t.Fatalf("new bridge must count no control bytes: %+v", snap)
	}
}

func TestAgentSnapshotSplitsControlAndMedia(t *testing.T) {
	bridge := newAgentBridge(time.Now())
	bridge.addViewerFrame(0x00, 100)
	bridge.addViewerFrame(0x01, 1000)
	bridge.addViewerFrame(0x02, 500)
	bridge.addGuestFrame(0x00, 64)
	bridge.addGuestFrame(0x01, 2048)
	snap := bridge.Snapshot()
	if snap.ControlToGuest != 100 || snap.MediaToGuest != 1500 {
		t.Fatalf("viewer split = control %d media %d, want 100/1500",
			snap.ControlToGuest, snap.MediaToGuest)
	}
	if snap.ControlToViewer != 64 || snap.MediaToViewer != 2048 {
		t.Fatalf("guest split = control %d media %d, want 64/2048",
			snap.ControlToViewer, snap.MediaToViewer)
	}
	if snap.FramesToGuest != 3 || snap.FramesToViewer != 2 {
		t.Fatalf("frames = %d/%d, want 3/2", snap.FramesToGuest, snap.FramesToViewer)
	}
	if snap.MediaBytes() != 3548 {
		t.Fatalf("media total = %d, want 3548", snap.MediaBytes())
	}
	if !snap.Active() {
		t.Fatal("counting must not end the session")
	}
}

func TestAgentFinishFirstReasonWins(t *testing.T) {
	bridge := newAgentBridge(time.Now())
	bridge.addViewerFrame(0x00, 10)
	ended := time.Now()
	bridge.finish(ended, agentEndViewerClosed)
	bridge.finish(ended.Add(time.Second), agentEndGuestClosed)
	snap := bridge.Snapshot()
	if snap.Active() {
		t.Fatal("finished bridge must release the seat")
	}
	if snap.DisconnectReason != agentEndViewerClosed {
		t.Fatalf("reason = %q, want first %q", snap.DisconnectReason, agentEndViewerClosed)
	}
	if !snap.EndedAt.Equal(ended) {
		t.Fatalf("endedAt = %v, want %v", snap.EndedAt, ended)
	}
	// A finished session with zero media bytes is a failed attach, never usage.
	empty := newAgentBridge(time.Now())
	empty.finish(time.Now(), agentEndGuestUnreachable)
	if got := empty.Snapshot(); got.Active() || got.MediaBytes() != 0 {
		t.Fatalf("unreachable guest must read as failed attach: %+v", got)
	}
}

func TestAgentRegistrySnapshotHitMissRelease(t *testing.T) {
	registry := &agentRegistry{}
	if _, ok := registry.snapshot("ns", "ws"); ok {
		t.Fatal("empty registry must miss")
	}
	bridge := newAgentBridge(time.Now())
	if !registry.tryHold("ns", "ws", bridge) {
		t.Fatal("first hold must succeed")
	}
	bridge.addGuestFrame(0x01, 512)
	snap, ok := registry.snapshot("ns", "ws")
	if !ok {
		t.Fatal("held session must snapshot")
	}
	if snap.MediaToViewer != 512 || !snap.Active() {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}
	if _, ok := registry.snapshot("ns", "other"); ok {
		t.Fatal("other workspace must miss")
	}
	registry.release("ns", "ws", bridge)
	if _, ok := registry.snapshot("ns", "ws"); ok {
		t.Fatal("released session must miss")
	}
}

func TestAgentTelemetrySurvivesConcurrency(t *testing.T) {
	bridge := newAgentBridge(time.Now())
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				bridge.addViewerFrame(byte(i%3), 10)
				bridge.addGuestFrame(0x01, 20)
				_ = bridge.Snapshot()
			}
		}(i)
	}
	wg.Wait()
	snap := bridge.Snapshot()
	if snap.FramesToGuest != 400 || snap.FramesToViewer != 400 {
		t.Fatalf("frames = %d/%d, want 400/400", snap.FramesToGuest, snap.FramesToViewer)
	}
}

// TestAgentSeatReleasesAfterClose exercises the finish + release wiring:
// a viewer that exchanges frames and disconnects frees the seat, so a
// second dial attaches instead of getting 409.
func TestAgentSeatReleasesAfterClose(t *testing.T) {
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
	var greeting []byte
	if err := websocket.Message.Receive(first, &greeting); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"protocol": "kw-agent-v1", "type": "attach", "sessionId": "s"})
	frame := append([]byte{0x00}, u32be(len(payload))...)
	frame = append(frame, payload...)
	if err := websocket.Message.Send(first, frame); err != nil {
		t.Fatalf("send: %v", err)
	}
	var reply []byte
	if err := websocket.Message.Receive(first, &reply); err != nil {
		t.Fatalf("receive: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		second, err := dialAuth(t, wsURL)
		if err == nil {
			second.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("seat never released after close: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
