package proxy

import (
	"encoding/json"
	"testing"
)

func admissionFrame(kind string, payload map[string]any) []byte {
	body, _ := json.Marshal(map[string]any{"type": kind, "sessionId": "guest-session", "payload": payload})
	return append(append([]byte{0}, u32be(len(body))...), body...)
}

func TestAgentAuthorityAndPurpose(t *testing.T) {
	for _, purpose := range []string{"display", "clipboard", "telemetry"} {
		t.Run(purpose, func(t *testing.T) {
			a := &agentAdmission{purpose: purpose, grant: map[string]any{"workspaceUid": "real-workspace", "controlEpoch": 1}}
			a.observe([]byte(`{"type":"hello","sessionId":"guest-session","payload":{"controlOnlyAvailable":true}}`))
			out, err := a.viewerFrame(admissionFrame("attach", map[string]any{"ticket": map[string]any{"workspaceUid": "forged"}, "controlOnly": false, "displaySession": purpose != "display"}))
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Payload struct {
					Ticket         map[string]any
					ControlOnly    bool
					DisplaySession bool
				}
			}
			if err := json.Unmarshal(out[5:], &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Payload.Ticket["workspaceUid"] != "real-workspace" || envelope.Payload.Ticket["sessionId"] != "guest-session" || envelope.Payload.ControlOnly != (purpose == "telemetry") {
				t.Fatalf("bad authority: %s", out[5:])
			}
			if envelope.Payload.DisplaySession != (purpose == "display") {
				t.Fatalf("viewer forged display topology intent: %s", out[5:])
			}
			if _, err := a.viewerFrame(admissionFrame("attach", nil)); err == nil {
				t.Fatal("duplicate attach accepted")
			}
			for _, action := range []string{"keyEvent", "resizeRequest", "keyframeRequest", "clipboardSet", "telemetry", "bye"} {
				_, err := a.viewerFrame(admissionFrame(action, nil))
				allowed := purpose == "display" || action == "telemetry" || action == "bye" || purpose == "clipboard" && action == "clipboardSet"
				if (err == nil) != allowed {
					t.Fatalf("%s allowed=%v: %v", action, allowed, err)
				}
			}
		})
	}
}

func TestAgentRejectsFramingAndUnsupportedHelper(t *testing.T) {
	a := &agentAdmission{purpose: "telemetry", grant: map[string]any{}}
	frame := admissionFrame("attach", nil)
	if _, err := a.viewerFrame(frame); err == nil {
		t.Fatal("attach before hello")
	}
	a.observe([]byte(`{"type":"hello","sessionId":"guest-session"}`))
	if _, err := a.viewerFrame(frame); err == nil {
		t.Fatal("telemetry downgraded to interactive")
	}
	for _, bad := range [][]byte{frame[:4], append(frame, 0), append([]byte{1}, frame[1:]...)} {
		if _, err := a.viewerFrame(bad); err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
}

func TestAgentHelloCapture(t *testing.T) {
	a := &agentAdmission{purpose: "display", grant: map[string]any{}}
	if version, _, _, _ := a.hello(); version != "" {
		t.Fatal("hello reported before any guest frame")
	}
	a.observe([]byte(`{"type":"hello","sessionId":"guest-session","payload":{"controlOnlyAvailable":false,"agentVersion":"0.4.0","platform":"windows","capture":{"width":1920,"height":1080}}}`))
	version, platform, w, h := a.hello()
	if version != "0.4.0" || platform != "windows" || w != 1920 || h != 1080 {
		t.Fatalf("hello = %q %q %dx%d", version, platform, w, h)
	}
	// A second hello must not overwrite the first: mid-bridge version
	// changes mean the guest restarted under us.
	a.observe([]byte(`{"type":"hello","sessionId":"other-session","payload":{"agentVersion":"9.9.9"}}`))
	if version, _, _, _ := a.hello(); version != "0.4.0" {
		t.Fatalf("hello overwritten mid-bridge: %q", version)
	}
	// Malformed hellos never poison the record.
	b := &agentAdmission{purpose: "display", grant: map[string]any{}}
	b.observe([]byte(`{"type":"hello","sessionId":`))
	if version, _, _, _ := b.hello(); version != "" {
		t.Fatalf("malformed hello recorded: %q", version)
	}
}

func TestProxyGuestClockRemainsMonotonicAcrossSyntheticKeyframes(t *testing.T) {
	a := &agentAdmission{purpose: "display", grant: map[string]any{}}
	a.observe([]byte(`{"type":"hello","sessionId":"guest-session"}`))
	var previousSequence, previousStamp uint64
	for _, kind := range []string{"attach", "input", "keyframeRequest", "input", "resizeRequest"} {
		frame, err := a.viewerFrame(admissionFrame(kind, nil))
		if err != nil {
			t.Fatal(err)
		}
		var msg struct {
			Sequence uint64 `json:"sequence"`
			Stamp    uint64 `json:"sentAtNs"`
		}
		if err := json.Unmarshal(frame[5:], &msg); err != nil {
			t.Fatal(err)
		}
		if msg.Sequence <= previousSequence || msg.Stamp <= previousStamp {
			t.Fatal("guest clock regressed")
		}
		previousSequence, previousStamp = msg.Sequence, msg.Stamp
	}
}
