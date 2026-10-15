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
			out, err := a.viewerFrame(admissionFrame("attach", map[string]any{"ticket": map[string]any{"workspaceUid": "forged"}, "controlOnly": false}))
			if err != nil {
				t.Fatal(err)
			}
			var envelope struct {
				Payload struct {
					Ticket      map[string]any
					ControlOnly bool
				}
			}
			if err := json.Unmarshal(out[5:], &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Payload.Ticket["workspaceUid"] != "real-workspace" || envelope.Payload.Ticket["sessionId"] != "guest-session" || envelope.Payload.ControlOnly != (purpose == "telemetry") {
				t.Fatalf("bad authority: %s", out[5:])
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
