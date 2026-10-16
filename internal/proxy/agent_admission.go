package proxy

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
)

// The API response is obtained by the authenticated bridge, never the viewer.
// Only that response supplies guest authority; platform keys stay off guests.
func agentGrant(ticket agentTicket) (map[string]any, error) {
	var signed string
	if json.Unmarshal(ticket.Ticket, &signed) != nil {
		return nil, errors.New("invalid API agent ticket")
	}
	parts := strings.Split(signed, ".")
	if len(parts) != 3 || parts[0] != ticket.ID {
		return nil, errors.New("invalid API agent ticket binding")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var grant map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if decoder.Decode(&grant) != nil || grant["audience"] != "workspace-agent" || grant["role"] != "controller" {
		return nil, errors.New("invalid API agent scope")
	}
	return grant, nil
}

type agentAdmission struct {
	mu          sync.Mutex
	grant       map[string]any
	purpose     string
	session     string
	controlOnly bool
	attached    bool
	// Guest self-description from hello, for readiness evidence. Empty
	// until the first hello arrives.
	version  string
	platform string
	capW     int
	capH     int
}

func (a *agentAdmission) observe(body []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var envelope struct {
		Type    string `json:"type"`
		Session string `json:"sessionId"`
		Payload struct {
			ControlOnly  bool   `json:"controlOnlyAvailable"`
			AgentVersion string `json:"agentVersion"`
			Platform     string `json:"platform"`
			Capture      struct {
				Width  int `json:"width"`
				Height int `json:"height"`
			} `json:"capture"`
		} `json:"payload"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.Type == "hello" && a.session == "" {
		a.session, a.controlOnly = envelope.Session, envelope.Payload.ControlOnly
		a.version, a.platform = envelope.Payload.AgentVersion, envelope.Payload.Platform
		a.capW, a.capH = envelope.Payload.Capture.Width, envelope.Payload.Capture.Height
	}
}

// hello reports the observed guest description. Empty version means no
// hello has been seen yet; callers must not treat it as stream readiness.
func (a *agentAdmission) hello() (version, platform string, w, h int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.version, a.platform, a.capW, a.capH
}

// viewerFrame enforces exact framing and substitutes the edge-owned grant.
// Helpers cannot obtain input/resize/encoder rights by changing attach flags.
func (a *agentAdmission) viewerFrame(frame []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(frame) < 6 || frame[0] != agentTagControl || len(frame)-5 > agentMaxControl || int(binary.BigEndian.Uint32(frame[1:5])) != len(frame)-5 {
		return nil, errors.New("invalid viewer control frame")
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(frame[5:], &envelope) != nil {
		return nil, errors.New("invalid control envelope")
	}
	var kind, session string
	_ = json.Unmarshal(envelope["type"], &kind)
	_ = json.Unmarshal(envelope["sessionId"], &session)
	if a.session == "" || session != a.session {
		return nil, errors.New("guest session binding missing")
	}
	if kind == "attach" {
		if a.attached || (a.purpose == "telemetry" && !a.controlOnly) {
			return nil, errors.New("agent purpose unavailable or duplicate attach")
		}
		payload := map[string]any{"ticket": a.grant}
		a.grant["sessionId"] = a.session
		if a.purpose == "telemetry" {
			payload["controlOnly"] = true
		}
		envelope["payload"], _ = json.Marshal(payload)
		a.attached = true
	} else if !a.attached {
		return nil, errors.New("attach required")
	} else if a.purpose != "display" {
		allowed := kind == "telemetry" || kind == "bye"
		if a.purpose == "clipboard" {
			allowed = allowed || kind == "clipboardGet" || kind == "clipboardSet"
		}
		if !allowed {
			return nil, errors.New("action forbidden for agent helper")
		}
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 5, len(body)+5)
	binary.BigEndian.PutUint32(out[1:], uint32(len(body)))
	return append(out, body...), nil
}
