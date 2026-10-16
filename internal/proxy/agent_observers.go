package proxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kube-workspaces/proxy/internal/monitoring"
)

const (
	agentObserverLimit  = 7
	agentObserverFrames = 32
	agentObserverBytes  = 16 * 1024 * 1024
)

// Queues share immutable encoded frames. Both count and byte limits apply;
// detaching on overflow avoids ever delivering deltas after a dropped frame.
type agentObserver struct {
	mu    sync.Mutex
	queue chan []byte
	bytes int
	ready bool
	done  chan struct{}
	once  sync.Once
}

func (o *agentObserver) stop() { o.once.Do(func() { close(o.done) }) }
func (o *agentObserver) push(frame []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	select {
	case <-o.done:
		return
	default:
	}
	if o.bytes+len(frame) > agentObserverBytes {
		o.stop()
		return
	}
	select {
	case o.queue <- frame:
		o.bytes += len(frame)
	default:
		o.stop()
	}
}

func agentWire(tag byte, body []byte) []byte {
	frame := make([]byte, 5, len(body)+5)
	frame[0] = tag
	binary.BigEndian.PutUint32(frame[1:], uint32(len(body)))
	return append(frame, body...)
}

// annexBNALs retains start codes, allowing SPS/PPS to bootstrap a decoder
// without replaying an unbounded GOP or asking the guest for observer rights.
func annexBNALs(body []byte) [][]byte {
	var starts []int
	for i := 0; i+3 < len(body); i++ {
		if body[i] == 0 && body[i+1] == 0 && (body[i+2] == 1 || (body[i+2] == 0 && body[i+3] == 1)) {
			starts = append(starts, i)
			if body[i+2] == 0 {
				i++
			}
			i += 2
		}
	}
	var units [][]byte
	for i, start := range starts {
		end := len(body)
		if i+1 < len(starts) {
			end = starts[i+1]
		}
		units = append(units, body[start:end])
	}
	return units
}

func nalType(unit []byte) byte {
	i := 2
	for i < len(unit) && unit[i] == 0 {
		i++
	}
	if i+1 >= len(unit) {
		return 0
	}
	return unit[i+1] & 31
}

// publish is called only by the guest reader, before writing to the controller.
// Never forward clipboard results, tickets or controller-specific telemetry.
func (b *agentBridge) publish(frame []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.observers == nil {
		b.observers = make(map[*agentObserver]struct{})
	}
	key := false
	if frame[0] == 0 {
		var msg struct {
			Type    string `json:"type"`
			Payload struct {
				Admitted bool           `json:"admitted"`
				Actual   map[string]any `json:"actual"`
			} `json:"payload"`
		}
		if json.Unmarshal(frame[5:], &msg) != nil {
			return
		}
		switch msg.Type {
		case "hello":
			b.helloFrame = append([]byte(nil), frame...)
			return
		case "attachResult":
			b.admitted = msg.Payload.Admitted
			return
		case "resizeAck": // Mode is shared state; every observer needs it.
			if len(msg.Payload.Actual) > 0 {
				var hello map[string]any
				if len(b.helloFrame) > 5 && json.Unmarshal(b.helloFrame[5:], &hello) == nil {
					if payload, ok := hello["payload"].(map[string]any); ok {
						payload["capture"] = msg.Payload.Actual
						raw, _ := json.Marshal(hello)
						b.helloFrame = agentWire(0, raw)
					}
				}
			}
		default:
			return
		}
	} else if frame[0] == 1 {
		hasSPS, hasPPS := false, false
		for _, unit := range annexBNALs(frame[5:]) {
			switch nalType(unit) {
			case 7:
				hasSPS = true
				b.sps = append([]byte(nil), unit...)
			case 8:
				hasPPS = true
				b.pps = append([]byte(nil), unit...)
			case 5:
				key = true
			}
		}
		if key && len(b.sps) > 0 && len(b.pps) > 0 {
			if !hasSPS || !hasPPS {
				body := append(append(append([]byte(nil), b.sps...), b.pps...), frame[5:]...)
				if len(body) > agentMaxMedia {
					return
				}
				frame = agentWire(1, body)
			}
		} else {
			key = false
		}
	}
	for o := range b.observers {
		if !o.ready {
			if !key {
				continue
			}
			o.ready = true
		}
		o.push(frame)
	}
}

func (b *agentBridge) subscribe() (*agentObserver, []byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.endReason != "" || !b.admitted || len(b.helloFrame) == 0 {
		return nil, nil, errors.New("premium controller is not streaming")
	}
	if len(b.observers) >= agentObserverLimit {
		return nil, nil, errors.New("premium observer limit reached")
	}
	var hello map[string]any
	if json.Unmarshal(b.helloFrame[5:], &hello) != nil {
		return nil, nil, errors.New("invalid guest hello")
	}
	payload, ok := hello["payload"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("invalid guest capabilities")
	}
	for _, key := range []string{"inputAvailable", "resizeAvailable", "clipboardText", "telemetryAvailable"} {
		payload[key] = false
	}
	payload["observer"] = true
	body, _ := json.Marshal(hello)
	o := &agentObserver{queue: make(chan []byte, agentObserverFrames), done: make(chan struct{})}
	if b.observers == nil {
		b.observers = make(map[*agentObserver]struct{})
	}
	b.observers[o] = struct{}{}
	return o, agentWire(0, body), nil
}

// Late joins need a fresh IDR even on an unchanged desktop. Demand is capped
// per bridge, independent of observer traffic; it never changes encoder policy.
func (b *agentBridge) observerKeyframe() error {
	b.mu.Lock()
	request := b.requestKeyframe
	if request == nil || len(b.observers) == 0 || b.endReason != "" {
		b.mu.Unlock()
		return nil
	}
	if wait := time.Second - time.Since(b.lastKeyframeRequest); wait > 0 {
		if !b.keyframePending {
			b.keyframePending = true
			time.AfterFunc(wait, func() {
				b.mu.Lock()
				b.keyframePending = false
				b.mu.Unlock()
				select {
				case <-b.done:
					return
				default:
				}
				_ = b.observerKeyframe()
			})
		}
		b.mu.Unlock()
		return nil
	}
	b.lastKeyframeRequest = time.Now()
	b.mu.Unlock()
	return request()
}

func (b *agentBridge) unsubscribe(o *agentObserver) {
	b.mu.Lock()
	delete(b.observers, o)
	b.mu.Unlock()
	o.stop()
}

// Membership calls use the ordinary authenticated display registry, retaining
// its pilot gate, namespace authorization, participant bound and replica routing.
func (d *agentDeps) observerMember(ctx context.Context, r *http.Request, ns, name, action, id string) (string, int, error) {
	endpoint := strings.TrimRight(d.API, "/") + "/v1/workspaces/" + url.PathEscape(name) + "/display/" + action + "?namespace=" + url.QueryEscape(ns)
	body, _ := json.Marshal(map[string]string{"role": "observer", "participant_id": id})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return "", 503, err
	}
	req.Header.Set("Content-Type", "application/json")
	if d.Credential != nil {
		req.Header.Set("Authorization", d.Credential(r))
	}
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 503, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", resp.StatusCode, errors.New("display membership refused")
	}
	if action == "leave" || action == "observer" {
		return "", 200, nil
	}
	var result struct {
		Participant struct {
			ID string `json:"id"`
		} `json:"participant"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&result)
	if err == nil && result.Participant.ID == "" {
		err = errors.New("missing display participant")
	}
	return result.Participant.ID, 503, err
}

func serveAgentObserver(deps *agentDeps, w http.ResponseWriter, r *http.Request, ns, name string) {
	registry := deps.registry()
	registry.mu.Lock()
	bridge := registry.sessions[registry.key(ns, name)]
	registry.mu.Unlock()
	if bridge == nil {
		deps.forwardAgentObserver(w, r, ns, name)
		return
	}
	// Join before revealing bridge state, so the API re-authorizes each viewer.
	id, status, err := deps.observerMember(r.Context(), r, ns, name, "join", "")
	if err != nil {
		http.Error(w, "premium observer membership refused", status)
		return
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _, _ = deps.observerMember(ctx, r, ns, name, "leave", id)
	}()
	o, hello, err := bridge.subscribe()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer bridge.unsubscribe(o)
	if _, status, err := deps.observerMember(r.Context(), r, ns, name, "observer", id); err != nil {
		http.Error(w, "observer membership unavailable", status)
		return
	}
	ws, err := agentWSUpgrade(w, r)
	if err != nil {
		return
	}
	defer ws.close()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		select {
		case <-ctx.Done():
		case <-bridge.done:
		case <-o.done:
		}
		_ = ws.close()
	}()
	_ = ws.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_ = ws.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if ws.writeMessage(hello) != nil {
		return
	}
	message, err := ws.readMessage()
	if err != nil {
		return
	}
	var greeting struct {
		Session string `json:"sessionId"`
	}
	_ = json.Unmarshal(hello[5:], &greeting)
	var attach map[string]json.RawMessage
	if len(message) < 6 || len(message) > agentMaxControl+5 || message[0] != 0 || int(binary.BigEndian.Uint32(message[1:5])) != len(message)-5 || json.Unmarshal(message[5:], &attach) != nil {
		return
	}
	var kind, session string
	_ = json.Unmarshal(attach["type"], &kind)
	_ = json.Unmarshal(attach["sessionId"], &session)
	if kind != "attach" || session != greeting.Session {
		return
	}
	attach["type"] = json.RawMessage(`"attachResult"`)
	attach["payload"] = json.RawMessage(`{"admitted":true,"role":"observer"}`)
	body, _ := json.Marshal(attach)
	_ = ws.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if ws.writeMessage(agentWire(0, body)) != nil {
		return
	}
	monitoring.Establish(r.Context(), "observer")
	monitoring.AgentEvidence(r.Context(), true, false)
	if err := bridge.observerKeyframe(); err != nil {
		return
	}
	_ = ws.conn.SetReadDeadline(time.Time{})
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()
	// Nothing a view-only peer sends is ever written to the guest. A narrow
	// local allowlist permits bootstrap/keepalive/close, all mutations detach.
	go func() {
		defer cancel()
		for {
			frame, err := ws.readMessage()
			if err != nil {
				return
			}
			if len(frame) < 6 || frame[0] != 0 || len(frame) > agentMaxControl+5 || int(binary.BigEndian.Uint32(frame[1:5])) != len(frame)-5 {
				return
			}
			var msg struct {
				Type    string `json:"type"`
				Session string `json:"sessionId"`
			}
			if json.Unmarshal(frame[5:], &msg) != nil || msg.Session != greeting.Session {
				return
			}
			switch msg.Type {
			case "keyframeRequest":
			case "bye":
				return
			default:
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-bridge.done:
			return
		case <-o.done:
			return
		case <-heartbeat.C:
			if _, _, err := deps.observerMember(ctx, r, ns, name, "observer", id); err != nil {
				return
			}
		case frame := <-o.queue:
			o.mu.Lock()
			o.bytes -= len(frame)
			o.mu.Unlock()
			_ = ws.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if ws.writeMessage(frame) != nil {
				return
			}
			if frame[0] != 0 {
				monitoring.AgentEvidence(r.Context(), false, true)
			}
		}
	}
}

func (d *agentDeps) forwardAgentObserver(w http.ResponseWriter, r *http.Request, ns, name string) {
	u, err := url.Parse(d.API)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "agent API unavailable", 503)
		return
	}
	endpoint := strings.TrimRight(d.API, "/") + "/v1/workspaces/" + url.PathEscape(name) + "/tier1/status?namespace=" + url.QueryEscape(ns)
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		http.Error(w, "agent status unavailable", 503)
		return
	}
	if d.Credential != nil {
		req.Header.Set("Authorization", d.Credential(r))
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "agent status unavailable", 503)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		http.Error(w, "agent status refused", resp.StatusCode)
		return
	}
	var status struct {
		Owner     string `json:"proxyOwner"`
		Transport string `json:"transport"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&status) != nil {
		http.Error(w, "invalid agent status", 503)
		return
	}
	if status.Transport != "agent" || status.Owner == "" || status.Owner == d.Owner || d.ResolveOwner == nil || r.Header.Get("X-KW-Agent-Hop") != "" {
		http.Error(w, "premium controller unavailable; reconnect when streaming", 409)
		return
	}
	host, err := d.ResolveOwner(ctx, status.Owner)
	if err != nil {
		http.Error(w, "premium proxy owner unavailable", 409)
		return
	}
	// Resolver only returns Kubernetes-verified peer addresses. Never route to
	// a host or URL supplied by the viewer or guest; the peer re-authorizes.
	proxy := &httputil.ReverseProxy{Director: func(req *http.Request) {
		req.URL.Scheme, req.URL.Host = "http", host
		req.Header.Set("X-KW-Agent-Hop", "1")
	}}
	monitoring.Ignore(r.Context())
	proxy.ServeHTTP(w, r)
}
