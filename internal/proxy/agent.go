package proxy

// Agent transport bridge: WebSocket at the edge, framed TCP inside.
//
// Route: {prefix}/{namespace}/{name}/agent/ upgrades to WebSocket and is
// bridged to the guest agent's TCP listener (one framed-protocol frame per
// WS binary message, in both directions). The viewer authenticates with the
// platform session; the proxy acquires a short-lived agent ticket from the
// API (like display claims), holds one active bridge per workspace (409 when
// busy), renews while traffic flows and releases on close.
//
// Guest requirements (controller schema/P2): the workspace Service exposes
// the agent port and the agent listens there. Without AgentPort configured
// the route refuses with 503 — never silently, never assumed.

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kube-workspaces/proxy/internal/monitoring"
)

const (
	// agentMaxControl is the 1MiB control-frame cap from the wire spec.
	agentMaxControl = 1024 * 1024
	// agentMaxMedia is the 8MiB media-frame cap from the wire spec.
	agentMaxMedia = 8 * 1024 * 1024
	// agentTagControl marks a JSON control envelope on the wire.
	agentTagControl = 0x00
)

// agentTicket is the API-issued attach ticket (opaque JSON to the proxy;
// the guest validates its binding, epoch and expiry).
type agentTicket struct {
	ID        string          `json:"id"`
	Ticket    json.RawMessage `json:"ticket"`
	TTLMillis int64           `json:"ttl_ms"`
	Protocol  int             `json:"protocol"`
}

// agentRegistry holds at most one active bridge per workspace, mirroring the
// single-controller seat: a second viewer gets 409 busy, never a second
// control channel.
type agentRegistry struct {
	mu       sync.Mutex
	sessions map[string]*agentBridge
}

func (r *agentRegistry) key(ns, name string) string { return ns + "/" + name }

// tryHold registers a bridge unless one is active. Returns false when busy.
func (r *agentRegistry) tryHold(ns, name string, bridge *agentBridge) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions == nil {
		r.sessions = map[string]*agentBridge{}
	}
	key := r.key(ns, name)
	if _, busy := r.sessions[key]; busy {
		return false
	}
	r.sessions[key] = bridge
	return true
}

func (r *agentRegistry) release(ns, name string, bridge *agentBridge) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sessions[r.key(ns, name)] == bridge {
		delete(r.sessions, r.key(ns, name))
	}
}

// Disconnect reasons recorded on the bridge snapshot (Layer 2 of the
// transport indicator contract). They describe how the session ended, never
// user content.
const (
	agentEndGuestUnreachable = "guest-unreachable"
	agentEndViewerClosed     = "viewer-closed"
	agentEndGuestClosed      = "guest-closed"
	agentEndViewerRejected   = "viewer-frame-rejected"
	agentEndGuestWriteFailed = "guest-write-failed"
	agentEndViewWriteFailed  = "viewer-write-failed"
)

// agentSnapshot is a point-in-time copy of one held session: attach time,
// control/media bytes and frames in both directions, and (once ended) how
// the session ended. An ended session with zero media bytes is a
// failed-attach, never usage. There is intentionally no HTTP route serving
// these yet; the snapshot is the in-process API a future status consumer
// reads.
type agentSnapshot struct {
	AttachedAt       time.Time
	EndedAt          time.Time
	DisconnectReason string
	ControlToGuest   int64
	MediaToGuest     int64
	ControlToViewer  int64
	MediaToViewer    int64
	FramesToGuest    int64
	FramesToViewer   int64
}

// Active reports whether the session still holds the seat.
func (s agentSnapshot) Active() bool { return s.DisconnectReason == "" }

// MediaBytes totals media (non-control) bytes in both directions.
func (s agentSnapshot) MediaBytes() int64 { return s.MediaToGuest + s.MediaToViewer }

// agentBridge is one held session: mutex-guarded counters for the telemetry
// the indicator contract requires (API/proxy/client/guest must agree on
// usage). Both copy goroutines update it; readers take Snapshot.
type agentBridge struct {
	mu                  sync.Mutex
	attachedAt          time.Time
	endedAt             time.Time
	endReason           string
	controlToGuest      int64
	mediaToGuest        int64
	controlToView       int64
	mediaToView         int64
	framesToGuest       int64
	framesToView        int64
	done                chan struct{}
	observers           map[*agentObserver]struct{}
	helloFrame          []byte
	admitted            bool
	sps, pps            []byte
	requestKeyframe     func() error
	lastKeyframeRequest time.Time
	keyframePending     bool
}

// newAgentBridge holds a session starting now.
func newAgentBridge(now time.Time) *agentBridge {
	return &agentBridge{attachedAt: now, done: make(chan struct{})}
}

// addViewerFrame accounts one viewer→guest message by its wire tag
// (0x00 control, anything else media). Callers must have validated the
// 5-byte framed header already.
func (b *agentBridge) addViewerFrame(tag byte, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if tag == agentTagControl {
		b.controlToGuest += n
	} else {
		b.mediaToGuest += n
	}
	b.framesToGuest++
}

// addGuestFrame accounts one guest→viewer frame by its wire tag.
func (b *agentBridge) addGuestFrame(tag byte, n int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if tag == agentTagControl {
		b.controlToView += n
	} else {
		b.mediaToView += n
	}
	b.framesToView++
}

// finish records how the session ended. First reason wins: the copy loop
// that detects the failure owns the verdict, not a racing teardown.
func (b *agentBridge) finish(now time.Time, reason string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.endReason != "" {
		return
	}
	b.endReason = reason
	b.endedAt = now
}

// Snapshot copies the current counters.
func (b *agentBridge) Snapshot() agentSnapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	return agentSnapshot{
		AttachedAt:       b.attachedAt,
		EndedAt:          b.endedAt,
		DisconnectReason: b.endReason,
		ControlToGuest:   b.controlToGuest,
		MediaToGuest:     b.mediaToGuest,
		ControlToViewer:  b.controlToView,
		MediaToViewer:    b.mediaToView,
		FramesToGuest:    b.framesToGuest,
		FramesToViewer:   b.framesToView,
	}
}

// snapshot returns the held session's counters, or false when no session
// holds the seat.
func (r *agentRegistry) snapshot(ns, name string) (agentSnapshot, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	bridge, ok := r.sessions[r.key(ns, name)]
	if !ok {
		return agentSnapshot{}, false
	}
	return bridge.Snapshot(), true
}

// agentDeps wires the bridge to its surroundings for tests.
type agentDeps struct {
	// API origin for ticket attach/renew/release (DisplayAPIURL equivalent).
	API string
	// HTTP client for API calls.
	Client *http.Client
	// DialAgent opens the guest TCP connection (K8s Service address).
	DialAgent func(ctx context.Context, ns, name string, port int32) (net.Conn, error)
	// Credential extracts the viewer Authorization for API calls.
	Credential func(r *http.Request) string
	// Registry for single-session discipline. Defaults to a fresh one when nil.
	Registry     *agentRegistry
	Owner        string
	ResolveOwner func(context.Context, string) (string, error)
}

func (d *agentDeps) registry() *agentRegistry {
	if d.Registry != nil {
		return d.Registry
	}
	return &agentRegistry{}
}

func (d *agentDeps) dial(ctx context.Context, ns, name string, port int32) (net.Conn, error) {
	if d.DialAgent != nil {
		return d.DialAgent(ctx, ns, name, port)
	}
	address := fmt.Sprintf("%s.%s.svc.cluster.local:%d", name, ns, port)
	// Bounded: an unreachable guest must fail the bridge fast (502/close),
	// never wedge it until the viewer gives up.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return dialer.DialContext(ctx, "tcp", address)
}

// agentCall POSTs an agent ticket action to the API, mirroring the display
// claim credential pattern (viewer Authorization, no platform cookies).
func (d *agentDeps) agentCall(ctx context.Context, action, api, ns, name string, headers http.Header, session string) (agentTicket, int, error) {
	var ticket agentTicket
	u, err := url.Parse(api)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ticket, http.StatusServiceUnavailable, errors.New("agent ticket API is not configured")
	}
	endpoint := strings.TrimRight(api, "/") + "/v1/workspaces/" + url.PathEscape(name) + "/agent/" + action + "?namespace=" + url.QueryEscape(ns)
	// The API requires a JSON body on these POSTs (Goa rejects bodiless
	// posts with missing-payload before auth/binding): {} for attach
	// (name arrives via the path), session correlation for renew/release
	// (mirrored in the X-KW-Agent-Session header per the API contract).
	body := `{}`
	if session != "" && action != "attach" {
		encoded, err := json.Marshal(map[string]string{"session_id": session})
		if err != nil {
			return ticket, http.StatusServiceUnavailable, err
		}
		body = string(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return ticket, http.StatusServiceUnavailable, err
	}
	req.Header.Set("Content-Type", "application/json")
	if d.Credential != nil {
		if credential := d.Credential(&http.Request{Header: headers}); credential != "" {
			req.Header.Set("Authorization", credential)
		}
	}
	if session != "" {
		req.Header.Set("X-KW-Agent-Session", session)
	}
	client := d.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return ticket, http.StatusServiceUnavailable, errors.New("agent ticket service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		status := resp.StatusCode
		if status != 401 && status != 403 && status != 409 && status != 404 {
			status = http.StatusServiceUnavailable
		}
		return ticket, status, errors.New("agent ticket request refused")
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&ticket); err != nil {
		return ticket, http.StatusServiceUnavailable, err
	}
	if action == "release" {
		return ticket, http.StatusOK, nil
	}
	if ticket.Protocol != 1 || ticket.TTLMillis <= 0 || (action == "attach" && (ticket.ID == "" || len(ticket.Ticket) == 0)) {
		return ticket, http.StatusServiceUnavailable, errors.New("unsupported agent ticket protocol")
	}
	return ticket, http.StatusOK, nil
}

// agentFrame reads one framed-protocol frame from a TCP stream with the wire
// spec caps enforced at the edge (protects the guest from blowup).
func agentFrame(reader io.Reader) (tag byte, body []byte, err error) {
	header := make([]byte, 5)
	if _, err = io.ReadFull(reader, header); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint32(header[1:5]))
	cap := agentMaxControl
	if header[0] != agentTagControl {
		if header[0] != 0x01 && header[0] != 0x02 {
			return 0, nil, fmt.Errorf("unknown media kind %d", header[0])
		}
		cap = agentMaxMedia
	}
	if length == 0 || length > cap {
		return 0, nil, fmt.Errorf("frame size %d outside caps", length)
	}
	body = make([]byte, length)
	if _, err = io.ReadFull(reader, body); err != nil {
		return 0, nil, err
	}
	return header[0], body, nil
}

// agentWSConn is a minimal WebSocket server endpoint over a hijacked
// connection. x/net/websocket requires a raw http.Hijacker and panics behind
// the proxy's status-capturing middleware wrappers; manual framing hijacks
// through http.ResponseController (which traverses Unwrap) instead. Server
// messages go out unmasked; client messages must arrive masked.
type agentWSConn struct {
	conn net.Conn
	br   *bufio.Reader
	mu   sync.Mutex
}

const agentWSGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// agentWSUpgrade validates the handshake request, hijacks the connection and
// writes the 101 response. No mitigation beyond the platform auth already
// enforced upstream: the bridge admits exactly one held session per
// workspace and the API ticket gate runs before this point.
func agentWSUpgrade(w http.ResponseWriter, r *http.Request) (*agentWSConn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("missing Sec-WebSocket-Key")
	}
	accept := wsAcceptKey(key)
	conn, readWriter, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return nil, err
	}
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := conn.Write([]byte(response)); err != nil {
		conn.Close()
		return nil, err
	}
	return &agentWSConn{conn: conn, br: readWriter.Reader}, nil
}

func wsAcceptKey(key string) string {
	// RFC 6455 §1.3: SHA-1 (not SHA-256) over the client key + GUID.
	sum := sha1.Sum([]byte(key + agentWSGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// readMessage returns one complete binary message. Fragmented, text and
// oversized messages terminate the session (the agent protocol already
// frames its own units; reassembly is not negotiated here). Ping is
// answered; close terminates.
func (c *agentWSConn) readMessage() ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(c.br, header); err != nil {
		return nil, err
	}
	fin := header[0]&0x80 != 0
	opcode := header[0] & 0x0F
	masked := header[1]&0x80 != 0
	length := int64(header[1] & 0x7F)
	switch length {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return nil, err
		}
		length = int64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(c.br, ext); err != nil {
			return nil, err
		}
		length = int64(binary.BigEndian.Uint64(ext))
	}
	if length < 0 || length > agentMaxMedia+5 {
		return nil, fmt.Errorf("message size %d outside caps", length)
	}
	// Clients must mask; servers must not.
	if !masked {
		return nil, errors.New("unmasked client frame")
	}
	mask := make([]byte, 4)
	if _, err := io.ReadFull(c.br, mask); err != nil {
		return nil, err
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.br, payload); err != nil {
		return nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	switch opcode {
	case 0x2:
		if !fin {
			return nil, errors.New("fragmented messages unsupported")
		}
		return payload, nil
	case 0x8:
		return nil, io.EOF
	case 0x9:
		_ = c.writeFrame(0xA, payload)
		return c.readMessage()
	case 0xA:
		return c.readMessage()
	default:
		return nil, fmt.Errorf("unsupported opcode %d", opcode)
	}
}

// writeMessage sends one binary message (single frame, unmasked).
func (c *agentWSConn) writeMessage(payload []byte) error {
	return c.writeFrame(0x2, payload)
}

func (c *agentWSConn) writeFrame(opcode byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	header := []byte{0x80 | opcode}
	length := len(payload)
	switch {
	case length <= 125:
		header = append(header, byte(length))
	case length <= 65535:
		header = append(header, 126, byte(length>>8), byte(length))
	default:
		header = append(header, 127, 0, 0, 0, 0, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	_, err := c.conn.Write(payload)
	return err
}

func (c *agentWSConn) close() error {
	return c.conn.Close()
}

// serveAgent bridges one WebSocket viewer to one guest agent TCP session.
func serveAgent(deps *agentDeps, w http.ResponseWriter, r *http.Request, ns, name string, port int32) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "WebSocket upgrade required", http.StatusUpgradeRequired)
		return
	}
	purpose := "display"
	if value := r.URL.Query().Get("purpose"); value != "" {
		switch value {
		case "v1.display", "v1.telemetry", "v1.clipboard", "v1.observe":
			purpose = strings.TrimPrefix(value, "v1.")
		default:
			http.Error(w, "unsupported agent purpose", http.StatusBadRequest)
			return
		}
	}
	if purpose == "observe" {
		serveAgentObserver(deps, w, r, ns, name)
		return
	}
	registry := deps.registry()
	bridge := newAgentBridge(time.Now())
	if !registry.tryHold(ns, name, bridge) {
		http.Error(w, `{"error":"agent session busy"}`, http.StatusConflict)
		return
	}
	defer registry.release(ns, name, bridge)
	defer close(bridge.done)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var claim *displayClaim
	if purpose == "display" {
		var status int
		var err error
		headers := r.Header.Clone()
		headers.Set("X-KW-Display-Transport", "agent")
		headers.Set("X-KW-Agent-Owner", deps.Owner)
		claim, status, err = acquireDisplay(ctx, deps.API, ns, name, headers, cancel)
		if err != nil {
			http.Error(w, "interactive display claim refused", status)
			return
		}
		defer claim.close()
	}
	ticket, status, err := deps.agentCall(ctx, "attach", deps.API, ns, name, r.Header, "")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), status)
		return
	}
	defer agentRelease(context.Background(), deps, ns, name, r.Header, ticket.ID)
	grant, err := agentGrant(ticket)
	if err != nil {
		http.Error(w, "invalid agent authority response", http.StatusServiceUnavailable)
		return
	}
	admission := &agentAdmission{grant: grant, purpose: purpose}
	go agentRenewLoop(ctx, deps, ns, name, r.Header, ticket, cancel)

	ws, err := agentWSUpgrade(w, r)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	func() {
		defer cancel()
		guest, err := deps.dial(ctx, ns, name, port)
		if err != nil {
			log.Printf("agent bridge %s/%s: guest dial failed: %v", ns, name, err)
			bridge.finish(time.Now(), agentEndGuestUnreachable)
			_ = ws.close()
			return
		}
		defer guest.Close()
		// Viewer controls and proxy-coalesced late-join keyframes share one
		// serializer and clock; neither may overtake the other's guest writes.
		var guestWriteMu sync.Mutex
		writeViewer := func(message []byte) (string, error) {
			guestWriteMu.Lock()
			defer guestWriteMu.Unlock()
			message, err := admission.viewerFrame(message)
			if err != nil {
				return agentEndViewerRejected, err
			}
			deadline := time.Now().Add(2 * time.Second)
			if claim != nil {
				fence, valid := claim.validDeadline()
				if !valid {
					return agentEndGuestWriteFailed, errors.New("display claim expired")
				}
				if fence.Before(deadline) {
					deadline = fence
				}
			}
			if err := guest.SetWriteDeadline(deadline); err != nil {
				return agentEndGuestWriteFailed, err
			}
			if _, err := guest.Write(message); err != nil {
				return agentEndGuestWriteFailed, err
			}
			bridge.addViewerFrame(message[0], int64(len(message)))
			return "", nil
		}
		bridge.mu.Lock()
		bridge.requestKeyframe = func() error {
			admission.mu.Lock()
			session := admission.session
			admission.mu.Unlock()
			body, _ := json.Marshal(map[string]any{"protocol": "kw-agent-v1", "protocolVersion": 1, "generation": 1, "channel": "control", "type": "keyframeRequest", "sessionId": session, "payload": map[string]any{}})
			reason, err := writeViewer(agentWire(0, body))
			if err != nil {
				bridge.finish(time.Now(), reason)
				_ = guest.Close()
			}
			return err
		}
		bridge.mu.Unlock()
		monitoring.Establish(r.Context(), "agent_"+purpose)
		go func() { <-ctx.Done(); _ = guest.Close(); _ = ws.close() }()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer guest.Close()
			for {
				message, err := ws.readMessage()
				if err != nil {
					bridge.finish(time.Now(), agentEndViewerClosed)
					return
				}
				if reason, err := writeViewer(message); err != nil {
					bridge.finish(time.Now(), reason)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			defer ws.close()
			for {
				tag, body, err := agentFrame(guest)
				if err != nil {
					bridge.finish(time.Now(), agentEndGuestClosed)
					return
				}
				frame := make([]byte, 0, len(body)+5)
				frame = append(frame, tag)
				length := make([]byte, 4)
				binary.BigEndian.PutUint32(length, uint32(len(body)))
				frame = append(frame, length...)
				frame = append(frame, body...)
				if tag == agentTagControl {
					admission.observe(body)
					if version, platform, w, h := admission.hello(); version != "" {
						monitoring.AgentHello(r.Context(), version, platform, w, h)
					}
				} else if purpose != "display" {
					continue // Legacy clipboard guests may emit media; never forward it.
				}
				if purpose == "display" {
					bridge.publish(frame)
				}
				_ = ws.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if err := ws.writeMessage(frame); err != nil {
					bridge.finish(time.Now(), agentEndViewWriteFailed)
					return
				}
				bridge.addGuestFrame(tag, int64(len(body)+5))
				if tag == agentTagControl {
					var envelope struct {
						Type    string `json:"type"`
						Payload struct {
							Admitted bool `json:"admitted"`
						} `json:"payload"`
					}
					if json.Unmarshal(body, &envelope) == nil && envelope.Type == "attachResult" {
						monitoring.AgentEvidence(r.Context(), envelope.Payload.Admitted, false)
					}
				} else {
					monitoring.AgentEvidence(r.Context(), false, true)
				}
			}
		}()
		wg.Wait()
	}()
}

func agentRenewLoop(ctx context.Context, deps *agentDeps, ns, name string, headers http.Header, ticket agentTicket, cancel context.CancelFunc) {
	interval := time.Duration(ticket.TTLMillis/2) * time.Millisecond
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, _, err := deps.agentCall(ctx, "renew", deps.API, ns, name, headers, ticket.ID); err != nil {
				cancel()
				return
			}
		}
	}
}

func agentRelease(ctx context.Context, deps *agentDeps, ns, name string, headers http.Header, id string) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _, _ = deps.agentCall(ctx, "release", deps.API, ns, name, headers, id)
}
