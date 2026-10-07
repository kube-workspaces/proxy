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
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
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

// agentBridge is one held session: counters for the telemetry the indicator
// contract requires (API/proxy/client/guest must agree on usage).
type agentBridge struct {
	bytesToGuest   int64
	bytesToViewer  int64
	framesToGuest  int64
	framesToViewer int64
	done           chan struct{}
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
	Registry *agentRegistry
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
	dialer := &net.Dialer{}
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return ticket, http.StatusServiceUnavailable, err
	}
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
	if ticket.Protocol != 1 || ticket.ID == "" || len(ticket.Ticket) == 0 || ticket.TTLMillis <= 0 {
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

// agentWSFrame wraps one agent frame (tag+len+body) for the wire.
func agentWSFrame(tag byte, body []byte) []byte {
	frame := make([]byte, 0, len(body)+5)
	frame = append(frame, tag)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(body)))
	frame = append(frame, length...)
	return append(frame, body...)
}

// serveAgent bridges one WebSocket viewer to one guest agent TCP session.
func serveAgent(deps *agentDeps, w http.ResponseWriter, r *http.Request, ns, name string, port int32) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "WebSocket upgrade required", http.StatusUpgradeRequired)
		return
	}
	registry := deps.registry()
	bridge := &agentBridge{done: make(chan struct{})}
	if !registry.tryHold(ns, name, bridge) {
		http.Error(w, `{"error":"agent session busy"}`, http.StatusConflict)
		return
	}
	defer registry.release(ns, name, bridge)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	ticket, status, err := deps.agentCall(ctx, "attach", deps.API, ns, name, r.Header, "")
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), status)
		return
	}
	renewCtx, renewCancel := context.WithCancel(context.Background())
	defer renewCancel()
	go agentRenewLoop(renewCtx, deps, ns, name, r.Header, ticket)

	websocket.Server{
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler: func(ws *websocket.Conn) {
			defer cancel()
			defer agentRelease(context.Background(), deps, ns, name, r.Header, ticket.ID)
			guest, err := deps.dial(ctx, ns, name, port)
			if err != nil {
				_ = ws.Close()
				return
			}
			defer guest.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				defer guest.Close()
				var message []byte
				for {
					if err := websocket.Message.Receive(ws, &message); err != nil {
						return
					}
					if len(message) < 5 || len(message)-5 > agentMaxMedia {
						return
					}
					if _, err := guest.Write(message); err != nil {
						return
					}
					bridge.framesToGuest++
					bridge.bytesToGuest += int64(len(message))
				}
			}()
			go func() {
				defer wg.Done()
				defer ws.Close()
				for {
					tag, body, err := agentFrame(guest)
					if err != nil {
						return
					}
					if err := websocket.Message.Send(ws, agentWSFrame(tag, body)); err != nil {
						return
					}
					bridge.framesToViewer++
					bridge.bytesToViewer += int64(len(body) + 5)
				}
			}()
			wg.Wait()
		},
	}.ServeHTTP(w, r)
	close(bridge.done)
}

func agentRenewLoop(ctx context.Context, deps *agentDeps, ns, name string, headers http.Header, ticket agentTicket) {
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
