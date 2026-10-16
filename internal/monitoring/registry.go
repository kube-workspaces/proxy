// Package monitoring owns process-local, client-facing bridge telemetry.
// The snapshot wire contract is shared with api/internal/monitoring.
package monitoring

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

type Metadata struct {
	WorkspaceUID  string `json:"workspace_uid"`
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	WorkspaceType string `json:"workspace_type"`
	Category      string `json:"category"`
	Transport     string `json:"transport"`
	Tier          string `json:"tier,omitempty"`
	Role          string `json:"role,omitempty"`
	User          string `json:"user,omitempty"`
	ByteLayer     string `json:"byte_layer"`
}
type Connection struct {
	Metadata
	ID            string     `json:"id"`
	State         string     `json:"state"`
	StartedAt     time.Time  `json:"started_at"`
	ConnectedAt   *time.Time `json:"connected_at,omitempty"`
	LastActivity  *time.Time `json:"last_activity,omitempty"`
	ToWorkspace   uint64     `json:"to_workspace_bytes"`
	ToClient      uint64     `json:"to_client_bytes"`
	MediaObserved bool       `json:"media_observed"`
	GuestAdmitted bool       `json:"guest_admitted"`
	// Guest agent build/platform/capture as advertised in hello. Empty
	// until the first hello is observed on the bridge; never a readiness
	// claim on its own, but combined with guest_admitted + media_observed
	// it identifies what is actually streaming.
	GuestVersion  string `json:"guest_version,omitempty"`
	GuestPlatform string `json:"guest_platform,omitempty"`
	CaptureWidth  int    `json:"capture_width,omitempty"`
	CaptureHeight int    `json:"capture_height,omitempty"`
}
type Traffic struct {
	Metadata
	ToWorkspace uint64 `json:"to_workspace_bytes"`
	ToClient    uint64 `json:"to_client_bytes"`
}
type Snapshot struct {
	SetupFailures uint64       `json:"setup_failures"`
	Protocol      int          `json:"protocol"`
	Component     string       `json:"component"`
	Owner         string       `json:"owner"`
	BootID        string       `json:"boot_id"`
	ObservedAt    time.Time    `json:"observed_at"`
	Connections   []Connection `json:"connections"`
	Traffic       []Traffic    `json:"traffic"`
}
type totals struct {
	Metadata
	In, Out, Attempts, Established, Closed, Failed uint64
}
type workspaceTotals struct {
	Traffic
	touched time.Time
}
type Registry struct {
	mu                     sync.Mutex
	component, owner, boot string
	platform               string
	lastPrune              time.Time
	draining               bool
	connections            map[string]*Session
	traffic                map[string]*workspaceTotals
	totals                 map[string]*totals
}
type Session struct {
	registry    *Registry
	connection  Connection
	key, labels string
	ended       bool
	close       func() error
}

func (s *Session) BindClose(close func() error) {
	if s == nil {
		return
	}
	s.registry.mu.Lock()
	s.close = close
	draining := s.registry.draining
	s.registry.mu.Unlock()
	if draining {
		_ = close()
	}
}
func (r *Registry) Close() {
	r.mu.Lock()
	r.draining = true
	var sessions []*Session
	for _, s := range r.connections {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	for _, s := range sessions {
		r.mu.Lock()
		close := s.close
		r.mu.Unlock()
		if close != nil {
			_ = close()
		}
		s.End()
	}
}

type sessionKey struct{}

func randomID() string { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func New(component string) *Registry {
	owner, _ := os.Hostname()
	return &Registry{platform: os.Getenv("KW_MONITORING_PLATFORM"), component: component, owner: owner, boot: randomID(), connections: map[string]*Session{}, traffic: map[string]*workspaceTotals{}, totals: map[string]*totals{}}
}
func (r *Registry) Start(m Metadata) *Session {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.lastPrune) > time.Minute {
		r.pruneLocked(time.Now())
		r.lastPrune = time.Now()
	}
	labels := fmt.Sprintf("kw_platform=%q,category=%q,transport=%q,tier=%q,byte_layer=%q", r.platform, m.Category, m.Transport, m.Tier, m.ByteLayer)
	key := m.WorkspaceUID + "/" + m.Namespace + "/" + m.Name + "/" + labels
	if r.totals[labels] == nil {
		r.totals[labels] = &totals{Metadata: m}
	}
	r.totals[labels].Attempts++
	s := &Session{registry: r, key: key, labels: labels, connection: Connection{Metadata: m, ID: randomID(), State: "connecting", StartedAt: time.Now().UTC()}}
	r.connections[s.connection.ID] = s
	return s
}
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}
func FromContext(ctx context.Context) *Session   { s, _ := ctx.Value(sessionKey{}).(*Session); return s }
func Establish(ctx context.Context, role string) { FromContext(ctx).Establish(role) }
func (s *Session) Establish(role string) {
	if s == nil {
		return
	}
	r := s.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ended || s.connection.State == "established" {
		return
	}
	now := time.Now().UTC()
	s.connection.ConnectedAt = &now
	s.connection.State = "established"
	if role != "" {
		s.connection.Role = role
	}
	r.totals[s.labels].Established++
}
func (s *Session) Add(in bool, n int) {
	if s == nil || n <= 0 {
		return
	}
	r := s.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ended || (s.connection.State != "established" && s.connection.Category != "http") {
		return
	}
	now := time.Now().UTC()
	s.connection.LastActivity = &now
	t := r.traffic[s.key]
	if t == nil {
		m := s.connection.Metadata
		m.User = ""
		m.Role = ""
		t = &workspaceTotals{Traffic: Traffic{Metadata: m}}
		r.traffic[s.key] = t
	}
	t.touched = now
	if in {
		s.connection.ToWorkspace += uint64(n)
		t.ToWorkspace += uint64(n)
		r.totals[s.labels].In += uint64(n)
	} else {
		s.connection.ToClient += uint64(n)
		t.ToClient += uint64(n)
		r.totals[s.labels].Out += uint64(n)
	}
}
func (s *Session) End() {
	if s == nil {
		return
	}
	r := s.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ended {
		return
	}
	s.ended = true
	delete(r.connections, s.connection.ID)
	if s.connection.State == "established" {
		r.totals[s.labels].Closed++
	} else {
		r.totals[s.labels].Failed++
	}
}

func AgentEvidence(ctx context.Context, admitted, media bool) {
	s := FromContext(ctx)
	if s == nil {
		return
	}
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	s.connection.GuestAdmitted = s.connection.GuestAdmitted || admitted
	s.connection.MediaObserved = s.connection.MediaObserved || media
}

// AgentHello records the guest's self-reported hello on a bridge: agent
// build, platform and capture size. First hello wins for the connection;
// a changed version mid-bridge means the guest restarted under us, which
// the generation counters already surface elsewhere.
func AgentHello(ctx context.Context, version, platform string, width, height int) {
	s := FromContext(ctx)
	if s == nil {
		return
	}
	s.registry.mu.Lock()
	defer s.registry.mu.Unlock()
	if s.connection.GuestVersion != "" {
		return
	}
	s.connection.GuestVersion = version
	s.connection.GuestPlatform = platform
	s.connection.CaptureWidth = width
	s.connection.CaptureHeight = height
}
func Ignore(ctx context.Context) {
	s := FromContext(ctx)
	if s == nil {
		return
	}
	r := s.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	if !s.ended {
		s.ended = true
		delete(r.connections, s.connection.ID)
		r.totals[s.labels].Attempts--
	}
}
func (r *Registry) Snapshot() Snapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	v := Snapshot{Protocol: 1, Component: r.component, Owner: r.owner, BootID: r.boot, ObservedAt: now, Connections: []Connection{}, Traffic: []Traffic{}}
	active := map[string]bool{}
	for _, t := range r.totals {
		v.SetupFailures += t.Failed
	}
	for _, s := range r.connections {
		v.Connections = append(v.Connections, s.connection)
		active[s.key] = true
	}
	for key, t := range r.traffic {
		if !active[key] && now.Sub(t.touched) > 10*time.Minute {
			delete(r.traffic, key)
			continue
		}
		v.Traffic = append(v.Traffic, t.Traffic)
	}
	sort.Slice(v.Connections, func(i, j int) bool { return v.Connections[i].ID < v.Connections[j].ID })
	return v
}
func (r *Registry) ServeSnapshot(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(r.Snapshot())
}

func (r *Registry) pruneLocked(now time.Time) {
	active := map[string]bool{}
	for _, s := range r.connections {
		active[s.key] = true
	}
	for key, t := range r.traffic {
		if !active[key] && now.Sub(t.touched) > 10*time.Minute {
			delete(r.traffic, key)
		}
	}
}
func (r *Registry) ServeMetrics(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	totalsCopy := map[string]totals{}
	for labels, t := range r.totals {
		totalsCopy[labels] = *t
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	active := map[string]int{}
	for _, s := range r.connections {
		if s.connection.State == "established" {
			active[s.labels]++
		}
	}
	r.mu.Unlock()
	for _, metric := range []string{"connections_active", "connection_attempts_total", "connections_established_total", "connections_closed_total", "connection_setup_failures_total", "traffic_bytes_total"} {
		kind := "counter"
		if metric == "connections_active" {
			kind = "gauge"
		}
		fmt.Fprintf(w, "# TYPE kubeworkspaces_%s %s\n", metric, kind)
	}
	for labels, t := range totalsCopy {
		fmt.Fprintf(w, "kubeworkspaces_connections_active{%s} %d\n", labels, active[labels])
		fmt.Fprintf(w, "kubeworkspaces_connection_attempts_total{%s} %d\n", labels, t.Attempts)
		fmt.Fprintf(w, "kubeworkspaces_connections_established_total{%s} %d\n", labels, t.Established)
		fmt.Fprintf(w, "kubeworkspaces_connections_closed_total{%s} %d\n", labels, t.Closed)
		fmt.Fprintf(w, "kubeworkspaces_connection_setup_failures_total{%s} %d\n", labels, t.Failed)
		fmt.Fprintf(w, "kubeworkspaces_traffic_bytes_total{%s,direction=\"toward_workspace\"} %d\n", labels, t.In)
		fmt.Fprintf(w, "kubeworkspaces_traffic_bytes_total{%s,direction=\"toward_client\"} %d\n", labels, t.Out)
	}
}
