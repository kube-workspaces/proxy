package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const displayTTL = 4 * time.Second

type displayClaim struct {
	mu                sync.Mutex
	deadline          time.Time
	closed            bool
	api, ns, name, id string
	credential        http.Header
	client            *http.Client
	cancel            context.CancelFunc
	done              chan struct{}
}

type claimResponse struct {
	ID       string `json:"id"`
	TTL      int64  `json:"ttl_ms"`
	Protocol int    `json:"protocol"`
}

func acquireDisplay(ctx context.Context, api, ns, name string, headers http.Header, revoke context.CancelFunc) (*displayClaim, int, error) {
	u, err := url.Parse(api)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, http.StatusServiceUnavailable, errors.New("display ownership API is not configured")
	}
	c := &displayClaim{api: strings.TrimRight(api, "/"), ns: ns, name: name, credential: make(http.Header),
		client: &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, done: make(chan struct{})}
	// Match platform auth's cookie precedence, without forwarding unrelated cookies.
	request := &http.Request{Header: headers}
	if cookie, err := request.Cookie("kw-session"); err == nil && cookie.Value != "" {
		c.credential.Set("Authorization", "Bearer "+cookie.Value)
	} else {
		c.credential.Set("Authorization", headers.Get("Authorization"))
	}
	started := time.Now()
	response, status, err := c.call(ctx, "claim")
	if err != nil {
		return nil, status, err
	}
	c.id = response.ID
	if len(c.id) != 64 || response.Protocol != 1 || response.TTL != int64(displayTTL/time.Millisecond) {
		return nil, http.StatusServiceUnavailable, errors.New("unsupported display ownership protocol")
	}
	c.deadline = started.Add(displayTTL)
	ctx, c.cancel = context.WithCancel(ctx)
	go c.run(ctx, revoke)
	return c, 0, nil
}

func (c *displayClaim) call(ctx context.Context, action string) (claimResponse, int, error) {
	endpoint := c.api + "/v1/workspaces/" + url.PathEscape(c.name) + "/tier1/" + action + "?namespace=" + url.QueryEscape(c.ns)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return claimResponse{}, http.StatusServiceUnavailable, err
	}
	req.Header = c.credential.Clone()
	if c.id != "" {
		req.Header.Set("X-KW-Display-Claim", c.id)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return claimResponse{}, http.StatusServiceUnavailable, errors.New("display ownership service unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		status := resp.StatusCode
		if status != 401 && status != 403 && status != 409 && status != 404 {
			status = http.StatusServiceUnavailable
		}
		return claimResponse{}, status, errors.New("display ownership request refused")
	}
	var result claimResponse
	err = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&result)
	return result, http.StatusServiceUnavailable, err
}

func (c *displayClaim) validDeadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline, !c.closed && time.Now().Before(c.deadline)
}

func (c *displayClaim) run(ctx context.Context, revoke context.CancelFunc) {
	defer close(c.done)
	defer revoke()
	defer func() { c.mu.Lock(); c.closed = true; c.mu.Unlock() }()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deadline, valid := c.validDeadline()
			if !valid {
				return
			}
			started := time.Now()
			renewCtx, cancel := context.WithDeadline(ctx, deadline)
			response, _, err := c.call(renewCtx, "renew")
			cancel()
			c.mu.Lock()
			if err != nil || response.Protocol != 1 || response.TTL != int64(displayTTL/time.Millisecond) || !time.Now().Before(c.deadline) {
				c.closed = true
				c.mu.Unlock()
				return
			}
			c.deadline = started.Add(displayTTL)
			c.mu.Unlock()
		}
	}
}

// Called after ReverseProxy has closed both upgraded sockets. Stop renewals
// first, then release. Lost releases expire conservatively in the API store.
func (c *displayClaim) close() {
	c.cancel()
	<-c.done
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, _ = c.call(ctx, "release")
}

type displayConn struct {
	net.Conn
	claim *displayClaim
}

func (c *displayConn) Write(data []byte) (int, error) {
	deadline, valid := c.claim.validDeadline()
	if !valid {
		_ = c.Close()
		return 0, errors.New("display ownership expired")
	}
	if err := c.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	return c.Conn.Write(data)
}
