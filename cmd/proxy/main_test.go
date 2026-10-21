package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kube-workspaces/proxy/internal/auth"
)

func TestIsTopLevelNavigation(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		// Fetch Metadata (modern browsers)
		{"sec-fetch-dest=document", map[string]string{"Sec-Fetch-Dest": "document"}, true},
		{"sec-fetch-dest=script", map[string]string{"Sec-Fetch-Dest": "script"}, false},
		{"sec-fetch-dest=image", map[string]string{"Sec-Fetch-Dest": "image"}, false},
		{"sec-fetch-dest=empty (XHR/fetch)", map[string]string{"Sec-Fetch-Dest": "empty"}, false},
		{"sec-fetch-dest=websocket", map[string]string{"Sec-Fetch-Dest": "websocket"}, false},

		// Accept header fallback (older browsers / curl)
		{"accept=text/html first", map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}, true},
		{"accept=application/json", map[string]string{"Accept": "application/json"}, false},
		{"accept=*/*", map[string]string{"Accept": "*/*"}, false},
		{"no headers", map[string]string{}, false},

		// Sec-Fetch-Dest takes precedence over Accept
		{"sec=document overrides accept=json", map[string]string{"Sec-Fetch-Dest": "document", "Accept": "application/json"}, true},
		{"sec=empty overrides accept=html", map[string]string{"Sec-Fetch-Dest": "empty", "Accept": "text/html"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/change-password", nil)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			if got := isTopLevelNavigation(r); got != tt.want {
				t.Errorf("isTopLevelNavigation() = %v, want %v", got, tt.want)
			}
		})
	}
}

type routingAuthProvider struct{}

func (routingAuthProvider) GetConfig(context.Context) (*auth.AuthConfig, error) {
	return &auth.AuthConfig{Enabled: true, SigningKey: []byte("routing-key")}, nil
}
func (routingAuthProvider) GetUserByEmail(context.Context, string) (*auth.UserInfo, error) {
	return &auth.UserInfo{Email: "user@example.com", Role: "viewer", PersonalNamespace: "allowed"}, nil
}
func (routingAuthProvider) ValidateDevice(context.Context, *auth.SessionToken) error { return nil }

func TestRecoveredPathsAreAuthorizedBeforeDispatch(t *testing.T) {
	payload, err := json.Marshal(auth.SessionToken{Email: "user@example.com", Role: "editor", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte("routing-key"))
	mac.Write([]byte(encoded))
	token := encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	for _, tt := range []struct {
		name, path, referer, dest, expectedPath string
		anonymous                               bool
		want                                    int
	}{
		{name: "allowed recovery", path: "/asset.js", referer: "https://example.com/proxy/allowed/ws/", expectedPath: "/proxy/allowed/ws/asset.js", want: 200},
		{name: "denied namespace", path: "/asset.js", referer: "https://example.com/proxy/denied/ws/", want: 403},
		{name: "denied interactive path", path: "/api/websockets", referer: "https://example.com/proxy/allowed/ws/", want: 403},
		{name: "root recovery requires authentication", path: "/", referer: "https://example.com/proxy/allowed/ws/", anonymous: true, want: 401},
		{name: "explicit path wins", path: "/proxy/denied/ws/asset.js", referer: "https://example.com/proxy/allowed/ws/", want: 403},
		{name: "full page navigation stays local", path: "/account", referer: "https://example.com/proxy/denied/ws/", dest: "document", expectedPath: "/account", want: 200},
		{name: "health stays public", path: "/healthz", referer: "https://example.com/proxy/denied/ws/", anonymous: true, expectedPath: "/healthz", want: 200},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dispatched := false
			upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				dispatched = true
				if r.URL.Path != tt.expectedPath {
					t.Errorf("path=%s, want %s", r.URL.Path, tt.expectedPath)
				}
				w.WriteHeader(200)
			})
			handler := recoverWorkspacePath(auth.Middleware(routingAuthProvider{}, "/proxy")(upstream), "/proxy")
			req := httptest.NewRequest("GET", tt.path, nil)
			req.Header.Set("Referer", tt.referer)
			req.Header.Set("Sec-Fetch-Dest", tt.dest)
			if !tt.anonymous {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.want || dispatched != (tt.want == 200) {
				t.Fatalf("status=%d dispatched=%t, want %d", rec.Code, dispatched, tt.want)
			}
		})
	}
}
