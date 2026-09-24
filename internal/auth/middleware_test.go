package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockProvider struct {
	config  *AuthConfig
	user    *UserInfo
	userErr error
}

func (m *mockProvider) GetConfig(ctx context.Context) (*AuthConfig, error) {
	return m.config, nil
}

func (m *mockProvider) GetUserByEmail(ctx context.Context, email string) (*UserInfo, error) {
	if m.userErr != nil {
		return nil, m.userErr
	}
	if m.user == nil {
		return &UserInfo{Email: email, Role: "viewer"}, nil
	}
	return m.user, nil
}

func TestIsRestrictedPath(t *testing.T) {
	tests := []struct {
		path   string
		prefix string
		want   bool
	}{
		{"/proxy/ns/name/api/websockets", "/proxy", true},
		{"/proxy/ns/name/api/health", "/proxy", false},
		{"/proxy/ns/name/api/status", "/proxy", false},
		{"/proxy/ns/name/api/vnc", "/proxy", true},
		{"/proxy/ns/name/index.html", "/proxy", false},
		{"/ns/name/api/websockets", "", true},
		{"/ns/name/foo", "", false},
	}

	for _, tt := range tests {
		if got := isRestrictedPath(tt.path, tt.prefix); got != tt.want {
			t.Errorf("isRestrictedPath(%q, %q) = %v; want %v", tt.path, tt.prefix, got, tt.want)
		}
	}
}

// signPayload builds a kw-session token (payload.signature) signed with key.
func signPayload(key []byte, token SessionToken) string {
	payload, _ := json.Marshal(token)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func validToken(key []byte, email, role string) string {
	return signPayload(key, SessionToken{
		Email:     email,
		Role:      role,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
}

func nextOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func doRequest(t *testing.T, provider ConfigReader, path, authHeader string) int {
	t.Helper()
	h := Middleware(provider, "/proxy")(nextOK())
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestMiddlewareRoleEnforcement(t *testing.T) {
	key := []byte("test-signing-key")

	viewerNS := &UserInfo{Email: "viewer@example.com", Role: "viewer", PersonalNamespace: "viewer-ns"}
	editorNS := &UserInfo{Email: "editor@example.com", Role: "editor", PersonalNamespace: "editor-ns"}

	tests := []struct {
		name       string
		provider   ConfigReader
		path       string
		authHeader string
		want       int
	}{
		{"auth disabled passes through", &mockProvider{config: &AuthConfig{Enabled: false}}, "/proxy/ns/name/foo", "Bearer " + validToken(key, "viewer@example.com", "viewer"), http.StatusOK},
		{"health endpoint passes through without token", &mockProvider{config: &AuthConfig{Enabled: true}}, "/readyz", "", http.StatusOK},
		{"missing token is 401", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}}, "/proxy/ns/name/foo", "", http.StatusUnauthorized},
		{"malformed token is 401", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}}, "/proxy/ns/name/foo", "Bearer not-a-token", http.StatusUnauthorized},
		{"forged token is 401", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}}, "/proxy/ns/name/foo", "Bearer " + signPayload([]byte("wrong-key"), SessionToken{Email: "viewer@example.com", Role: "viewer", ExpiresAt: time.Now().Add(time.Hour).Unix()}), http.StatusUnauthorized},
		{"expired token is 401", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}}, "/proxy/ns/name/foo", "Bearer " + signPayload(key, SessionToken{Email: "viewer@example.com", Role: "viewer", ExpiresAt: time.Now().Add(-time.Hour).Unix()}), http.StatusUnauthorized},
		{"admin role bypasses namespace checks", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}, user: &UserInfo{Email: "admin@example.com", Role: "viewer"}}, "/proxy/ns/name/foo", "Bearer " + validToken(key, "admin@example.com", "admin"), http.StatusOK},
		{"admin email override bypasses namespace checks", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key, AdminEmails: []string{"admin@example.com"}}, user: &UserInfo{Email: "admin@example.com", Role: "viewer"}}, "/proxy/ns/name/foo", "Bearer " + validToken(key, "admin@example.com", "viewer"), http.StatusOK},
		{"viewer with namespace access passes", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}, user: viewerNS}, "/proxy/viewer-ns/name/foo", "Bearer " + validToken(key, "viewer@example.com", "viewer"), http.StatusOK},
		{"viewer without namespace access is 403", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}, user: viewerNS}, "/proxy/other-ns/name/foo", "Bearer " + validToken(key, "viewer@example.com", "viewer"), http.StatusForbidden},
		{"unknown user is 403", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}, userErr: errors.New("user not found")}, "/proxy/ns/name/foo", "Bearer " + validToken(key, "ghost@example.com", "viewer"), http.StatusForbidden},
		{"disabled user is 403", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}, userErr: errors.New("user account is disabled")}, "/proxy/ns/name/foo", "Bearer " + validToken(key, "disabled@example.com", "viewer"), http.StatusForbidden},
		{"viewer restricted guest api is 403", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}, user: viewerNS}, "/proxy/viewer-ns/name/api/websockets", "Bearer " + validToken(key, "viewer@example.com", "viewer"), http.StatusForbidden},
		{"editor restricted guest api passes", &mockProvider{config: &AuthConfig{Enabled: true, SigningKey: key}, user: editorNS}, "/proxy/editor-ns/name/api/websockets", "Bearer " + validToken(key, "editor@example.com", "editor"), http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := doRequest(t, tt.provider, tt.path, tt.authHeader); got != tt.want {
				t.Errorf("status = %d, want %d", got, tt.want)
			}
		})
	}
}
