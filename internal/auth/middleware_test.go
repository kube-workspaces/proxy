package auth

import (
	"context"
	"testing"
)

type mockProvider struct {
	config *AuthConfig
}

func (m *mockProvider) GetConfig(ctx context.Context) (*AuthConfig, error) {
	return m.config, nil
}

func (m *mockProvider) GetUserByEmail(ctx context.Context, email string) (*UserInfo, error) {
	return &UserInfo{Email: email, Role: "viewer"}, nil
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

func TestMiddlewareRoleEnforcement(t *testing.T) {
	// TODO: implement middleware tests with proper token validation mocks
}
