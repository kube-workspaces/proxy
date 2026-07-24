// Package auth provides authentication middleware for the kube-workspaces proxy.
// It validates session tokens and checks namespace access before proxying requests.
// When auth is disabled (AuthConfig.spec.enabled=false), all requests pass through.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SessionToken represents the payload of a kw-session token.
type SessionToken struct {
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName,omitempty"`
	Role        string   `json:"role"`
	Groups      []string `json:"groups,omitempty"`
	IssuedAt    int64    `json:"iat"`
	ExpiresAt   int64    `json:"exp"`
}

// ValidateSessionToken validates and decodes a session token.
// Token format: base64url(JSON payload).base64url(HMAC-SHA256 signature)
func ValidateSessionToken(tokenStr string, signingKey []byte) (*SessionToken, error) {
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	encodedPayload := parts[0]
	signature := parts[1]

	// Verify HMAC signature
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(encodedPayload))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid token signature")
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("invalid token encoding: %w", err)
	}

	var token SessionToken
	if err := json.Unmarshal(payload, &token); err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}

	// Check expiry
	if time.Now().Unix() > token.ExpiresAt {
		return nil, fmt.Errorf("token expired")
	}

	return &token, nil
}
