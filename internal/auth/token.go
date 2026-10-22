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
	AuthMethod        string   `json:"auth_method,omitempty"`
	CredentialVersion string   `json:"credential_version,omitempty"`
	Issuer            string   `json:"issuer,omitempty"`
	Subject           string   `json:"subject,omitempty"`
	UserUID           string   `json:"user_uid,omitempty"`
	Type              string   `json:"typ,omitempty"`
	JTI               string   `json:"jti,omitempty"`
	Email             string   `json:"email"`
	DisplayName       string   `json:"displayName,omitempty"`
	Role              string   `json:"role"`
	Groups            []string `json:"groups,omitempty"`
	IssuedAt          int64    `json:"iat"`
	ExpiresAt         int64    `json:"exp"`
}

// ValidateSessionToken validates and decodes a session token.
// Token format: base64url(JSON payload).base64url(HMAC-SHA256 signature)
func ValidateSessionToken(tokenStr string, signingKey []byte) (*SessionToken, error) {
	return ValidateSessionTokenWithKeys(tokenStr, [][]byte{signingKey})
}

func ValidateSessionTokenWithKeys(tokenStr string, signingKeys [][]byte) (*SessionToken, error) {
	if len(signingKeys) == 0 {
		return nil, fmt.Errorf("session signing key is not configured")
	}
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token format")
	}

	encodedPayload := parts[0]
	signature := parts[1]

	// Verify HMAC signature
	valid := false
	for _, key := range signingKeys {
		if len(key) == 0 {
			continue
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(encodedPayload))
		expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		if hmac.Equal([]byte(signature), []byte(expectedSig)) {
			valid = true
			break
		}
	}
	if !valid {
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
