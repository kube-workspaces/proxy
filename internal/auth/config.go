package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	authConfigGVR = schema.GroupVersionResource{
		Group:    "kubeworkspaces.io",
		Version:  "v1alpha1",
		Resource: "authconfigs",
	}
	userGVR = schema.GroupVersionResource{
		Group:    "kubeworkspaces.io",
		Version:  "v1alpha1",
		Resource: "users",
	}
	secretGVR = schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "secrets",
	}
)

// ErrConfigUnavailable reports a genuine failure loading the auth
// configuration from the cluster. It must never be treated as "auth
// disabled": a read failure cannot opt the proxy out of authentication.
var ErrConfigUnavailable = fmt.Errorf("auth config unavailable from cluster")

// AuthConfig holds the resolved authentication configuration needed by the proxy.
type AuthConfig struct {
	Enabled            bool
	SigningKey         []byte
	PreviousSigningKey []byte
	TokenExpiry        time.Duration
	AdminEmails        []string
}

func (c *AuthConfig) SessionSigningKeys() [][]byte {
	keys := [][]byte{c.SigningKey}
	if len(c.PreviousSigningKey) > 0 {
		keys = append(keys, c.PreviousSigningKey)
	}
	return keys
}

// UserInfo represents the authenticated user's identity and access.
type UserInfo struct {
	record            *unstructured.Unstructured
	UID               string
	Email             string
	DisplayName       string
	Role              string
	PersonalNamespace string
	Namespaces        []string
}

// ConfigProvider loads and caches the AuthConfig from Kubernetes.
// The signing key and AuthConfig are cached for 30 seconds.
// User CRs are looked up fresh on every request for instant revocation.
type ConfigProvider struct {
	dynamicClient dynamic.Interface
	mu            sync.RWMutex
	config        *AuthConfig
	lastFetch     time.Time
	cacheDuration time.Duration
	lastError     error
	rotatedAt     time.Time
}

// NewConfigProvider creates a new ConfigProvider with a 30-second cache.
func NewConfigProvider(dynamicClient dynamic.Interface) *ConfigProvider {
	return &ConfigProvider{
		dynamicClient: dynamicClient,
		cacheDuration: 30 * time.Second,
	}
}

// GetConfig returns the current auth configuration, fetching from Kubernetes
// if the cache is stale. Like API, failed refreshes deny requests rather than
// authorizing against stale (possibly disabled) configuration.
func (p *ConfigProvider) GetConfig(ctx context.Context) (*AuthConfig, error) {
	p.mu.RLock()
	if !p.lastFetch.IsZero() && time.Since(p.lastFetch) < p.cacheDuration {
		cfg, err := p.cachedResult()
		p.mu.RUnlock()
		return cfg, err
	}
	p.mu.RUnlock()

	return p.refresh(ctx)
}

func (p *ConfigProvider) cachedResult() (*AuthConfig, error) {
	if p.lastError != nil {
		return nil, p.lastError
	}
	return p.config, nil
}

func (p *ConfigProvider) refresh(ctx context.Context) (*AuthConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if !p.lastFetch.IsZero() && time.Since(p.lastFetch) < p.cacheDuration {
		return p.cachedResult()
	}

	cfg, err := p.loadFromCluster(ctx)
	p.lastFetch = time.Now()
	if err != nil {
		p.lastError = fmt.Errorf("%w: %v", ErrConfigUnavailable, err)
		return nil, p.lastError
	}
	p.lastError = nil
	if p.config != nil {
		switch {
		case bytes.Equal(p.config.SigningKey, cfg.SigningKey):
			if time.Since(p.rotatedAt) <= cfg.TokenExpiry {
				cfg.PreviousSigningKey = p.config.PreviousSigningKey
			}
		case len(cfg.SigningKey) > 0:
			cfg.PreviousSigningKey = p.config.SigningKey
			p.rotatedAt = time.Now()
		}
	}
	p.config = cfg
	return cfg, nil
}

func (p *ConfigProvider) loadFromCluster(ctx context.Context) (*AuthConfig, error) {
	obj, err := p.dynamicClient.Resource(authConfigGVR).Get(ctx, "default", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	cfg := &AuthConfig{TokenExpiry: 24 * time.Hour}

	// Parse spec.enabled
	enabled, found, err := unstructured.NestedBool(obj.Object, "spec", "enabled")
	if err != nil || !found {
		return nil, fmt.Errorf("AuthConfig spec.enabled must be an explicit boolean")
	}
	cfg.Enabled = enabled

	if !enabled {
		return cfg, nil
	}
	if expiry, _, _ := unstructured.NestedString(obj.Object, "spec", "session", "tokenExpiry"); expiry != "" {
		if duration, err := time.ParseDuration(expiry); err == nil {
			cfg.TokenExpiry = duration
		}
	}

	// Parse admin emails
	adminEmails, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "adminEmails")
	cfg.AdminEmails = adminEmails

	// Load signing key from Secret
	signingKeyRef, _, _ := unstructured.NestedString(obj.Object, "spec", "session", "signingKey", "name")
	signingKeyKey, _, _ := unstructured.NestedString(obj.Object, "spec", "session", "signingKey", "key")
	if signingKeyRef == "" || signingKeyKey == "" {
		return nil, fmt.Errorf("auth is enabled but no session signing key secret is configured")
	}
	secret, err := p.getSecret(ctx, signingKeyRef, signingKeyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load session signing key from secret %s/%s: %w", signingKeyRef, signingKeyKey, err)
	}
	if secret == "" {
		return nil, fmt.Errorf("session signing key in secret %s/%s is empty", signingKeyRef, signingKeyKey)
	}
	cfg.SigningKey = []byte(secret)

	return cfg, nil
}

func (p *ConfigProvider) getSecret(ctx context.Context, name, key string) (string, error) {
	// Match the API: auth Secrets belong to this installation's pod namespace.
	// Keep legacy lookup only for launches without an explicit namespace.
	namespaces := []string{"kube-workspaces-system", "default"}
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		namespaces = []string{ns}
	}
	for _, ns := range namespaces {
		obj, err := p.dynamicClient.Resource(secretGVR).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			continue
		}

		data, found, _ := unstructured.NestedMap(obj.Object, "data")
		if !found {
			continue
		}

		val, ok := data[key].(string)
		if !ok {
			continue
		}

		// Secret .data values are base64-encoded by the Kubernetes API
		decoded, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			// If decoding fails, the value might already be plain text (e.g. from stringData)
			return val, nil
		}
		return string(decoded), nil
	}
	return "", fmt.Errorf("secret %s/%s not found", name, key)
}

// GetUserByEmail fetches a User CR by email address.
// This is NOT cached — called on every request for instant revocation.
func (p *ConfigProvider) GetUserByEmail(ctx context.Context, email string) (*UserInfo, error) {
	// Match API semantics: exact email and exactly one current User. A slug
	// shortcut would hide duplicate accounts and can resolve a different identity.
	list, err := p.dynamicClient.Resource(userGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	var matched *unstructured.Unstructured
	for i := range list.Items {
		userEmail, _, _ := unstructured.NestedString(list.Items[i].Object, "spec", "email")
		if userEmail == email {
			if matched != nil {
				return nil, fmt.Errorf("multiple user accounts match email")
			}
			matched = &list.Items[i]
		}
	}
	if matched != nil {
		return extractUserInfo(matched)
	}
	return nil, fmt.Errorf("user with email %s not found", email)
}

func extractUserInfo(obj *unstructured.Unstructured) (*UserInfo, error) {
	email, _, _ := unstructured.NestedString(obj.Object, "spec", "email")
	displayName, _, _ := unstructured.NestedString(obj.Object, "spec", "displayName")
	role, _, roleErr := unstructured.NestedString(obj.Object, "spec", "role")
	personalNS, _, _ := unstructured.NestedString(obj.Object, "status", "personalNamespace")
	disabled, _, err := unstructured.NestedBool(obj.Object, "spec", "disabled")

	if obj.GetDeletionTimestamp() != nil {
		return nil, fmt.Errorf("user account is being deleted")
	}
	if err != nil || disabled {
		return nil, fmt.Errorf("user account is disabled or invalid")
	}
	if roleErr != nil || (role != "admin" && role != "editor" && role != "viewer") {
		return nil, fmt.Errorf("current user role is invalid")
	}

	var namespaces []string
	if personalNS != "" {
		namespaces = append(namespaces, personalNS)
	}

	access, found, _ := unstructured.NestedSlice(obj.Object, "spec", "namespaceAccess")
	if found {
		for _, a := range access {
			if m, ok := a.(map[string]interface{}); ok {
				if ns, ok := m["namespace"].(string); ok {
					namespaces = append(namespaces, ns)
				}
			}
		}
	}

	return &UserInfo{
		record:            obj,
		UID:               string(obj.GetUID()),
		Email:             email,
		DisplayName:       displayName,
		Role:              role,
		PersonalNamespace: personalNS,
		Namespaces:        namespaces,
	}, nil
}

// UserHasNamespaceAccess checks if a user has access to a given namespace.
func UserHasNamespaceAccess(user *UserInfo, namespace string) bool {
	if user == nil {
		return true // Auth disabled
	}
	if user.Role == "admin" {
		return true
	}
	if user.PersonalNamespace == namespace {
		return true
	}
	for _, ns := range user.Namespaces {
		if ns == namespace {
			return true
		}
	}
	return false
}

// HasMinimumRole reports whether role is at least level.
// Levels: admin > editor > viewer > "".
func HasMinimumRole(role, level string) bool {
	if role == "admin" {
		return true
	}
	if role == "editor" {
		return level == "editor" || level == "viewer" || level == ""
	}
	if role == "viewer" {
		return level == "viewer" || level == ""
	}
	return level == ""
}

func slugifyEmail(email string) string {
	s := strings.ToLower(email)
	s = strings.ReplaceAll(s, "@", "-at-")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, "_", "-")
	var result []byte
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			result = append(result, c)
		}
	}
	s = strings.Trim(string(result), "-")
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}
