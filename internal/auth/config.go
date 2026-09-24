package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	Enabled     bool
	SigningKey  []byte
	AdminEmails []string
}

// UserInfo represents the authenticated user's identity and access.
type UserInfo struct {
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
}

// NewConfigProvider creates a new ConfigProvider with a 30-second cache.
func NewConfigProvider(dynamicClient dynamic.Interface) *ConfigProvider {
	return &ConfigProvider{
		dynamicClient: dynamicClient,
		cacheDuration: 30 * time.Second,
	}
}

// GetConfig returns the current auth configuration, fetching from Kubernetes if the cache is stale.
// GetConfig returns the current auth configuration, fetching from Kubernetes
// if the cache is stale. A refresh failure serves the previously-loaded
// config and triggers a background retry; only a first-load failure is fatal.
// Failures must never change a working config into pass-through.
func (p *ConfigProvider) GetConfig(ctx context.Context) (*AuthConfig, error) {
	p.mu.RLock()
	if p.config != nil && time.Since(p.lastFetch) < p.cacheDuration {
		cfg := p.config
		p.mu.RUnlock()
		return cfg, nil
	}
	if p.config != nil {
		cfg := p.config
		p.mu.RUnlock()
		go func() {
			if _, err := p.refresh(context.Background()); err != nil {
				log.Printf("auth: refresh failed; serving cached config: %v", err)
			}
		}()
		return cfg, nil
	}
	p.mu.RUnlock()

	return p.refresh(ctx)
}

func (p *ConfigProvider) refresh(ctx context.Context) (*AuthConfig, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring write lock
	if p.config != nil && time.Since(p.lastFetch) < p.cacheDuration {
		return p.config, nil
	}

	cfg, err := p.loadFromCluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigUnavailable, err)
	}
	p.config = cfg
	p.lastFetch = time.Now()
	return cfg, nil
}

func (p *ConfigProvider) loadFromCluster(ctx context.Context) (*AuthConfig, error) {
	obj, err := p.dynamicClient.Resource(authConfigGVR).Get(ctx, "default", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		// No AuthConfig CR means auth genuinely disabled (opt-in).
		return &AuthConfig{Enabled: false}, nil
	}
	if err != nil {
		return nil, err
	}

	cfg := &AuthConfig{Enabled: false}

	// Parse spec.enabled
	enabled, _, _ := unstructured.NestedBool(obj.Object, "spec", "enabled")
	cfg.Enabled = enabled

	if !enabled {
		return cfg, nil
	}

	// Parse admin emails
	adminEmails, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "adminEmails")
	cfg.AdminEmails = adminEmails

	// Load signing key from Secret
	signingKeyRef, _, _ := unstructured.NestedString(obj.Object, "spec", "session", "signingKey", "name")
	signingKeyKey, _, _ := unstructured.NestedString(obj.Object, "spec", "session", "signingKey", "key")
	if signingKeyRef != "" && signingKeyKey != "" {
		secret, err := p.getSecret(ctx, signingKeyRef, signingKeyKey)
		if err == nil {
			cfg.SigningKey = []byte(secret)
		}
	}

	return cfg, nil
}

func (p *ConfigProvider) getSecret(ctx context.Context, name, key string) (string, error) {
	// Try kube-workspaces-system namespace first, then default
	for _, ns := range []string{"kube-workspaces-system", "default"} {
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
	// Try by slugified name first (faster than list)
	slugName := slugifyEmail(email)
	obj, err := p.dynamicClient.Resource(userGVR).Get(ctx, slugName, metav1.GetOptions{})
	if err == nil {
		userEmail, _, _ := unstructured.NestedString(obj.Object, "spec", "email")
		if strings.EqualFold(userEmail, email) {
			return extractUserInfo(obj)
		}
	}

	// Fallback: list and filter (handles edge cases where slug doesn't match exactly)
	list, err := p.dynamicClient.Resource(userGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	for i := range list.Items {
		userEmail, _, _ := unstructured.NestedString(list.Items[i].Object, "spec", "email")
		if strings.EqualFold(userEmail, email) {
			return extractUserInfo(&list.Items[i])
		}
	}
	return nil, fmt.Errorf("user with email %s not found", email)
}

func extractUserInfo(obj *unstructured.Unstructured) (*UserInfo, error) {
	email, _, _ := unstructured.NestedString(obj.Object, "spec", "email")
	displayName, _, _ := unstructured.NestedString(obj.Object, "spec", "displayName")
	role, _, _ := unstructured.NestedString(obj.Object, "spec", "role")
	personalNS, _, _ := unstructured.NestedString(obj.Object, "status", "personalNamespace")
	disabled, _, _ := unstructured.NestedBool(obj.Object, "spec", "disabled")

	if disabled {
		return nil, fmt.Errorf("user account is disabled")
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
