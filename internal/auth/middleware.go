package auth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

const (
	// SessionCookieName is the name of the session cookie.
	SessionCookieName = "kw-session"
)

// ConfigReader abstracts the auth configuration and user lookups the
// middleware needs, so tests can substitute a mock. *ConfigProvider
// implements it.
type ConfigReader interface {
	GetConfig(ctx context.Context) (*AuthConfig, error)
	GetUserByEmail(ctx context.Context, email string) (*UserInfo, error)
}

// Middleware creates an HTTP middleware that validates session tokens and checks
// namespace access before allowing proxy requests through.
//
// The middleware extracts the namespace from the request path (expected format:
// /proxy/{namespace}/{name}/...) and verifies the authenticated user has access.
//
// Behavior:
//   - Auth disabled (AuthConfig.spec.enabled=false) → pass through
//   - Health endpoints (/healthz, /readyz) → pass through
//   - No token → 401 Unauthorized
//   - Invalid/expired token → 401 Unauthorized
//   - User disabled → 403 Forbidden
//   - No namespace access → 403 Forbidden
//   - Valid token + access → pass through
func Middleware(provider ConfigReader, pathPrefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Always allow health checks
			if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
				next.ServeHTTP(w, r)
				return
			}

			// Always allow the root info endpoint
			if r.URL.Path == "/" || r.URL.Path == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Always allow no-op service worker
			if r.URL.Path == "/sw.js" {
				next.ServeHTTP(w, r)
				return
			}

			// Get auth config — deny on unavailable state, never fail-open.
			cfg, err := provider.GetConfig(ctx)
			if err != nil {
				log.Printf("auth: failed to get config: %v", err)
				writeAuthError(w, http.StatusServiceUnavailable, "auth configuration unavailable")
				return
			}

			// If auth is not enabled, pass through
			if !cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}

			// Extract token from cookie or Authorization header
			tokenStr := ""
			cookie, err := r.Cookie(SessionCookieName)
			if err == nil && cookie.Value != "" {
				tokenStr = cookie.Value
			} else {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if tokenStr == "" {
				writeAuthError(w, http.StatusUnauthorized, "authentication required")
				return
			}

			// Validate the session token
			token, err := ValidateSessionToken(tokenStr, cfg.SigningKey)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, err.Error())
				return
			}

			// Check if user is in admin emails list (override role)
			role := token.Role
			for _, adminEmail := range cfg.AdminEmails {
				if strings.EqualFold(adminEmail, token.Email) {
					role = "admin"
					break
				}
			}

			// Admins bypass namespace access checks
			if role == "admin" {
				next.ServeHTTP(w, r)
				return
			}

			// Extract namespace from path
			namespace := extractNamespace(r.URL.Path, pathPrefix)
			if namespace == "" {
				// Can't determine namespace — let the proxy handler deal with it
				// (it will return 400 for malformed paths)
				next.ServeHTTP(w, r)
				return
			}

			// Look up user's namespace access (not cached — instant revocation)
			user, err := provider.GetUserByEmail(ctx, token.Email)
			if err != nil {
				// If user lookup fails, check if it's a "disabled" error
				if strings.Contains(err.Error(), "disabled") {
					writeAuthError(w, http.StatusForbidden, "user account is disabled")
					return
				}
				// User not found in CRs — no namespace access
				writeAuthError(w, http.StatusForbidden, "no access to namespace")
				return
			}

			// Override role from token if admin emails matched
			user.Role = role

			// Check namespace access
			if !UserHasNamespaceAccess(user, namespace) {
				writeAuthError(w, http.StatusForbidden, "no access to namespace "+namespace)
				return
			}

			// Enforce editor/admin role for restricted guest API paths (interactive console access)
			if isRestrictedPath(r.URL.Path, pathPrefix) {
				if !HasMinimumRole(user.Role, "editor") {
					writeAuthError(w, http.StatusForbidden, "editor or admin role required for interactive console access")
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isRestrictedPath reports whether path (after stripping prefix) is a guest API
// path that requires interactive (editor/admin) access. This covers Tier 1
// transport and management endpoints.
func isRestrictedPath(path, pathPrefix string) bool {
	if pathPrefix != "" {
		path = strings.TrimPrefix(path, pathPrefix)
	}
	path = strings.TrimPrefix(path, "/")

	// Expected format: {namespace}/{name}/{rest...}
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 3 {
		return false
	}
	rest := "/" + parts[2]

	// Selkies and other guest agents often use /api/ for their control plane.
	// /api/health and /api/status are left open for monitoring.
	if rest == "/api/health" || rest == "/api/status" {
		return false
	}
	return strings.HasPrefix(rest, "/api/")
}

// extractNamespace extracts the namespace from a proxy request path.
// Expected formats:
//   - /proxy/{namespace}/{name}/...  (when pathPrefix="/proxy")
//   - /{namespace}/{name}/...        (when pathPrefix="")
func extractNamespace(path, pathPrefix string) string {
	if pathPrefix != "" {
		path = strings.TrimPrefix(path, pathPrefix)
	}
	path = strings.TrimPrefix(path, "/")

	parts := strings.SplitN(path, "/", 3)
	if len(parts) >= 2 && parts[0] != "" {
		return parts[0]
	}
	return ""
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   http.StatusText(status),
		"message": message,
	})
}
