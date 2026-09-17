// Package proxy provides a reverse proxy for workspace services running in-cluster.
// It supports HTTP and WebSocket connections, with Location header rewriting for redirects.
// Proxy behavior is configurable per-image via ProxyConfig.
package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Config holds proxy behavior hints for a specific workspace image.
type Config struct {
	// NeedsNoOpSW: serve a no-op ServiceWorker at /sw.js to prevent SW registration errors.
	NeedsNoOpSW bool
	// WebSocketPaths: paths that use WebSocket (informational — all paths support WS transparently).
	WebSocketPaths []string
	// RewriteHostAbsolutePaths: rewrite requests with absolute paths that escape the proxy
	// prefix by using the Referer header to determine the target workspace.
	RewriteHostAbsolutePaths bool
	// CustomRequestHeaders: additional headers to inject into proxied requests.
	CustomRequestHeaders map[string]string
	// InjectBaseTag: inject a <base> tag into HTML responses.
	InjectBaseTag bool
	// Scheme: the URL scheme used to connect to the workspace backend, "http" or
	// "https". Defaults to "http" when empty.
	Scheme string
	// TLSSkipVerify: when connecting over HTTPS, do not verify the backend's
	// certificate. Required for workspaces serving self-signed certs.
	TLSSkipVerify bool
	// TLSInsecure is deprecated: it conflated scheme selection with certificate
	// verification. Use Scheme ("https") and TLSSkipVerify instead. Still honoured
	// as a fallback when Scheme is empty, for backwards compatibility.
	TLSInsecure bool
	// PreservePathPrefix: forward the full proxy path (including /proxy/{ns}/{name}) to the
	// workspace pod instead of stripping it. Required for apps configured with a base URL
	// matching the proxy prefix (e.g. filebrowser --baseurl, JupyterLab --base-url).
	PreservePathPrefix bool
	// AudioPort: if set, requests to /audio/ are routed to this port instead of the
	// workspace's default port. Used for images with a separate audio WebSocket service.
	AudioPort int32
}

// ConfigLookup is a function that returns the proxy config for a given workspace image string.
// Returns nil if no specific config is found (default behavior applies).
type ConfigLookup func(imageRef string) *Config

// ResolveScheme returns the URL scheme to use for the backend connection.
// Precedence: explicit Scheme, then the deprecated TLSInsecure flag, then "http".
func (c *Config) ResolveScheme() string {
	if c == nil {
		return "http"
	}
	switch strings.ToLower(c.Scheme) {
	case "https":
		return "https"
	case "http":
		return "http"
	}
	// No explicit scheme: fall back to the deprecated combined flag.
	if c.TLSInsecure {
		return "https"
	}
	return "http"
}

// ResolveTLSSkipVerify reports whether backend certificate verification should be
// skipped. The deprecated TLSInsecure flag implies skip-verify.
func (c *Config) ResolveTLSSkipVerify() bool {
	if c == nil {
		return false
	}
	return c.TLSSkipVerify || c.TLSInsecure
}

// WorkspaceImageLookup is a function that returns the container image for a workspace
// given its namespace and name. Returns empty string if not found.
type WorkspaceImageLookup func(namespace, name string) string

// WorkspaceInfo holds workspace metadata relevant to proxy behavior.
type WorkspaceInfo struct {
	Image              string
	PreservePathPrefix bool // from workspace annotation
}

// WorkspaceInfoLookup is a function that returns workspace metadata including
// the image reference and proxy annotations. Returns nil if not found.
type WorkspaceInfoLookup func(namespace, name string) *WorkspaceInfo

// HandlerOptions configures the proxy handler.
type HandlerOptions struct {
	// ConfigLookup returns proxy config for a given image reference.
	ConfigLookup ConfigLookup
	// WorkspaceImageLookup returns the image reference for a workspace by ns/name.
	// Deprecated: use WorkspaceInfoLookup instead.
	WorkspaceImageLookup WorkspaceImageLookup
	// WorkspaceInfoLookup returns workspace metadata (image + annotations).
	// When set, takes precedence over WorkspaceImageLookup.
	WorkspaceInfoLookup WorkspaceInfoLookup
	// ExternalHost is the external hostname (e.g. "workspaces.example.com") that
	// clients use to reach this service. When set, it is forwarded as the Host
	// header to backend services so they generate correct remoteAuthority values.
	ExternalHost string
	// PathPrefix is the path prefix under which proxy requests are served.
	// Default is "/proxy" (routes are /proxy/{ns}/{name}/...).
	PathPrefix string
	// DisplayAPIURL is a trusted operator-configured API origin, never metadata
	// or an incoming Host header. Required for the Selkies interactive socket.
	DisplayAPIURL string
}

// Handler returns an http.Handler that proxies requests to workspace services.
// URL pattern: {prefix}/{namespace}/{name}/{rest...}
// Proxies to: http://{name}.{namespace}.svc.cluster.local:80/{rest...}
//
// Supports WebSocket upgrade transparently via httputil.ReverseProxy.
// Applies per-image proxy configuration when available.
func Handler(opts *HandlerOptions) http.Handler {
	prefix := ""
	if opts != nil {
		prefix = strings.TrimSuffix(opts.PathPrefix, "/")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip prefix to get /{namespace}/{name}/{rest...}
		path := r.URL.Path
		if prefix != "" {
			path = strings.TrimPrefix(path, prefix)
		}
		path = strings.TrimPrefix(path, "/")

		parts := strings.SplitN(path, "/", 3)

		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			http.Error(w, `{"error":"URL must be /{namespace}/{name}/..."}`, http.StatusBadRequest)
			return
		}

		namespace := parts[0]
		name := parts[1]
		rest := "/"
		if len(parts) == 3 {
			rest = "/" + parts[2]
		}
		var claim *displayClaim
		if strings.HasSuffix(rest, "/api/websockets") {
			if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				http.Error(w, "WebSocket upgrade required", http.StatusUpgradeRequired); return
			}
			api := ""
			if opts != nil { api = opts.DisplayAPIURL }
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			var status int
			var err error
			claim, status, err = acquireDisplay(ctx, api, namespace, name, r.Header, cancel)
			if err != nil { http.Error(w, err.Error(), status); return }
			defer claim.close()
			r = r.WithContext(ctx)
		}

		// Look up proxy config for this workspace's image
		var cfg *Config
		var wsPreservePathPrefix *bool // from workspace annotation (authoritative)
		if opts != nil {
			var imageRef string
			if opts.WorkspaceInfoLookup != nil {
				if info := opts.WorkspaceInfoLookup(namespace, name); info != nil {
					imageRef = info.Image
					ppp := info.PreservePathPrefix
					wsPreservePathPrefix = &ppp
				}
			} else if opts.WorkspaceImageLookup != nil {
				imageRef = opts.WorkspaceImageLookup(namespace, name)
			}
			if imageRef != "" && opts.ConfigLookup != nil {
				cfg = opts.ConfigLookup(imageRef)
			}
		}
		// Workspace annotation overrides Image CR's preservePathPrefix setting.
		// This ensures old workspaces (without SUBFOLDER env) don't get
		// preservePathPrefix applied just because the Image CR was updated.
		if wsPreservePathPrefix != nil {
			if cfg == nil {
				cfg = &Config{}
			}
			cfg.PreservePathPrefix = *wsPreservePathPrefix
		}

		// Build target URL
		// Always specify :80 explicitly so that https scheme doesn't default to port 443.
		targetPort := int32(80)
		// Route audio requests to the audio port if configured
		if cfg != nil && cfg.AudioPort > 0 && (rest == "/audio/" || strings.HasPrefix(rest, "/audio/")) {
			targetPort = cfg.AudioPort
		}
		targetHost := fmt.Sprintf("%s.%s.svc.cluster.local:%d", name, namespace, targetPort)
		scheme := cfg.ResolveScheme()
		target := &url.URL{
			Scheme: scheme,
			Host:   targetHost,
		}

		// proxyPrefix is the full path prefix for this workspace (used in response rewriting)
		var proxyPrefix string
		if prefix != "" {
			proxyPrefix = fmt.Sprintf("%s/%s/%s", prefix, namespace, name)
		} else {
			proxyPrefix = fmt.Sprintf("/%s/%s", namespace, name)
		}

		proxy := &httputil.ReverseProxy{
			// Use custom transport to skip TLS verification for self-signed certs
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.ResolveTLSSkipVerify()},
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
					if err == nil && claim != nil { return &displayConn{Conn: conn, claim: claim}, nil }
					return conn, err
				},
			},
			Director: func(req *http.Request) {
				req.URL.Scheme = target.Scheme
				req.URL.Host = target.Host
				// When preservePathPrefix is enabled, forward the full path including
				// the proxy prefix (e.g. /proxy/{ns}/{name}/...) so apps configured with
				// a matching base URL can strip it themselves.
				if cfg != nil && cfg.PreservePathPrefix {
					req.URL.Path = proxyPrefix + rest
				} else {
					req.URL.Path = rest
				}
				// Preserve original query string
				req.URL.RawQuery = r.URL.RawQuery

				// Forward the external Host header so that backend services
				// (e.g. code-server) generate correct remoteAuthority values.
				// ExternalHost takes precedence; fall back to the incoming request Host.
				if opts != nil && opts.ExternalHost != "" {
					req.Host = opts.ExternalHost
				} else {
					req.Host = r.Host
				}

				// Set standard forwarding headers
				req.Header.Set("X-Forwarded-Host", r.Host)
				if r.TLS != nil {
					req.Header.Set("X-Forwarded-Proto", "https")
				} else if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
					req.Header.Set("X-Forwarded-Proto", proto)
				} else {
					req.Header.Set("X-Forwarded-Proto", "http")
				}

				// Remove hop-by-hop headers that shouldn't be forwarded,
				// except Connection/Upgrade which are needed for WebSocket.
				if req.Header.Get("Upgrade") == "" {
					req.Header.Del("Connection")
				}

				// Strip platform credentials so they don't reach the guest.
				// This prevents the guest from seeing the user's session token.
				req.Header.Del("Authorization")
				req.Header.Del("X-KW-Display-Claim")
				stripPlatformCookie(req)

				// Strip Accept-Encoding so Go's transport auto-decompresses the
				// response. httputil.ReverseProxy otherwise passes compressed
				// bytes through raw, which breaks the client.
				req.Header.Del("Accept-Encoding")

				// Inject custom request headers from proxy config
				if cfg != nil && cfg.CustomRequestHeaders != nil {
					for k, v := range cfg.CustomRequestHeaders {
						req.Header.Set(k, v)
					}
				}
			},
			ModifyResponse: func(resp *http.Response) error {
				resp.Header.Del("X-KW-Display-Ownership")
				if claim != nil && resp.StatusCode == http.StatusSwitchingProtocols {
					if _, valid := claim.validDeadline(); !valid { return fmt.Errorf("display ownership expired during upgrade") }
					resp.Header.Set("X-KW-Display-Ownership", "1")
				}
				// Rewrite Location headers to keep redirects under the proxy prefix.
				// When preservePathPrefix is true, the app already generates URLs with
				// the proxy prefix, so we only rewrite absolute URLs pointing to the
				// target host (not absolute paths which already have the prefix).
				location := resp.Header.Get("Location")
				if location != "" {
					preservePrefix := cfg != nil && cfg.PreservePathPrefix
					rewritten := rewriteLocation(location, proxyPrefix, rest, target, preservePrefix)
					resp.Header.Set("Location", rewritten)
				}

				// Set a cookie tracking the current proxy prefix. This enables
				// recovery of "escaped" WebSocket requests (e.g. /websockify) that
				// don't carry a Referer header — the frontend reads this cookie to
				// determine which workspace to forward the request to.
				if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
					resp.Header.Add("Set-Cookie", fmt.Sprintf("kw-proxy-prefix=%s; Path=/; SameSite=Strict", proxyPrefix))
				}

				// Rewrite HTML responses for proxy compatibility.
				if cfg != nil && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
					browserHost := r.Header.Get("X-Forwarded-Host")
					if browserHost == "" {
						browserHost = r.Host
					}
					rewriteHTMLResponse(resp, proxyPrefix, browserHost, cfg.InjectBaseTag)
				}

				return nil
			},
			// FlushInterval -1 enables streaming (important for long-running responses)
			FlushInterval: -1,
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprintf(w, `{"error":"Failed to connect to workspace: %s"}`, err.Error())
			},
		}

		proxy.ServeHTTP(w, r)
	})
}

// rewriteLocation rewrites a Location header value to keep it under the proxy prefix.
// When preservePrefix is true, absolute paths are assumed to already contain the proxy
// prefix (generated by the app itself), so they are not rewritten.
func rewriteLocation(location, proxyPrefix, currentPath string, target *url.URL, preservePrefix bool) string {
	// Absolute URL pointing to the target host — always rewrite these
	if strings.HasPrefix(location, "http://"+target.Host) || strings.HasPrefix(location, "https://"+target.Host) {
		parsed, err := url.Parse(location)
		if err != nil {
			return proxyPrefix + "/" + location
		}
		// When the app uses preservePathPrefix, the path in the Location header
		// already includes the proxy prefix, so just use it directly.
		if preservePrefix && strings.HasPrefix(parsed.Path, proxyPrefix) {
			result := parsed.Path
			if parsed.RawQuery != "" {
				result += "?" + parsed.RawQuery
			}
			return result
		}
		result := proxyPrefix + parsed.Path
		if parsed.RawQuery != "" {
			result += "?" + parsed.RawQuery
		}
		return result
	}

	// Absolute path
	if strings.HasPrefix(location, "/") {
		// When preservePathPrefix is true, the app generates paths with the full prefix
		// already included (e.g. /proxy/{ns}/{name}/login), so don't double-prefix.
		if preservePrefix && strings.HasPrefix(location, proxyPrefix) {
			return location
		}
		return proxyPrefix + location
	}

	// Relative path (./foo, ../foo, or bare foo)
	currentDir := proxyPrefix + currentPath
	if idx := strings.LastIndex(currentDir, "/"); idx >= 0 {
		currentDir = currentDir[:idx]
	}

	if strings.HasPrefix(location, "./") {
		return currentDir + "/" + location[2:]
	}
	if strings.HasPrefix(location, "../") {
		parentDir := currentDir
		if idx := strings.LastIndex(parentDir, "/"); idx >= 0 {
			parentDir = parentDir[:idx]
		}
		return parentDir + "/" + location[3:]
	}

	return currentDir + "/" + location
}

// rewriteHTMLResponse reads an HTML response body, rewrites code-server-specific
// configuration values, optionally injects a <base> tag, and updates the response.
// It handles gzip-encoded responses.
func rewriteHTMLResponse(resp *http.Response, proxyPrefix, browserHost string, injectBaseTag bool) {
	// Read the body (possibly gzip-compressed)
	var body []byte
	var err error
	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, gzErr := gzip.NewReader(resp.Body)
		if gzErr != nil {
			return
		}
		body, err = io.ReadAll(reader)
		reader.Close()
	} else {
		body, err = io.ReadAll(resp.Body)
	}
	resp.Body.Close()
	if err != nil {
		return
	}

	html := string(body)

	// Inject <base> tag so relative and absolute URL references resolve through the proxy.
	// This is critical for apps like filebrowser that use absolute paths (e.g. /js/app.js).
	if injectBaseTag && proxyPrefix != "" {
		baseTag := fmt.Sprintf(`<base href="%s/">`, proxyPrefix)
		// Insert after <head> if present
		if idx := strings.Index(html, "<head>"); idx >= 0 {
			html = html[:idx+6] + baseTag + html[idx+6:]
		} else if idx := strings.Index(html, "<HEAD>"); idx >= 0 {
			html = html[:idx+6] + baseTag + html[idx+6:]
		} else if idx := strings.Index(html, "<html"); idx >= 0 {
			// Fallback: insert after the opening <html...> tag
			closeIdx := strings.Index(html[idx:], ">")
			if closeIdx >= 0 {
				insertPos := idx + closeIdx + 1
				html = html[:insertPos] + baseTag + html[insertPos:]
			}
		}
	}

	// Rewrite remoteAuthority: replace "remote:443" or similar with the browser's host.
	// code-server hardcodes this based on its internal detection; we need it to match
	// the browser's actual origin so VS Code connects WebSocket through the proxy.
	html = strings.ReplaceAll(html, `"remoteAuthority":"remote:443"`, fmt.Sprintf(`"remoteAuthority":"%s"`, browserHost))
	html = strings.ReplaceAll(html, `"remoteAuthority":"remote:80"`, fmt.Sprintf(`"remoteAuthority":"%s"`, browserHost))

	// Rewrite serverBasePath: "." should be the proxy prefix so VS Code constructs
	// correct URLs for its resources.
	if proxyPrefix != "" {
		html = strings.ReplaceAll(html, `"serverBasePath":"."`, fmt.Sprintf(`"serverBasePath":"%s"`, proxyPrefix))
	}

	// Rewrite rootEndpoint: "." should be the proxy prefix
	if proxyPrefix != "" {
		html = strings.ReplaceAll(html, `"rootEndpoint":"."`, fmt.Sprintf(`"rootEndpoint":"%s"`, proxyPrefix))
	}

	// Re-encode the response
	var newBody []byte
	if resp.Header.Get("Content-Encoding") == "gzip" {
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		gzWriter.Write([]byte(html))
		gzWriter.Close()
		newBody = buf.Bytes()
	} else {
		newBody = []byte(html)
	}

	resp.Body = io.NopCloser(bytes.NewReader(newBody))
	resp.ContentLength = int64(len(newBody))
	resp.Header.Del("Content-Length")
	resp.Header.Del("Content-Encoding")
}

// ExtractProxyPrefix extracts the proxy prefix (/{namespace}/{name} or /proxy/{namespace}/{name})
// from a Referer URL. Returns empty string if the Referer doesn't contain a proxy path.
func ExtractProxyPrefix(referer, pathPrefix string) string {
	parsed, err := url.Parse(referer)
	if err != nil {
		return ""
	}
	path := parsed.Path

	// Try with path prefix first (e.g. /proxy/{ns}/{name})
	if pathPrefix != "" {
		pfx := strings.TrimSuffix(pathPrefix, "/") + "/"
		if strings.HasPrefix(path, pfx) {
			trimmed := strings.TrimPrefix(path, pfx)
			parts := strings.SplitN(trimmed, "/", 3)
			if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
				return pathPrefix + "/" + parts[0] + "/" + parts[1]
			}
		}
	}

	// Try without prefix (fallback: /{ns}/{name})
	trimmed := strings.TrimPrefix(path, "/")
	parts := strings.SplitN(trimmed, "/", 3)
	if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
		return "/" + parts[0] + "/" + parts[1]
	}

	return ""
}

// stripPlatformCookie removes the platform session cookie from the request headers
// to prevent it from being leaked to guest applications.
func stripPlatformCookie(req *http.Request) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		return
	}

	req.Header.Del("Cookie")
	for _, c := range cookies {
		// kw-session is the platform token; kw-proxy-prefix is used by the frontend
		// for recovery and is also platform-specific.
		if c.Name == "kw-session" || c.Name == "kw-proxy-prefix" {
			continue
		}
		req.AddCookie(c)
	}
}
