// Package main implements the kube-workspaces-proxy standalone binary.
// It serves as a reverse proxy to workspace pods running in-cluster,
// with session-based authentication and namespace access control.
//
// All proxy traffic is served under a single path prefix (/proxy by default):
//
//	/proxy/{namespace}/{name}/...
//
// Authentication:
//   - When AuthConfig.spec.enabled=true, validates kw-session cookie (HMAC-SHA256)
//   - Checks user has access to the target namespace via User CR
//   - Admins (by role or adminEmails) bypass namespace checks
//   - When auth is disabled, all requests pass through (backward compatible)
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kube-workspaces/proxy/internal/auth"
	"github.com/kube-workspaces/proxy/internal/k8s"
	"github.com/kube-workspaces/proxy/internal/proxy"
)

// Build information, injected at link time:
//
//	go build -ldflags "-X main.version=v1.2.3 -X main.commit=abc1234 -X main.buildDate=..."
//
// runtime/debug.ReadBuildInfo cannot substitute for this: it reports "(devel)"
// for a build that is not driven by `go install module@version`, which is the
// case for the container build.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// versionString renders the build information for logs and the /version endpoint.
func versionString() string {
	return fmt.Sprintf("%s (commit %s, built %s, %s/%s, %s)",
		version, commit, buildDate, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func main() {
	port := flag.Int("port", 8080, "HTTP listen port")
	showVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(versionString())
		return
	}

	// Override port from env
	if p := os.Getenv("HTTP_PORT"); p != "" {
		fmt.Sscanf(p, "%d", port)
	}

	// Configuration from environment
	allowedOrigins := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")
	pathPrefix := os.Getenv("PATH_PREFIX") // e.g. "/proxy"
	if pathPrefix == "" {
		pathPrefix = "/proxy"
	}

	log.Printf("Starting kube-workspaces-proxy %s", versionString())
	log.Printf("  listening on :%d", *port)
	log.Printf("  PATH_PREFIX=%q", pathPrefix)
	log.Printf("  ALLOWED_ORIGINS=%v", allowedOrigins)

	// Initialize Kubernetes client
	client, err := k8s.NewClient()
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}
	log.Println("Kubernetes client initialized")

	// Initialize auth config provider
	authProvider := auth.NewConfigProvider(client.DynamicClient())
	log.Println("Auth provider initialized")

	// Build lookup functions for the proxy handler
	workspaceImageLookup := func(namespace, name string) string {
		image, err := client.GetWorkspaceImage(context.Background(), namespace, name)
		if err != nil {
			log.Printf("Warning: failed to get workspace image for %s/%s: %v", namespace, name, err)
			return ""
		}
		return image
	}

	workspaceInfoLookup := func(namespace, name string) *proxy.WorkspaceInfo {
		info := client.GetWorkspaceInfo(context.Background(), namespace, name)
		if info == nil {
			return nil
		}
		return &proxy.WorkspaceInfo{
			Image:              info.Image,
			PreservePathPrefix: info.PreservePathPrefix,
		}
	}

	configLookup := func(imageRef string) *proxy.Config {
		cfg := client.GetImageProxyConfig(context.Background(), imageRef)
		if cfg == nil {
			return nil
		}
		return &proxy.Config{
			NeedsNoOpSW:              cfg.NeedsNoOpSW,
			WebSocketPaths:           cfg.WebSocketPaths,
			RewriteHostAbsolutePaths: cfg.RewriteHostAbsolutePaths,
			CustomRequestHeaders:     cfg.CustomRequestHeaders,
			InjectBaseTag:            cfg.InjectBaseTag,
			Scheme:                   cfg.Scheme,
			TLSSkipVerify:            cfg.TLSSkipVerify,
			TLSInsecure:              cfg.TLSInsecure,
			PreservePathPrefix:       cfg.PreservePathPrefix,
			AudioPort:                cfg.AudioPort,
		}
	}

	// Create proxy handler for shared-host mode: /proxy/{namespace}/{name}/...
	proxyHandler := proxy.Handler(&proxy.HandlerOptions{
		ConfigLookup:         configLookup,
		WorkspaceImageLookup: workspaceImageLookup,
		WorkspaceInfoLookup:  workspaceInfoLookup,
		ExternalHost:         "", // Not needed — requests come through the main host
		PathPrefix:           pathPrefix,
	})

	// Root handler with routing and health check
	rootHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health check
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// The "status" field is load-bearing: the deployment smoke tests and
			// the container probes both match on it. Version is additive.
			fmt.Fprintf(w, `{"status":"ok","version":%q}`, version)
			return
		}

		// Build information, so a running pod can be identified without
		// inspecting the image digest.
		if r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w,
				`{"version":%q,"commit":%q,"buildDate":%q,"go":%q,"platform":"%s/%s"}`,
				version, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return
		}

		// No-op ServiceWorker for proxied apps that try to register one
		if r.URL.Path == "/sw.js" {
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Service-Worker-Allowed", "/")
			w.Write([]byte("// no-op service worker for proxied workspaces\nself.addEventListener('install', () => self.skipWaiting());\nself.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));\n"))
			return
		}

		// Route to proxy handler if path matches the prefix
		if strings.HasPrefix(r.URL.Path, pathPrefix+"/") {
			proxyHandler.ServeHTTP(w, r)
			return
		}

		// Escaped request recovery via Referer header
		referer := r.Header.Get("Referer")
		if referer != "" {
			proxyPrefix := proxy.ExtractProxyPrefix(referer, pathPrefix)
			if proxyPrefix != "" {
				// Validate the path segments look like K8s names before rewriting
				trimmed := strings.TrimPrefix(proxyPrefix, pathPrefix+"/")
				parts := strings.SplitN(trimmed, "/", 2)
				if len(parts) >= 2 && isValidK8sName(parts[0]) && isValidK8sName(parts[1]) {
					r.URL.Path = proxyPrefix + r.URL.Path
					proxyHandler.ServeHTTP(w, r)
					return
				}
			}
		}

		// Root path — simple info response
		if r.URL.Path == "/" || r.URL.Path == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"service":"kube-workspaces-proxy","status":"ok"}`))
			return
		}

		http.NotFound(w, r)
	})

	// Wrap with auth middleware, then CORS, then request logging
	authedHandler := auth.Middleware(authProvider, pathPrefix)(rootHandler)
	corsHandler := corsMiddleware(authedHandler, allowedOrigins)
	handler := requestLoggingMiddleware(corsHandler)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      handler,
		ReadTimeout:  0, // No timeout for WebSocket/streaming
		WriteTimeout: 0, // No timeout for WebSocket/streaming
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()

	log.Printf("Listening on :%d", *port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
	log.Println("Server stopped")
}

// corsMiddleware adds CORS headers for allowed origins.
func corsMiddleware(next http.Handler, allowedOrigins []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			for _, o := range allowedOrigins {
				if strings.TrimSpace(o) == origin {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					break
				}
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isValidK8sName checks if a string looks like a valid Kubernetes resource name.
// Kubernetes names must be lowercase, alphanumeric, with hyphens allowed (not at start/end).
// This filters out bot probes like ".git", ".ssh", "wp-admin", "actuator", etc.
func isValidK8sName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if !isLowerAlphaNum(name[0]) {
		return false
	}
	if !isLowerAlphaNum(name[len(name)-1]) {
		return false
	}
	for i := 1; i < len(name)-1; i++ {
		c := name[i]
		if !isLowerAlphaNum(c) && c != '-' {
			return false
		}
	}
	return true
}

func isLowerAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

// requestLoggingMiddleware logs each incoming HTTP request with method, path, status, and duration.
func requestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip health checks to avoid noise
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		duration := time.Since(start)

		upgrade := ""
		if r.Header.Get("Upgrade") != "" {
			upgrade = fmt.Sprintf(" [upgrade=%s]", r.Header.Get("Upgrade"))
		}

		log.Printf("%s %s → %d (%s)%s", r.Method, r.URL.Path, rw.status, duration.Round(time.Millisecond), upgrade)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}
