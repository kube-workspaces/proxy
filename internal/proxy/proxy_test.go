package proxy

import (
	"net/http"
	"net/url"
	"testing"
)

func TestStripPlatformCookie(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	req.AddCookie(&http.Cookie{Name: "kw-session", Value: "secret"})
	req.AddCookie(&http.Cookie{Name: "kw-proxy-prefix", Value: "prefix"})
	req.AddCookie(&http.Cookie{Name: "other", Value: "value"})

	stripPlatformCookie(req)

	cookies := req.Cookies()
	if len(cookies) != 1 {
		t.Errorf("got %d cookies; want 1", len(cookies))
	}
	if cookies[0].Name != "other" {
		t.Errorf("got cookie %q; want \"other\"", cookies[0].Name)
	}
}

func TestRewriteLocation(t *testing.T) {
	target, _ := url.Parse("http://work.example.svc.cluster.local:80")
	proxyPrefix := "/proxy/ns/name"

	tests := []struct {
		name           string
		location       string
		currentPath    string
		preservePrefix bool
		want           string
	}{
		{"absolute URL to backend host", "http://work.example.svc.cluster.local:80/login", "/", false, "/proxy/ns/name/login"},
		{"absolute URL to backend host with query", "http://work.example.svc.cluster.local:80/login?next=/", "/", false, "/proxy/ns/name/login?next=/"},
		{"absolute URL to external host stays absolute", "https://auth.example.com/callback", "/", false, "/proxy/ns/name/https://auth.example.com/callback"},
		{"absolute path", "/settings", "/", false, "/proxy/ns/name/settings"},
		{"relative dot path", "./css/app.css", "/", false, "/proxy/ns/name/css/app.css"},
		{"relative parent path escapes one level", "../other", "/page", false, "/proxy/ns/other"},
		{"bare relative path", "app.js", "/", false, "/proxy/ns/name/app.js"},

		// preservePathPrefix: apps generate prefixed URLs themselves.
		{"preserve: absolute path already prefixed is returned", "/proxy/ns/name/login", "/", true, "/proxy/ns/name/login"},
		{"preserve: absolute path without prefix is prefixed", "/login", "/", true, "/proxy/ns/name/login"},
		{"preserve: backend URL with prefixed path is stripped of host", "http://work.example.svc.cluster.local:80/proxy/ns/name/login", "/", true, "/proxy/ns/name/login"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rewriteLocation(tt.location, proxyPrefix, tt.currentPath, target, tt.preservePrefix); got != tt.want {
				t.Errorf("rewriteLocation(%q) = %q, want %q", tt.location, got, tt.want)
			}
		})
	}
}
