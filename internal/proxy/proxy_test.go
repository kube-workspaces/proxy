package proxy

import (
	"net/http"
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
	// TODO: add tests for rewriteLocation
}
