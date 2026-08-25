package main

import (
	"net/http"
	"testing"
)

func TestIsTopLevelNavigation(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		// Fetch Metadata (modern browsers)
		{"sec-fetch-dest=document", map[string]string{"Sec-Fetch-Dest": "document"}, true},
		{"sec-fetch-dest=script", map[string]string{"Sec-Fetch-Dest": "script"}, false},
		{"sec-fetch-dest=image", map[string]string{"Sec-Fetch-Dest": "image"}, false},
		{"sec-fetch-dest=empty (XHR/fetch)", map[string]string{"Sec-Fetch-Dest": "empty"}, false},
		{"sec-fetch-dest=websocket", map[string]string{"Sec-Fetch-Dest": "websocket"}, false},

		// Accept header fallback (older browsers / curl)
		{"accept=text/html first", map[string]string{"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}, true},
		{"accept=application/json", map[string]string{"Accept": "application/json"}, false},
		{"accept=*/*", map[string]string{"Accept": "*/*"}, false},
		{"no headers", map[string]string{}, false},

		// Sec-Fetch-Dest takes precedence over Accept
		{"sec=document overrides accept=json", map[string]string{"Sec-Fetch-Dest": "document", "Accept": "application/json"}, true},
		{"sec=empty overrides accept=html", map[string]string{"Sec-Fetch-Dest": "empty", "Accept": "text/html"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := http.NewRequest("GET", "/change-password", nil)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			if got := isTopLevelNavigation(r); got != tt.want {
				t.Errorf("isTopLevelNavigation() = %v, want %v", got, tt.want)
			}
		})
	}
}
