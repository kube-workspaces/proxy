package proxy

import "testing"

func TestResolveScheme(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"nil config defaults to http", nil, "http"},
		{"empty config defaults to http", &Config{}, "http"},
		{"explicit http", &Config{Scheme: "http"}, "http"},
		{"explicit https", &Config{Scheme: "https"}, "https"},
		{"scheme is case insensitive", &Config{Scheme: "HTTPS"}, "https"},
		{"unrecognised scheme falls back to http", &Config{Scheme: "ftp"}, "http"},

		// Backwards compatibility: the deprecated combined flag implied HTTPS.
		{"deprecated tlsInsecure implies https", &Config{TLSInsecure: true}, "https"},
		{"explicit http wins over deprecated flag", &Config{Scheme: "http", TLSInsecure: true}, "http"},
		{"explicit https with deprecated flag", &Config{Scheme: "https", TLSInsecure: true}, "https"},

		// TLSSkipVerify alone must not change the scheme.
		{"tlsSkipVerify alone stays http", &Config{TLSSkipVerify: true}, "http"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.ResolveScheme(); got != tt.want {
				t.Errorf("ResolveScheme() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveTLSSkipVerify(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{"nil config verifies", nil, false},
		{"empty config verifies", &Config{}, false},
		{"explicit skip", &Config{TLSSkipVerify: true}, true},
		{"deprecated tlsInsecure implies skip", &Config{TLSInsecure: true}, true},
		{"https without skip verifies", &Config{Scheme: "https"}, false},
		{"https with explicit skip", &Config{Scheme: "https", TLSSkipVerify: true}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.ResolveTLSSkipVerify(); got != tt.want {
				t.Errorf("ResolveTLSSkipVerify() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The deprecated flag conflated scheme selection with certificate verification.
// This documents that the new fields can express what the old one could not:
// HTTPS with proper certificate validation.
func TestSecureHTTPSIsExpressible(t *testing.T) {
	cfg := &Config{Scheme: "https"}
	if got := cfg.ResolveScheme(); got != "https" {
		t.Errorf("scheme = %q, want https", got)
	}
	if cfg.ResolveTLSSkipVerify() {
		t.Error("TLSSkipVerify should be false: HTTPS with a valid CA must verify certs")
	}
}
