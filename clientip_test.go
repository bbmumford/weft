package weft

import (
	"net/http/httptest"
	"testing"
)

// The trust model: forwarded headers are honoured only from a trusted-prefix
// peer, X-Forwarded-For takes the LAST hop, and an untrusted peer's header is
// ignored in favour of RemoteAddr.
func TestClientIPFromRequest_TrustModel(t *testing.T) {
	loopback := ParseTrustedPrefixes([]string{"127.0.0.1/32"})

	// Trusted peer + XFF chain → last entry (closest trusted proxy).
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:9999"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 8.8.8.8, 10.0.0.5")
	if got := ClientIPFromRequest(r, loopback, DefaultTrustedHeaderOrder); got != "10.0.0.5" {
		t.Errorf("trusted XFF = %q, want last hop 10.0.0.5", got)
	}

	// Trusted peer + higher-precedence header wins over XFF.
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "127.0.0.1:9999"
	r2.Header.Set("X-Real-IP", "203.0.113.1")
	r2.Header.Set("X-Forwarded-For", "10.0.0.5")
	if got := ClientIPFromRequest(r2, loopback, DefaultTrustedHeaderOrder); got != "203.0.113.1" {
		t.Errorf("precedence = %q, want X-Real-IP 203.0.113.1", got)
	}

	// UNtrusted peer → forged header ignored, RemoteAddr wins (anti-spoof).
	r3 := httptest.NewRequest("GET", "/", nil)
	r3.RemoteAddr = "198.51.100.9:5555"
	r3.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := ClientIPFromRequest(r3, loopback, DefaultTrustedHeaderOrder); got != "198.51.100.9" {
		t.Errorf("untrusted peer = %q, want RemoteAddr 198.51.100.9 (header ignored)", got)
	}

	// nil header order → RemoteAddr only, even from a trusted peer.
	r4 := httptest.NewRequest("GET", "/", nil)
	r4.RemoteAddr = "127.0.0.1:1"
	r4.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := ClientIPFromRequest(r4, loopback, nil); got != "127.0.0.1" {
		t.Errorf("nil order = %q, want RemoteAddr 127.0.0.1", got)
	}

	if got := ClientIPFromRequest(nil, loopback, DefaultTrustedHeaderOrder); got != "" {
		t.Errorf("nil request = %q, want empty", got)
	}
}
