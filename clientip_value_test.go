package weft

import (
	"net/http/httptest"
	"testing"
)

// A trusted edge's forwarded header is taken only when its value is an IP
// address; any other text is no address, and the peer address is the caller's.
// An address is returned in canonical form, an IPv4-mapped one as IPv4, so one
// caller has one key.
func TestAForwardedValueThatIsNoAddressIsNotTheCallersAddress(t *testing.T) {
	const edge = "127.0.0.1"
	for header, value := range map[string]string{
		"Fly-Client-IP":   "not-an-address",
		"X-Real-IP":       "198.51.100.7; DROP",
		"X-Forwarded-For": "198.51.100.7, 203.0.113.9 extra",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = edge + ":5555"
		r.Header.Set(header, value)
		if got := DefaultClientIP(r); got != edge {
			t.Errorf("%s=%q read as %q, want the peer %q", header, value, got, edge)
		}
	}
	for value, want := range map[string]string{
		" 198.51.100.7 ":      "198.51.100.7",
		"::ffff:198.51.100.7": "198.51.100.7",
		"2001:DB8::1":         "2001:db8::1",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = edge + ":5555"
		r.Header.Set("Fly-Client-IP", value)
		if got := DefaultClientIP(r); got != want {
			t.Errorf("Fly-Client-IP=%q read as %q, want %q", value, got, want)
		}
	}
}
