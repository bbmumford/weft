package weft

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPUserAgentCarriers_RoundTrip(t *testing.T) {
	ctx := WithUserAgent(WithClientIP(context.Background(), "203.0.113.7"), "curl/8")
	if got := ExtractClientIP(ctx); got != "203.0.113.7" {
		t.Errorf("client ip = %q, want 203.0.113.7", got)
	}
	if got := ExtractUserAgent(ctx); got != "curl/8" {
		t.Errorf("user agent = %q, want curl/8", got)
	}
	if got := ExtractClientIP(context.Background()); got != "" {
		t.Errorf("absent client ip = %q, want empty", got)
	}
}

func TestClientIPFromRequest_XFFThenRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:5555"
	r.Header.Set("X-Forwarded-For", "198.51.100.9, 10.0.0.1")
	if got := ClientIPFromRequest(r); got != "198.51.100.9" {
		t.Errorf("XFF leftmost = %q, want 198.51.100.9", got)
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "192.0.2.4:443"
	if got := ClientIPFromRequest(r2); got != "192.0.2.4" {
		t.Errorf("RemoteAddr host = %q, want 192.0.2.4", got)
	}
	if got := ClientIPFromRequest(nil); got != "" {
		t.Errorf("nil request = %q, want empty", got)
	}
}

func TestStampRequestMetadata_PopulatesCtx(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.10:1234"
	r.Header.Set("User-Agent", "agent/1")
	var gotIP, gotUA string
	h := StampRequestMetadata(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		gotIP = ExtractClientIP(req.Context())
		gotUA = ExtractUserAgent(req.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if gotIP != "192.0.2.10" || gotUA != "agent/1" {
		t.Fatalf("stamped ip=%q ua=%q, want 192.0.2.10 / agent/1", gotIP, gotUA)
	}
}
