package weft

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// Request-metadata context carriers. An ingress middleware stamps the caller's
// client IP and user agent onto the request context once; handlers read them via
// Extract* without re-parsing the request. weft interprets neither value — they
// are opaque carriers (audit/rate-limit context), never authority or scope.
// A consumer swaps its With*/Extract* pair to these together per endpoint so the
// stamp and the read share weft's key.

const (
	clientIPKey  = contextKey("client_ip")
	userAgentKey = contextKey("user_agent")
)

// WithClientIP stores the caller's client IP on ctx; call from ingress middleware.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey, ip)
}

// ExtractClientIP reads the client IP stamped by WithClientIP, or "" when absent.
func ExtractClientIP(ctx context.Context) string {
	if ip, ok := ctx.Value(clientIPKey).(string); ok {
		return ip
	}
	return ""
}

// WithUserAgent stores the caller's user agent on ctx.
func WithUserAgent(ctx context.Context, ua string) context.Context {
	return context.WithValue(ctx, userAgentKey, ua)
}

// ExtractUserAgent reads the user agent stamped by WithUserAgent, or "" when absent.
func ExtractUserAgent(ctx context.Context) string {
	if ua, ok := ctx.Value(userAgentKey).(string); ok {
		return ua
	}
	return ""
}

// ClientIPFromRequest extracts the caller's client IP from a request: the
// leftmost X-Forwarded-For hop (the original client behind proxies) when present,
// else the host of RemoteAddr. Returns "" for a nil request.
func ClientIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// StampRequestMetadata is the ingress middleware that stamps the client IP and
// user agent onto the request context, so downstream handlers read them via
// ExtractClientIP/ExtractUserAgent without touching the request.
func StampRequestMetadata(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithClientIP(r.Context(), ClientIPFromRequest(r))
		ctx = WithUserAgent(ctx, GetUserAgent(r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
