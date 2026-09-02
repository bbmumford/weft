package weft

import (
	"context"
	"net/http"
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

// StampRequestMetadata is the ingress middleware that stamps the client IP and
// user agent onto the request context, so downstream handlers read them via
// ExtractClientIP/ExtractUserAgent without touching the request. The client IP
// uses the trusted-proxy-aware DefaultClientIP (see clientip.go) so a spoofed
// forwarded header from an untrusted peer cannot set the stamped IP.
func StampRequestMetadata(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithClientIP(r.Context(), DefaultClientIP(r))
		ctx = WithUserAgent(ctx, GetUserAgent(r))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
