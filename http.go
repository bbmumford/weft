/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
	"net/http"
)

// GetClientIP was removed (audit-r2 H4). The previous implementation
// unconditionally trusted X-Forwarded-For / X-Real-IP and took the FIRST
// XFF entry, which is the spoofable end of the chain. Callers should use
// security_helpers.DefaultClientIP, which gates header trust on a parsed
// trusted-proxy prefix set (Fly 6PN ULA by default) and takes the LAST
// XFF entry — the value the immediately upstream trusted proxy wrote.
//
// No callers of this package's GetClientIP exist in the tree at removal
// time, so no wrapper is kept. If a future caller reaches for it, the
// compile error should send them to security/helpers.DefaultClientIP
// rather than reintroducing the unsafe extractor.

// GetUserAgent extracts the User-Agent header from the HTTP request
func GetUserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}
