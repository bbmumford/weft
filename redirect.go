/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
	"net/url"
	"strings"
)

// ValidateRedirect validates an untrusted redirect target.
// STRICT MODE (host exact match only)
// Rules:
//   - Empty => return empty, false.
//   - Relative path starting with '/' allowed when allowRelative true; returned unchanged (fragment stripped).
//   - Absolute must be https, fragment stripped.
//   - Host MUST exactly match one of allowHosts (case-insensitive). No wildcard, no subdomain allowance.
//   - Returns cleaned URL string and true on success.
func ValidateRedirect(raw string, allowHosts []string, allowRelative bool) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if allowRelative && strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") { // prevent scheme-relative
		// strip fragment if any
		if i := strings.Index(raw, "#"); i >= 0 {
			raw = raw[:i]
		}
		return raw, true
	}
	// Parse absolute
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	if strings.ToLower(u.Scheme) != "https" { // enforce https
		return "", false
	}
	// strip fragment
	u.Fragment = ""
	host := strings.ToLower(u.Host)
	// Exact host match only
	for _, ah := range allowHosts {
		ah = strings.ToLower(strings.TrimSpace(ah))
		if ah == "" {
			continue
		}
		if host == ah {
			return u.String(), true
		}
	}
	return "", false
}
