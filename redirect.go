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
//     It must name no host to a browser (relativePathStaysOnSite): a browser reads '\' as '/' and
//     drops tabs and newlines, so "/\evil.example" and "/<TAB>/evil.example" leave the site and are refused.
//   - Absolute must be https, fragment stripped.
//   - Host MUST exactly match one of allowHosts (case-insensitive). No wildcard, no subdomain allowance.
//   - Returns cleaned URL string and true on success.
func ValidateRedirect(raw string, allowHosts []string, allowRelative bool) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if allowRelative && strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") { // prevent scheme-relative
		if !relativePathStaysOnSite(raw) {
			return "", false
		}
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

// relativePathStaysOnSite reports whether p, a target beginning with a single '/', is a path a
// browser resolves on the current site. A browser treats '\' as '/' and removes tab, newline and
// other control characters before resolving, so a path holding either can become "//host" and
// leave the site; and p must parse as a URL with no scheme, host or user.
func relativePathStaysOnSite(p string) bool {
	for i := 0; i < len(p); i++ {
		if c := p[i]; c == '\\' || c < 0x20 || c == 0x7f {
			return false
		}
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == "" && u.User == nil
}
