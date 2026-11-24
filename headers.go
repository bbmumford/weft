/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// SecurityHeadersConfig parameterises SecurityHeaders on values and one seam.
// Every policy it applies is supplied by the consumer: this package holds no
// domain, no asset host, and no allow-list of its own, so nothing it emits
// changes when a consumer's hosting does.
type SecurityHeadersConfig struct {
	// AllowedOrigins lists the hosts whose cross-origin requests are answered,
	// matched case-insensitively against the Origin header's host, either exactly
	// or as a subdomain of the entry. Only https origins are considered.
	//
	// An origin outside this list gets NO CORS headers rather than a rejection:
	// the absence is what the browser enforces, and an explicit denial would tell
	// a caller which origins exist.
	AllowedOrigins []string

	// AllowCredentials sets Access-Control-Allow-Credentials. It is only ever
	// paired with a single reflected origin — the wildcard form is never emitted,
	// because a browser that accepted both would send cookies to any site.
	AllowCredentials bool

	// AllowedMethods, AllowedHeaders and ExposedHeaders are sent verbatim when an
	// origin is allowed. Empty ones are omitted rather than sent blank, since a
	// blank Access-Control-Allow-Methods denies every method instead of defaulting.
	AllowedMethods []string
	AllowedHeaders []string
	ExposedHeaders []string

	// PathCORS gives requests under particular paths their own cross-origin
	// policy. The first entry whose Path matches the request decides its CORS
	// headers alone: AllowedOrigins, AllowCredentials and the lists above are not
	// consulted for it, so a host admitted site-wide by subdomain is not admitted
	// on a path that names its origins exactly. A path no entry matches is
	// answered from AllowedOrigins.
	PathCORS []PathCORS

	// ContentSecurityPolicy is sent verbatim. This package does not compose one:
	// a policy names the consumer's own script, style and asset hosts, and a
	// composed default would either block assets the consumer serves or admit
	// hosts the consumer never vetted. Empty omits the header.
	//
	// A policy carrying frame-ancestors makes FrameOptions dead weight — a browser
	// that understands frame-ancestors ignores X-Frame-Options entirely — so the
	// two must agree, and where they disagree the CSP is what takes effect.
	ContentSecurityPolicy string

	// FrameOptions, ReferrerPolicy and StrictTransportSecurity are sent verbatim
	// when non-empty and omitted when empty. They are values rather than flags so
	// a consumer can send a directive this package has never heard of.
	FrameOptions            string
	ReferrerPolicy          string
	StrictTransportSecurity string

	// NoSniff sends X-Content-Type-Options: nosniff.
	NoSniff bool

	// CanonicalHost maps a request's host to the host it belongs on, returning ""
	// or the same host when the request is already canonical. It is a SEAM: the
	// mapping lives in whatever the consumer uses to know its own deployment, so
	// this package needs no registry and no global of its own to consult.
	//
	// The redirect it produces is https and permanent, and carries the request URI
	// unchanged.
	CanonicalHost func(host string) string

	// CanonicalExempt lists paths the canonical-host redirect skips. An entry
	// ending in "/" matches by prefix; any other entry matches exactly, so
	// "/health" does not also exempt "/healthcheck-admin".
	//
	// Liveness and mesh paths belong here: a prober or a peer that follows a
	// redirect to the canonical host stops reporting on the instance it dialled.
	CanonicalExempt []string
}

// PathCORS is the cross-origin policy of one path.
//
// A path policy never sends Access-Control-Allow-Credentials: a caller of such a
// path presents its credential in a request header it names in AllowedHeaders,
// so the browser needs no cookie grant, and an origin that is admitted exactly
// gains nothing a cookie would add.
type PathCORS struct {
	// Path is matched as CanonicalExempt entries are: an entry ending in "/" by
	// prefix, any other exactly.
	Path string

	// Origins lists the exact origins admitted, each an https scheme and a host
	// with an optional port ("https://docs.example.com"), compared with the
	// request's Origin header as a whole and case-insensitively. There is no
	// subdomain match and no wildcard; an entry ParseCORSOrigin refuses never
	// admits anything.
	Origins []string

	// AllowedMethods, AllowedHeaders and ExposedHeaders are sent verbatim when an
	// origin is admitted, and omitted when empty, as the site-wide lists are.
	AllowedMethods []string
	AllowedHeaders []string
	ExposedHeaders []string
}

// ErrCORSOrigin refuses an origin ParseCORSOrigin cannot use as an exact origin.
var ErrCORSOrigin = errors.New("weft: a CORS origin is an https scheme and a host with an optional port, and nothing else")

// ParseCORSOrigin returns origin in the form PathCORS compares ("https://" and the
// lowercased host and port), or ErrCORSOrigin for anything else: a wildcard, a
// scheme other than https, user info, a path, a query or a fragment. A consumer
// that reads PathCORS origins from configuration checks each with it at load, so
// a mistyped origin stops the load rather than silently admitting nothing.
func ParseCORSOrigin(origin string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || strings.Contains(u.Host, "*") {
		return "", ErrCORSOrigin
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// SecurityHeaders applies response security headers, answers CORS preflight, and
// redirects a request that arrived on a non-canonical host.
//
// Order matters: the canonical redirect runs first, so a request that is about to
// be sent elsewhere does not also receive the headers for the host it never
// reached.
func SecurityHeaders(cfg SecurityHeadersConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.CanonicalHost != nil && !exemptPath(cfg.CanonicalExempt, r.URL.Path) {
				host := r.Host
				if i := strings.IndexByte(host, ':'); i >= 0 {
					host = host[:i]
				}
				if canonical := cfg.CanonicalHost(host); canonical != "" && canonical != host {
					http.Redirect(w, r, "https://"+canonical+r.URL.RequestURI(), http.StatusMovedPermanently)
					return
				}
			}

			// Vary on Origin whenever an origin could change the response, including
			// when this one is refused: a shared cache that stored the allowed
			// variant would otherwise replay one origin's grant to every other.
			if origin := r.Header.Get("Origin"); origin != "" {
				w.Header().Add("Vary", "Origin")
				if p, ok := pathCORS(cfg.PathCORS, r.URL.Path); ok {
					if exactOriginAllowed(p.Origins, origin) {
						h := w.Header()
						h.Set("Access-Control-Allow-Origin", origin)
						setIfAny(h, "Access-Control-Allow-Methods", p.AllowedMethods)
						setIfAny(h, "Access-Control-Allow-Headers", p.AllowedHeaders)
						setIfAny(h, "Access-Control-Expose-Headers", p.ExposedHeaders)
					}
				} else if originAllowed(cfg.AllowedOrigins, origin) {
					h := w.Header()
					h.Set("Access-Control-Allow-Origin", origin)
					if cfg.AllowCredentials {
						h.Set("Access-Control-Allow-Credentials", "true")
					}
					setIfAny(h, "Access-Control-Allow-Methods", cfg.AllowedMethods)
					setIfAny(h, "Access-Control-Allow-Headers", cfg.AllowedHeaders)
					setIfAny(h, "Access-Control-Expose-Headers", cfg.ExposedHeaders)
				}
			}

			h := w.Header()
			if cfg.NoSniff {
				h.Set("X-Content-Type-Options", "nosniff")
			}
			setIfSet(h, "X-Frame-Options", cfg.FrameOptions)
			setIfSet(h, "Referrer-Policy", cfg.ReferrerPolicy)
			setIfSet(h, "Strict-Transport-Security", cfg.StrictTransportSecurity)
			setIfSet(h, "Content-Security-Policy", cfg.ContentSecurityPolicy)

			// A preflight is answered here and never reaches the route. When the
			// origin was refused above it is answered WITHOUT CORS headers, which is
			// what the browser reads as a denial — replying with an error status
			// instead would report the same refusal as a server fault.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// originAllowed reports whether an Origin header names an https host that is, or
// is a subdomain of, one of the allowed entries.
//
// The scheme check is not decoration: an http origin matching by host alone
// would let a network attacker on a plaintext page read the response.
func originAllowed(allowed []string, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// pathCORS returns the first policy whose Path matches path, as exemptPath
// matches an entry.
func pathCORS(policies []PathCORS, path string) (PathCORS, bool) {
	for _, p := range policies {
		if p.Path != "" && exemptPath([]string{p.Path}, path) {
			return p, true
		}
	}
	return PathCORS{}, false
}

// exactOriginAllowed reports whether an Origin header is, as a whole, one of the
// allowed exact origins once both are in ParseCORSOrigin's form. An allowed entry
// ParseCORSOrigin refuses matches nothing.
func exactOriginAllowed(allowed []string, origin string) bool {
	o, err := ParseCORSOrigin(origin)
	if err != nil {
		return false
	}
	for _, a := range allowed {
		if want, err := ParseCORSOrigin(a); err == nil && want == o {
			return true
		}
	}
	return false
}

// exemptPath reports whether path matches an entry: by prefix when the entry
// ends in "/", exactly otherwise.
func exemptPath(exempt []string, path string) bool {
	for _, e := range exempt {
		if e == "" {
			continue
		}
		if strings.HasSuffix(e, "/") {
			if strings.HasPrefix(path, e) {
				return true
			}
			continue
		}
		if path == e {
			return true
		}
	}
	return false
}

// setIfSet writes a header only when the value is non-empty, so an unset config
// field omits the header rather than sending it blank.
func setIfSet(h http.Header, name, value string) {
	if value != "" {
		h.Set(name, value)
	}
}

// setIfAny writes a comma-joined header only when the list has entries.
func setIfAny(h http.Header, name string, values []string) {
	if len(values) > 0 {
		h.Set(name, strings.Join(values, ", "))
	}
}
