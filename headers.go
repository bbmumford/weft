/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
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
				if originAllowed(cfg.AllowedOrigins, origin) {
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
