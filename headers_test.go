/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serve(cfg SecurityHeadersConfig, method, target, origin string) (*httptest.ResponseRecorder, *bool) {
	called := new(bool)
	h := SecurityHeaders(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(method, target, nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, called
}

func TestCORSAllowsExactAndSubdomainOverHTTPS(t *testing.T) {
	cfg := SecurityHeadersConfig{AllowedOrigins: []string{"example.com"}}
	for _, origin := range []string{"https://example.com", "https://app.example.com", "https://DEEP.app.Example.com"} {
		rec, _ := serve(cfg, http.MethodGet, "/x", origin)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Fatalf("origin %q: ACAO = %q, want it reflected", origin, got)
		}
	}
}

func TestCORSRejectsSuffixLookalikeHost(t *testing.T) {
	// "notexample.com" ends with "example.com" as a STRING but is a different
	// registrable host; a bare HasSuffix check would hand it the grant.
	rec, _ := serve(SecurityHeadersConfig{AllowedOrigins: []string{"example.com"}}, http.MethodGet, "/x", "https://notexample.com")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO = %q for a lookalike host; want no CORS headers", got)
	}
}

func TestCORSRejectsNonHTTPSOrigin(t *testing.T) {
	rec, _ := serve(SecurityHeadersConfig{AllowedOrigins: []string{"example.com"}}, http.MethodGet, "/x", "http://example.com")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO = %q for an http origin; a plaintext page must not read the response", got)
	}
}

func TestCORSVariesOnOriginEvenWhenRefused(t *testing.T) {
	rec, _ := serve(SecurityHeadersConfig{AllowedOrigins: []string{"example.com"}}, http.MethodGet, "/x", "https://other.test")
	if v := rec.Header().Get("Vary"); !strings.Contains(v, "Origin") {
		t.Fatalf("Vary = %q, want it to include Origin — a cache must not replay one origin's grant to another", v)
	}
}

func TestCORSCredentialsOnlyWithReflectedOrigin(t *testing.T) {
	cfg := SecurityHeadersConfig{AllowedOrigins: []string{"example.com"}, AllowCredentials: true}
	rec, _ := serve(cfg, http.MethodGet, "/x", "https://example.com")
	if rec.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatal("wildcard origin emitted alongside credentials")
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("credentials header missing for an allowed origin")
	}
	refused, _ := serve(cfg, http.MethodGet, "/x", "https://other.test")
	if refused.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("credentials header sent for a refused origin")
	}
}

func TestCORSEmptyListsOmitHeadersRatherThanSendBlank(t *testing.T) {
	rec, _ := serve(SecurityHeadersConfig{AllowedOrigins: []string{"example.com"}}, http.MethodGet, "/x", "https://example.com")
	for _, h := range []string{"Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Expose-Headers"} {
		if _, present := rec.Header()[h]; present {
			t.Fatalf("%s present with an empty config list; a blank value denies every method", h)
		}
	}
}

func TestPreflightIsAnsweredWithoutReachingTheRoute(t *testing.T) {
	rec, called := serve(SecurityHeadersConfig{AllowedOrigins: []string{"example.com"}}, http.MethodOptions, "/x", "https://example.com")
	if *called {
		t.Fatal("preflight reached the route")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
}

func TestUnsetHeaderFieldsAreOmitted(t *testing.T) {
	rec, _ := serve(SecurityHeadersConfig{}, http.MethodGet, "/x", "")
	for _, h := range []string{"X-Frame-Options", "Referrer-Policy", "Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options"} {
		if _, present := rec.Header()[h]; present {
			t.Fatalf("%s present on a zero-value config", h)
		}
	}
}

func TestSetHeaderFieldsAreSentVerbatim(t *testing.T) {
	cfg := SecurityHeadersConfig{
		NoSniff:               true,
		FrameOptions:          "DENY",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		ContentSecurityPolicy: "default-src 'self'",
	}
	rec, _ := serve(cfg, http.MethodGet, "/x", "")
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" ||
		rec.Header().Get("X-Frame-Options") != "DENY" ||
		rec.Header().Get("Content-Security-Policy") != "default-src 'self'" {
		t.Fatalf("headers not sent verbatim: %v", rec.Header())
	}
}

func TestCanonicalRedirectPreservesRequestURI(t *testing.T) {
	cfg := SecurityHeadersConfig{CanonicalHost: func(string) string { return "canonical.test" }}
	rec, called := serve(cfg, http.MethodGet, "/a/b?q=1", "")
	if *called {
		t.Fatal("route reached despite a canonical redirect")
	}
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://canonical.test/a/b?q=1" {
		t.Fatalf("Location = %q, want the URI preserved", loc)
	}
}

func TestCanonicalRedirectSkippedWhenAlreadyCanonical(t *testing.T) {
	cfg := SecurityHeadersConfig{CanonicalHost: func(h string) string { return h }}
	_, called := serve(cfg, http.MethodGet, "/x", "")
	if !*called {
		t.Fatal("an already-canonical request was redirected")
	}
}

func TestCanonicalExemptMatchesExactlyAndByPrefix(t *testing.T) {
	cfg := SecurityHeadersConfig{
		CanonicalHost:   func(string) string { return "canonical.test" },
		CanonicalExempt: []string{"/health", "/mesh/"},
	}
	if _, called := serve(cfg, http.MethodGet, "/health", ""); !*called {
		t.Fatal("/health was redirected despite being exempt; a prober that follows it stops watching this instance")
	}
	if _, called := serve(cfg, http.MethodGet, "/mesh/peers", ""); !*called {
		t.Fatal("/mesh/ prefix exemption did not apply")
	}
	if _, called := serve(cfg, http.MethodGet, "/healthcheck-admin", ""); *called {
		t.Fatal("/healthcheck-admin was exempted by the exact entry /health; exact must not match by prefix")
	}
}
