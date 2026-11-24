/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// pathCORSConfig admits example.com and its subdomains site-wide with
// credentials, and gives /api/ its own exact list of one origin.
func pathCORSConfig() SecurityHeadersConfig {
	return SecurityHeadersConfig{
		AllowedOrigins:   []string{"example.com"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET"},
		PathCORS: []PathCORS{{
			Path:           "/api/",
			Origins:        []string{"https://Docs.Example.com"},
			AllowedMethods: []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders: []string{"x-api-key", "authorization", "content-type", "anthropic-version"},
		}},
	}
}

func TestPathCORSAnswersTheListedOriginsFullPreflight(t *testing.T) {
	rec, called := serve(pathCORSConfig(), http.MethodOptions, "/api/messages", "https://docs.example.com")
	h := rec.Header()
	if rec.Code != http.StatusNoContent || *called {
		t.Fatalf("preflight answered %d, reached the route %v; want 204 answered here", rec.Code, *called)
	}
	for name, want := range map[string]string{
		"Access-Control-Allow-Origin":  "https://docs.example.com",
		"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
		"Access-Control-Allow-Headers": "x-api-key, authorization, content-type, anthropic-version",
	} {
		if got := h.Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if got := h.Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("a path policy sent Access-Control-Allow-Credentials %q", got)
	}
	if v := h.Get("Vary"); !strings.Contains(v, "Origin") {
		t.Fatalf("Vary = %q, want Origin", v)
	}
	rec, called = serve(pathCORSConfig(), http.MethodPost, "/api/messages", "https://docs.example.com")
	if !*called || rec.Header().Get("Access-Control-Allow-Origin") != "https://docs.example.com" {
		t.Fatalf("the request after the preflight: reached %v, ACAO %q", *called, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}

// Under a path policy another subdomain the site-wide list admits, a foreign
// origin and the listed host over http get no CORS header at all, on the
// preflight and on the request; the same subdomain still gets the site-wide grant
// on a path no policy names.
func TestPathCORSRefusesEveryOriginItDoesNotList(t *testing.T) {
	for _, origin := range []string{"https://app.example.com", "https://example.com", "https://docs.example.com.evil.test",
		"https://foreign.test", "http://docs.example.com", "null"} {
		for _, method := range []string{http.MethodOptions, http.MethodPost} {
			rec, _ := serve(pathCORSConfig(), method, "/api/messages", origin)
			for name := range rec.Header() {
				if strings.HasPrefix(name, "Access-Control-") {
					t.Fatalf("%s %s from %q: sent %s %q", method, "/api/messages", origin, name, rec.Header().Get(name))
				}
			}
		}
	}
	rec, _ := serve(pathCORSConfig(), http.MethodGet, "/other", "https://app.example.com")
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" || rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("POSITIVE CONTROL: a path no policy names lost the site-wide grant: %v", rec.Header())
	}
	rec, _ = serve(pathCORSConfig(), http.MethodGet, "/apix", "https://app.example.com")
	if rec.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatalf("/apix matched the /api/ policy: %v", rec.Header())
	}
}

func TestParseCORSOriginTakesOnlyAnExactHTTPSOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://docs.example.com":      "https://docs.example.com",
		" https://Docs.Example.COM ":    "https://docs.example.com",
		"https://docs.example.com:8443": "https://docs.example.com:8443",
	} {
		got, err := ParseCORSOrigin(in)
		if err != nil || got != want {
			t.Fatalf("ParseCORSOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"*", "https://*.example.com", "http://docs.example.com", "docs.example.com",
		"https://docs.example.com/", "https://docs.example.com/v1", "https://u@docs.example.com", "https://docs.example.com?x=1",
		"https://docs.example.com#f", "https://", ""} {
		if got, err := ParseCORSOrigin(in); !errors.Is(err, ErrCORSOrigin) {
			t.Fatalf("ParseCORSOrigin(%q) = %q, %v; want ErrCORSOrigin", in, got, err)
		}
	}
	cfg := pathCORSConfig()
	cfg.PathCORS[0].Origins = []string{"https://docs.example.com/"}
	if rec, _ := serve(cfg, http.MethodOptions, "/api/messages", "https://docs.example.com"); rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("an entry ParseCORSOrigin refuses admitted its host")
	}
}
