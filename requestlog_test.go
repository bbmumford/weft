/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func observeOne(t *testing.T, cfg RequestLogConfig, path string, h http.HandlerFunc) (*RequestRecord, bool) {
	t.Helper()
	var got RequestRecord
	seen := false
	inner := cfg.Observe
	cfg.Observe = func(r *http.Request, rec RequestRecord) {
		got, seen = rec, true
		if inner != nil {
			inner(r, rec)
		}
	}
	RequestLogging(cfg)(h).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil))
	return &got, seen
}

func TestRequestLoggingReportsStatusAndBytes(t *testing.T) {
	rec, seen := observeOne(t, RequestLogConfig{Observe: func(*http.Request, RequestRecord) {}}, "/x",
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte("12345"))
		})
	if !seen {
		t.Fatal("observer never ran")
	}
	if rec.Status != http.StatusTeapot || rec.Bytes != 5 {
		t.Fatalf("record = status %d bytes %d, want 418/5", rec.Status, rec.Bytes)
	}
	if rec.Method != http.MethodGet || rec.Path != "/x" {
		t.Fatalf("record = %s %s, want GET /x", rec.Method, rec.Path)
	}
}

func TestRequestLoggingReportsImplicitOKForASilentHandler(t *testing.T) {
	rec, _ := observeOne(t, RequestLogConfig{Observe: func(*http.Request, RequestRecord) {}}, "/x",
		func(http.ResponseWriter, *http.Request) {})
	if rec.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 — net/http sends one when a handler writes nothing", rec.Status)
	}
}

func TestRequestLoggingSkipsConfiguredPaths(t *testing.T) {
	cfg := RequestLogConfig{Observe: func(*http.Request, RequestRecord) {}, SkipPaths: []string{"/health", "/mesh/"}}
	for _, p := range []string{"/health", "/mesh/peers"} {
		if _, seen := observeOne(t, cfg, p, func(http.ResponseWriter, *http.Request) {}); seen {
			t.Fatalf("%s was reported despite being skipped", p)
		}
	}
	if _, seen := observeOne(t, cfg, "/healthcheck-admin", func(http.ResponseWriter, *http.Request) {}); !seen {
		t.Fatal("/healthcheck-admin was skipped by the exact entry /health; exact must not match by prefix")
	}
}

func TestRequestLoggingWithNilObserverIsAPassThrough(t *testing.T) {
	var gotWriter http.ResponseWriter
	h := RequestLogging(RequestLogConfig{})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gotWriter = w
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if _, wrapped := gotWriter.(*statusWriter); wrapped {
		t.Fatal("nil observer still wrapped the writer; an unread wrapper is pure cost")
	}
}

func TestRequestLoggingPreservesFlusher(t *testing.T) {
	var sawFlusher bool
	h := RequestLogging(RequestLogConfig{Observe: func(*http.Request, RequestRecord) {}})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, sawFlusher = w.(http.Flusher)
		}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/sse", nil))
	if !sawFlusher {
		t.Fatal("Flusher stripped: a streaming handler behind this would buffer to the end")
	}
}

// A panicking handler must still be reported, and must NOT be reported as a 200.
// The status stays 0 because nothing was written: filing a panic as a success is
// worse than the silence it replaces.
func TestRequestLoggingReportsAPanickingHandlerAsIncomplete(t *testing.T) {
	var got RequestRecord
	var seen bool
	h := RequestLogging(RequestLogConfig{
		Observe: func(_ *http.Request, rec RequestRecord) { got, seen = rec, true },
	})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))

	func() {
		defer func() {
			if recover() == nil {
				t.Error("the panic was swallowed here; RequestLogging must not recover")
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))
	}()

	if !seen {
		t.Fatal("a panicking request was not reported at all")
	}
	if got.Status != 0 {
		t.Errorf("Status = %d, want 0 — the handler never returned and wrote nothing", got.Status)
	}
	if got.Path != "/x" || got.Method != http.MethodGet {
		t.Errorf("record = %+v, want the request's method and path", got)
	}
}
