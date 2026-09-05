/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// hijackableRecorder is a ResponseRecorder that also implements http.Hijacker,
// since the standard recorder does not and a Hijacker test needs a writer that does.
type hijackableRecorder struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (h *hijackableRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijacked = true
	return nil, nil, nil
}

func TestRecoveryPreservesFlusherForStreamingHandlers(t *testing.T) {
	var sawFlusher bool
	h := Recovery(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, sawFlusher = w.(http.Flusher)
		if sawFlusher {
			w.(http.Flusher).Flush()
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/sse", nil))
	if !sawFlusher {
		t.Fatal("Flusher stripped: an SSE or streamed-inference handler behind this would buffer its frames to the end")
	}
}

func TestRecoveryPreservesHijackerForUpgrades(t *testing.T) {
	var sawHijacker bool
	rec := &hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}
	h := Recovery(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		sawHijacker = ok
		if ok {
			_, _, _ = hj.Hijack()
		}
	}))
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ws", nil))
	if !sawHijacker {
		t.Fatal("Hijacker stripped: a WebSocket upgrade behind this would fail")
	}
	if !rec.hijacked {
		t.Fatal("Hijack did not reach the underlying writer")
	}
}

func TestStatusWriterUnwrapExposesTheWrappedWriter(t *testing.T) {
	inner := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: inner}
	if got := sw.Unwrap(); got != http.ResponseWriter(inner) {
		t.Fatal("Unwrap did not return the wrapped writer; http.ResponseController cannot reach it")
	}
}

func TestStatusWriterRecordsFirstStatusOnly(t *testing.T) {
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder()}
	sw.WriteHeader(http.StatusTeapot)
	sw.WriteHeader(http.StatusInternalServerError)
	if sw.status != http.StatusTeapot {
		t.Fatalf("status = %d, want 418 — only the first status reaches the client", sw.status)
	}
}

func TestStatusWriterRecordsImplicitOKAndByteCount(t *testing.T) {
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder()}
	n, err := sw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write = (%d, %v)", n, err)
	}
	if sw.status != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a body written without WriteHeader is a 200 on the wire", sw.status)
	}
	if sw.bytes != 5 {
		t.Fatalf("bytes = %d, want 5", sw.bytes)
	}
}

func TestStatusWriterHijackErrorsWhenUnderlyingCannot(t *testing.T) {
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder()} // recorder is not a Hijacker
	if _, _, err := sw.Hijack(); err == nil {
		t.Fatal("Hijack returned nil error on a non-hijackable writer; an upgrade would proceed on a dead connection")
	}
}
