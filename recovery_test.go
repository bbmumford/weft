/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serveRecovered(report PanicReporter, h http.HandlerFunc) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	Recovery(report)(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	return rec
}

func TestRecoveryTurnsPanicInto500(t *testing.T) {
	rec := serveRecovered(nil, func(http.ResponseWriter, *http.Request) { panic("boom") })
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestRecoveryDoesNotLeakThePanicValue(t *testing.T) {
	rec := serveRecovered(nil, func(http.ResponseWriter, *http.Request) {
		panic("token=SECRET_VALUE for /admin")
	})
	if strings.Contains(rec.Body.String(), "SECRET_VALUE") {
		t.Fatalf("response body leaked the panic value: %q", rec.Body.String())
	}
}

func TestRecoveryReportsValueAndStack(t *testing.T) {
	var gotVal any
	var gotStack []byte
	serveRecovered(func(_ *http.Request, v any, s []byte) { gotVal, gotStack = v, s },
		func(http.ResponseWriter, *http.Request) { panic("boom") })
	if gotVal != "boom" {
		t.Fatalf("reported value = %v, want boom", gotVal)
	}
	if len(gotStack) == 0 || !strings.Contains(string(gotStack), "weft") {
		t.Fatalf("reported stack did not capture the goroutine: %d bytes", len(gotStack))
	}
}

func TestRecoveryRepanicsErrAbortHandler(t *testing.T) {
	var reported bool
	defer func() {
		rec := recover()
		if rec != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want ErrAbortHandler re-panicked so net/http still sees it", rec)
		}
		if reported {
			t.Fatal("a deliberate abort was reported as a panic")
		}
	}()
	serveRecovered(func(*http.Request, any, []byte) { reported = true },
		func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })
}

func TestRecoveryLeavesAnAlreadyStartedResponseAlone(t *testing.T) {
	rec := serveRecovered(nil, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("partial"))
		panic("after the write")
	})
	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", rec.Code)
	}
	// The status alone cannot show this: a recorder keeps the first WriteHeader
	// and silently drops a second, so the guard is only visible in the body that
	// http.Error would otherwise append to a response already in flight.
	if body := rec.Body.String(); body != "partial" {
		t.Fatalf("body = %q, want %q — a 500 was appended to a response already being sent", body, "partial")
	}
}

func TestRecoveryWithNilReporterStillRecovers(t *testing.T) {
	rec := serveRecovered(nil, func(http.ResponseWriter, *http.Request) { panic("boom") })
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d with a nil reporter, want 500", rec.Code)
	}
}
