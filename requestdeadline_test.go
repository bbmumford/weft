/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// serveWithDeadline runs h over a bare request and reports what the handler saw:
// whether its context carried a deadline, and the error it ended with.
//
// It waits on its own bound rather than on the handler's context, because an
// unbounded handler context is exactly the fault these tests look for: waiting
// on it would hang the run instead of failing it, and a hanging test reports
// nothing.
func serveWithDeadline(t *testing.T, mw func(http.Handler) http.Handler) (hadDeadline bool, ended error, rec *httptest.ResponseRecorder) {
	t.Helper()
	type seen struct {
		deadline bool
		err      error
	}
	out := make(chan seen, 1)
	rec = httptest.NewRecorder()
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, ok := r.Context().Deadline()
		select {
		case <-r.Context().Done():
			out <- seen{ok, r.Context().Err()}
		case <-time.After(2 * time.Second):
			out <- seen{ok, nil}
		}
	})
	mw(inner).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	s := <-out
	return s.deadline, s.err, rec
}

// TestRequestDeadlineBoundsTheHandlerContext checks the two legs the mounts
// depend on: with the middleware the handler's context carries a deadline and
// expires, and a request with no such mount carries neither, so a route group
// that loses the middleware is visibly different rather than silently unbounded.
func TestRequestDeadlineBoundsTheHandlerContext(t *testing.T) {
	t.Run("with the middleware the context expires", func(t *testing.T) {
		hadDeadline, ended, _ := serveWithDeadline(t, RequestDeadline(10*time.Millisecond))
		if !hadDeadline {
			t.Fatal("the handler's context carries no deadline, so a slow call below it is unbounded")
		}
		if ended == nil {
			t.Fatal("the handler's context did not finish within 2s, so the deadline did not fire")
		}
		if ended != context.DeadlineExceeded {
			t.Fatalf("the handler's context ended with %v, want %v", ended, context.DeadlineExceeded)
		}
	})

	t.Run("without the middleware there is no deadline", func(t *testing.T) {
		passthrough := func(next http.Handler) http.Handler { return next }
		hadDeadline, ended, _ := serveWithDeadline(t, passthrough)
		if hadDeadline {
			t.Fatal("a request with no RequestDeadline mount reports a deadline, so this test proves nothing")
		}
		if ended != nil {
			t.Fatalf("an unmounted request's context ended with %v, want it still running", ended)
		}
	})
}

// TestRequestDeadlineRefusesANonPositiveDuration pins the construction refusal.
// context.WithTimeout on a non-positive duration returns an already-expired
// context, so a zero field would turn every request through the group into a
// cancelled one with nothing naming the mount; the panic names it at boot.
func TestRequestDeadlineRefusesANonPositiveDuration(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("RequestDeadline(%s) returned a middleware instead of refusing", d)
				}
			}()
			RequestDeadline(d)
		}()
	}
}

// TestRequestDeadlineWritesNoResponse pins that the middleware leaves the status
// to the handler: the handler below writes 204 after its context expired, and a
// middleware that wrote its own code first would hold the recorder's status and
// drop that write.
func TestRequestDeadlineWritesNoResponse(t *testing.T) {
	_, _, rec := serveWithDeadline(t, func(next http.Handler) http.Handler {
		return RequestDeadline(5 * time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			w.WriteHeader(http.StatusNoContent)
		}))
	})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, want %d: the middleware wrote a response of its own", rec.Code, http.StatusNoContent)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("body %q, want empty: the middleware wrote a body of its own", rec.Body.String())
	}
}
