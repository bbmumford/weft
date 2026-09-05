/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
	"net/http"
	"runtime"
)

// PanicReporter receives a panic recovered from a handler, with the stack
// captured at the point of recovery. It is a SEAM: this package chooses no
// logger, so a consumer reports through whatever it already uses.
//
// It runs before the response is written and must not panic itself — a second
// panic escapes the recovery entirely and takes the connection with it.
type PanicReporter func(r *http.Request, recovered any, stack []byte)

// Recovery turns a handler panic into a 500 instead of a dropped connection.
//
// The response carries the status and nothing else. The recovered value and the
// stack go to the reporter alone: a panic message routinely quotes the argument
// that caused it — a path, a query, a token — and writing it to the response
// hands that back to whoever sent it.
//
// A handler that already began writing gets no second status: the client is
// already receiving a response, and a WriteHeader after the first one changes
// nothing except to emit a superfluous-write warning that reads as a second bug.
//
// http.ErrAbortHandler is re-panicked rather than reported. It is the documented
// way a handler abandons a request deliberately, and net/http expects to see it.
func Recovery(report PanicReporter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rw := &statusWriter{ResponseWriter: w}
			defer func() {
				rec := recover()
				if rec == nil {
					return
				}
				if rec == http.ErrAbortHandler {
					panic(rec)
				}
				if report != nil {
					buf := make([]byte, 8192)
					n := runtime.Stack(buf, false)
					report(r, rec, buf[:n])
				}
				if !rw.wrote {
					http.Error(rw.ResponseWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(rw, r)
		})
	}
}

// statusWriter records whether the handler began a response, so Recovery can
// tell a panic before the first write from one after it.
type statusWriter struct {
	http.ResponseWriter
	wrote bool
}

func (s *statusWriter) WriteHeader(status int) {
	s.wrote = true
	s.ResponseWriter.WriteHeader(status)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}
