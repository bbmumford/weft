/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"bufio"
	"errors"
	"net"
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

// statusWriter records whether the handler began a response, and with what status
// and how many bytes, so Recovery can tell a panic before the first write from one
// after it and RequestLogging can report what was sent.
type statusWriter struct {
	http.ResponseWriter
	wrote  bool
	status int
	bytes  int
}

// WriteHeader records only the FIRST status, which is the one that reaches the
// client; a later WriteHeader changes nothing on the wire and must not change what
// is reported either.
func (s *statusWriter) WriteHeader(status int) {
	if !s.wrote {
		s.status = status
	}
	s.wrote = true
	s.ResponseWriter.WriteHeader(status)
}

// Write records an implicit 200 for a handler that writes a body without calling
// WriteHeader, which is what net/http sends in that case.
func (s *statusWriter) Write(b []byte) (int, error) {
	if !s.wrote {
		s.status = http.StatusOK
		s.wrote = true
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Flush forwards to the wrapped writer. Without it, wrapping strips the Flusher
// interface from every request behind this middleware, and an SSE or chunked
// handler downstream — a text/event-stream feed, a streamed inference response —
// buffers its frames instead of sending them as they are produced. The failure is
// silent: the handler's type assertion just stops succeeding, and the response is
// correct but arrives all at once at the end.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the wrapped writer, which a WebSocket upgrade and a raw
// connection relay both require. Unlike Flush this one fails loudly, so a stripped
// Hijacker shows up as a failed upgrade rather than as latency.
func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := s.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("weft: underlying ResponseWriter does not support hijacking")
}

// Unwrap exposes the wrapped writer to http.ResponseController, which is how
// std-library code reaches the optional interfaces this type does not name
// explicitly — read/write deadlines among them. Flush and Hijack stay declared
// above because callers that type-assert directly never consult Unwrap.
func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
