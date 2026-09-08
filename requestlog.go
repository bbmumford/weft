/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
	"net/http"
	"time"
)

// RequestRecord is what one completed request is reported as. It holds only what
// the middleware itself observed: the request line, what was sent back, and how
// long it took.
//
// It carries NO caller identity. This middleware is mounted at the outside of the
// chain, where the authenticating middleware has not run yet — and a context
// stamped downstream is not visible out here, because each handler passes its new
// context inward rather than back out. A UserID field here would therefore be
// empty on every request, which is worse than an absent one: it reads as
// "anonymous" rather than as "not known at this point". A consumer that wants the
// subject on its log line reads the carriers itself from the request it is given,
// having mounted this INSIDE its auth middleware.
type RequestRecord struct {
	Method   string
	Path     string
	Status   int
	Bytes    int
	Duration time.Duration
}

// RequestObserver receives one completed request. It is a SEAM: this package picks
// no logger, no format, and no level policy — whether a 200 is worth recording at
// all, and whether a 5xx goes somewhere louder, is the consumer's call, not a rule
// baked in here.
//
// It runs after the response is finished, on the request's own goroutine, so work
// that can block belongs behind a queue the observer owns.
type RequestObserver func(r *http.Request, rec RequestRecord)

// RequestLogConfig parameterises RequestLogging.
type RequestLogConfig struct {
	// Observe receives each completed request. A nil Observe makes the middleware
	// a pass-through with no wrapping at all, so a consumer can leave it unset
	// without paying for a writer wrapper it never reads.
	Observe RequestObserver

	// SkipPaths are not reported. An entry ending in "/" matches by prefix; any
	// other entry matches exactly, so "/health" does not also skip
	// "/healthcheck-admin".
	//
	// Liveness paths belong here: a prober hitting one every few seconds otherwise
	// produces most of the log volume and none of its value.
	SkipPaths []string
}

// RequestLogging reports each completed request to the configured observer.
//
// It wraps the ResponseWriter to learn the status and byte count, which is why
// that wrapper forwards Flush, Hijack and Unwrap — see statusWriter. Wrapping
// without them would strip streaming and upgrades from every handler behind this.
func RequestLogging(cfg RequestLogConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg.Observe == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if exemptPath(cfg.SkipPaths, r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			returned := false
			// Deferred so a handler that PANICS is still reported. Without this the
			// panic unwinds past the call and the request vanishes from the log —
			// and a recovery middleware mounted outside this one turns it into a 500
			// the log never mentions, which is the request an operator most wants.
			defer func() {
				status := sw.status
				// A handler that RETURNED without writing anything still produced a
				// 200: net/http sends one when the handler falls off the end. One
				// that never returned wrote nothing and produced nothing from here,
				// so its status stays 0 — recording 200 would file a panic as a
				// success. A reader treats 0 as "did not complete", never as a code.
				if status == 0 && returned {
					status = http.StatusOK
				}
				cfg.Observe(r, RequestRecord{
					Method:   r.Method,
					Path:     r.URL.Path,
					Status:   status,
					Bytes:    sw.bytes,
					Duration: time.Since(start),
				})
			}()
			next.ServeHTTP(sw, r)
			returned = true
		})
	}
}
