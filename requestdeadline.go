/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"context"
	"net/http"
	"time"
)

// RequestDeadline bounds how long a handler's work may run by giving the
// request context a deadline, so a slow downstream call cannot hold a
// connection open without end.
//
// It consumes a duration the mount chooses and the incoming request; what
// consumes it is the handler chain beneath it, which reads the deadline from
// r.Context() — a mesh dial, a store query or any call taking a context stops
// at it and returns its own error. Mounted by the ordinary API and page route
// groups of app.orbtr.io and help.orbtr.io.
//
// It writes nothing to the ResponseWriter: the handler below owns the status
// code, because only the handler knows whether the cancelled work had already
// written bytes. A middleware that wrote its own 503 or 504 here would race
// that handler for the header and produce a superfluous-WriteHeader log on
// every expiry. The caller therefore sees whatever the handler returns once its
// context is done, which is why this is a deadline and not a timeout response.
//
// It must not be mounted on a long-lived connection — mesh WebSocket, the agent
// command channel, a relay bridge or an SSE stream — because those are
// expected to outlive any per-request bound and the deadline would cut them at
// the duration rather than at a fault. Bound those with ConcurrencyGuard, which
// counts in-flight work instead of timing it.
//
// A non-positive duration panics rather than defaulting one: an unset field is
// far more often the cause than an intent, and context.WithTimeout on a
// non-positive duration returns an already-expired context, so every request
// through the group would fail with nothing in the logs naming the mount that
// did it.
func RequestDeadline(d time.Duration) func(http.Handler) http.Handler {
	if d <= 0 {
		panic("weft: RequestDeadline requires a positive duration")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
