package weft

import (
	"net/http"
	"sync/atomic"
)

// ConcurrencyGuard bounds the number of requests executing a handler at once.
// It exists for long-lived streaming handlers — WebSocket, SSE, relay bridges —
// where every in-flight request holds an upstream concurrency slot (a Fly.io
// connection, for instance), so one unbounded handler type can consume every
// slot and starve the others.
//
// It counts in-flight requests and nothing else: it does not read the caller,
// keep a token bucket, or consult the clock. Past the cap a new request is
// refused with 503 "service at capacity" — the server is full, which a monitor
// reads differently from 429 (a request to slow down). It holds no name registry,
// so there is no unregistered-name path that could answer "allow" by default.
type ConcurrencyGuard struct {
	inFlight int64
	max      int64
}

// NewConcurrencyGuard returns a guard admitting up to maxConcurrent requests at
// once. maxConcurrent is a per-route value the mount supplies; it is the one
// setting no surface should inherit from another.
//
// It panics on a non-positive cap rather than defaulting one. A zero or negative
// value is an unset field far more often than an intent, and a defaulted ceiling
// is one no surface chose: a negative cap makes `current > max` never true, so the
// guard would admit without bound; a zero cap refuses every request. Both fail
// silently, so the construction refuses instead.
func NewConcurrencyGuard(maxConcurrent int) *ConcurrencyGuard {
	if maxConcurrent <= 0 {
		panic("weft: NewConcurrencyGuard requires a positive cap")
	}
	return &ConcurrencyGuard{max: int64(maxConcurrent)}
}

// Wrap returns middleware admitting at most the configured number of concurrent
// executions of next and refusing the rest with 503.
//
// The slot is claimed before the cap check and released with a deferred
// decrement, so it is returned on every exit path — the normal return, the
// refusal, and a panic inside next (a deferred call runs while the panic
// unwinds). A slot released only at the end of the happy path would be held
// forever by a handler that panicked, and the surface would decay toward zero
// capacity with no error and no log line.
func (g *ConcurrencyGuard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt64(&g.inFlight, 1)
		defer atomic.AddInt64(&g.inFlight, -1)
		if current > g.max {
			http.Error(w, "service at capacity", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// WrapFunc wraps an http.HandlerFunc; see Wrap.
func (g *ConcurrencyGuard) WrapFunc(next http.HandlerFunc) http.Handler {
	return g.Wrap(next)
}

// InFlight reports how many requests are currently executing the wrapped
// handler. It is a monitoring read, not a gate.
func (g *ConcurrencyGuard) InFlight() int64 {
	return atomic.LoadInt64(&g.inFlight)
}
