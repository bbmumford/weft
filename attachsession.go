package weft

import (
	"context"
	"net/http"
	"time"
)

// SessionResolver turns a session token from the request cookie into the
// session data to stamp. A consumer implements it over its own session store;
// weft never learns how a token is stored or validated.
type SessionResolver interface {
	// Resolve returns the session for token. A zero expiresAt means the session
	// does not expire. An error, or a session whose UserID is empty, is treated
	// as no session at all — Resolve reports "who this token belongs to", never
	// "this request may proceed".
	Resolve(ctx context.Context, token string) (data UserSessionData, expiresAt time.Time, err error)
}

// SessionToucher is the optional extension a resolver implements when it records
// session use. AttachSession calls Touch after a session resolves, and ignores
// its error: failing to record use is bookkeeping, and turning it into a denial
// would let a store's write outage log everyone out.
type SessionToucher interface {
	Touch(ctx context.Context, token string, expiresAt time.Time) error
}

// AttachSessionConfig configures AttachSession.
type AttachSessionConfig struct {
	// CookieName is the cookie carrying the session token. Required; without it
	// there is nothing to read and the middleware stamps nothing.
	CookieName string

	// Resolver loads the session. Required, for the same reason.
	Resolver SessionResolver

	// Now supplies the clock the expiry check compares against. Defaults to
	// time.Now.
	Now func() time.Time

	// OnResolveError observes a resolver failure. It cannot change the outcome —
	// the request continues unstamped either way — and exists so a consumer can
	// log or count without weft depending on its logger.
	OnResolveError func(r *http.Request, err error)
}

// AttachSession reads the session cookie, resolves it, and stamps the session on
// the request context for GetSessionDataFromContext to read.
//
// It is an ATTACHER, not a gate. Every failure — no cookie, an unresolvable or
// expired token, a resolver error, or a missing CookieName/Resolver — leaves the
// request unstamped and continues. That is safe only because being unstamped is
// what an unauthenticated request looks like to the reader: GetUserIDFromContext
// reports not-ok, and RequireAuth denies. Mount a gate behind this; on its own it
// admits nothing and refuses nothing.
//
// A session that resolves but carries an empty UserID is not stamped, so a
// handler can never read an authenticated-looking session with no subject.
func AttachSession(cfg AttachSessionConfig) func(http.Handler) http.Handler {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.CookieName == "" || cfg.Resolver == nil {
				next.ServeHTTP(w, r)
				return
			}
			cookie, err := r.Cookie(cfg.CookieName)
			if err != nil || cookie.Value == "" {
				next.ServeHTTP(w, r)
				return
			}

			data, expiresAt, err := cfg.Resolver.Resolve(r.Context(), cookie.Value)
			if err != nil {
				if cfg.OnResolveError != nil {
					cfg.OnResolveError(r, err)
				}
				next.ServeHTTP(w, r)
				return
			}
			if data.UserID == "" {
				next.ServeHTTP(w, r)
				return
			}
			// A zero expiresAt is a session that does not expire; only a set one is
			// compared, so an unset expiry is never read as "expired at the epoch".
			if !expiresAt.IsZero() && !now().Before(expiresAt) {
				next.ServeHTTP(w, r)
				return
			}

			if toucher, ok := cfg.Resolver.(SessionToucher); ok {
				_ = toucher.Touch(r.Context(), cookie.Value, expiresAt)
			}

			next.ServeHTTP(w, r.WithContext(SetSessionDataInContext(r.Context(), data)))
		})
	}
}
