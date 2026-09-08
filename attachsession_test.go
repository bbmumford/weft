package weft

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type stubResolver struct {
	data      UserSessionData
	expiresAt time.Time
	err       error

	touched      bool
	touchedToken string
	touchErr     error
}

func (s *stubResolver) Resolve(context.Context, string) (UserSessionData, time.Time, error) {
	return s.data, s.expiresAt, s.err
}

type touchingResolver struct{ *stubResolver }

func (t touchingResolver) Touch(_ context.Context, token string, _ time.Time) error {
	t.touched = true
	t.touchedToken = token
	return t.touchErr
}

// records what the handler behind the middleware saw
type sessionSeen struct {
	reached bool
	data    UserSessionData
	ok      bool
}

func serveSession(t *testing.T, cfg AttachSessionConfig, cookie *http.Cookie) *sessionSeen {
	t.Helper()
	got := &sessionSeen{}
	h := AttachSession(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.reached = true
		got.data, got.ok = GetSessionDataFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !got.reached {
		t.Fatal("middleware did not call the next handler")
	}
	return got
}

func sessionFixedNow(ts time.Time) func() time.Time { return func() time.Time { return ts } }

func TestAttachSession_StampsAResolvedSession(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	r := &stubResolver{data: UserSessionData{UserID: "u-1", Provider: "google"}, expiresAt: now.Add(time.Hour)}
	got := serveSession(t, AttachSessionConfig{CookieName: "sid", Resolver: r, Now: sessionFixedNow(now)},
		&http.Cookie{Name: "sid", Value: "tok"})
	if !got.ok {
		t.Fatal("session was not stamped")
	}
	if got.data.UserID != "u-1" || got.data.Provider != "google" {
		t.Fatalf("stamped %+v, want u-1/google", got.data)
	}
}

// An expired session must not be stamped, or a handler reads an authenticated
// session for a token that stopped being valid.
func TestAttachSession_ExpiredSessionIsNotStamped(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	r := &stubResolver{data: UserSessionData{UserID: "u-1"}, expiresAt: now.Add(-time.Second)}
	if got := serveSession(t, AttachSessionConfig{CookieName: "sid", Resolver: r, Now: sessionFixedNow(now)},
		&http.Cookie{Name: "sid", Value: "tok"}); got.ok {
		t.Fatalf("expired session stamped: %+v", got.data)
	}
}

// The boundary: expiry is not a grace period.
func TestAttachSession_ExpiryInstantIsAlreadyExpired(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	r := &stubResolver{data: UserSessionData{UserID: "u-1"}, expiresAt: now}
	if got := serveSession(t, AttachSessionConfig{CookieName: "sid", Resolver: r, Now: sessionFixedNow(now)},
		&http.Cookie{Name: "sid", Value: "tok"}); got.ok {
		t.Fatal("session stamped at its exact expiry instant")
	}
}

// A zero expiry means no expiry, and must not be read as the epoch.
func TestAttachSession_ZeroExpiryNeverExpires(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	r := &stubResolver{data: UserSessionData{UserID: "u-1"}}
	if got := serveSession(t, AttachSessionConfig{CookieName: "sid", Resolver: r, Now: sessionFixedNow(now)},
		&http.Cookie{Name: "sid", Value: "tok"}); !got.ok {
		t.Fatal("zero expiry treated as expired")
	}
}

func TestAttachSession_ResolverErrorIsObservedAndNotStamped(t *testing.T) {
	wantErr := errors.New("store down")
	r := &stubResolver{data: UserSessionData{UserID: "u-1"}, err: wantErr}
	var observed error
	got := serveSession(t, AttachSessionConfig{
		CookieName:     "sid",
		Resolver:       r,
		OnResolveError: func(_ *http.Request, err error) { observed = err },
	}, &http.Cookie{Name: "sid", Value: "tok"})
	if got.ok {
		t.Fatal("session stamped despite a resolver error")
	}
	if !errors.Is(observed, wantErr) {
		t.Fatalf("OnResolveError observed %v, want %v", observed, wantErr)
	}
}

// An empty subject must never be stamped: a handler would read an
// authenticated-looking session with nobody in it.
func TestAttachSession_EmptyUserIDIsNotStamped(t *testing.T) {
	r := &stubResolver{data: UserSessionData{Provider: "google"}}
	if got := serveSession(t, AttachSessionConfig{CookieName: "sid", Resolver: r},
		&http.Cookie{Name: "sid", Value: "tok"}); got.ok {
		t.Fatalf("stamped a session with no subject: %+v", got.data)
	}
}

func TestAttachSession_NoCookieOrEmptyValueIsAPassThrough(t *testing.T) {
	r := &stubResolver{data: UserSessionData{UserID: "u-1"}}
	if got := serveSession(t, AttachSessionConfig{CookieName: "sid", Resolver: r}, nil); got.ok {
		t.Fatal("stamped with no cookie present")
	}
	if got := serveSession(t, AttachSessionConfig{CookieName: "sid", Resolver: r},
		&http.Cookie{Name: "sid", Value: ""}); got.ok {
		t.Fatal("stamped on an empty cookie value")
	}
}

// An unconfigured middleware must be transparent rather than panic: the gate
// behind it is what refuses the request.
func TestAttachSession_UnconfiguredIsTransparent(t *testing.T) {
	r := &stubResolver{data: UserSessionData{UserID: "u-1"}}
	if got := serveSession(t, AttachSessionConfig{Resolver: r}, &http.Cookie{Name: "sid", Value: "tok"}); got.ok {
		t.Fatal("stamped with no CookieName configured")
	}
	if got := serveSession(t, AttachSessionConfig{CookieName: "sid"}, &http.Cookie{Name: "sid", Value: "tok"}); got.ok {
		t.Fatal("stamped with no Resolver configured")
	}
}

func TestAttachSession_TouchesTheResolvedTokenAndIgnoresItsError(t *testing.T) {
	base := &stubResolver{data: UserSessionData{UserID: "u-1"}, touchErr: errors.New("write failed")}
	res := touchingResolver{base}
	got := serveSession(t, AttachSessionConfig{CookieName: "sid", Resolver: res},
		&http.Cookie{Name: "sid", Value: "tok-42"})
	if !got.ok {
		t.Fatal("a Touch error denied the session")
	}
	if !base.touched || base.touchedToken != "tok-42" {
		t.Fatalf("Touch got token %q (called=%v), want tok-42", base.touchedToken, base.touched)
	}
}

// An expired session must not be touched — recording use would extend the life
// of something already invalid.
func TestAttachSession_ExpiredSessionIsNotTouched(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	base := &stubResolver{data: UserSessionData{UserID: "u-1"}, expiresAt: now.Add(-time.Hour)}
	serveSession(t, AttachSessionConfig{CookieName: "sid", Resolver: touchingResolver{base}, Now: sessionFixedNow(now)},
		&http.Cookie{Name: "sid", Value: "tok"})
	if base.touched {
		t.Fatal("an expired session was touched")
	}
}

func TestAttachSession_ResolverWithoutTouchIsFine(t *testing.T) {
	r := &stubResolver{data: UserSessionData{UserID: "u-1"}}
	if got := serveSession(t, AttachSessionConfig{CookieName: "sid", Resolver: r},
		&http.Cookie{Name: "sid", Value: "tok"}); !got.ok {
		t.Fatal("a resolver that does not implement Touch failed to stamp")
	}
}
