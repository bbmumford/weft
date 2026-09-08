package weft

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The full request spine a consumer mounts, in the order it must run. Every test
// here drives THIS chain rather than a middleware in isolation, because the
// failures worth catching are the ones that only appear in composition: a wrapper
// that satisfies http.ResponseWriter and quietly drops the interfaces a
// downstream handler needs, or a gate that runs after the thing it was meant to
// gate.
//
// Order, outermost first, and each position is load-bearing:
//
//	Recovery         must be outermost or a panic below it escapes the chain
//	RequestLogging   inside Recovery so a panicking request is still recorded
//	SecurityHeaders  before anything can write, so a denial carries them too
//	Maintenance      before auth: a closed service must not consult a session store
//	AttachSession    resolves the session
//	RequireAuth      reads what AttachSession stamped, so it must follow it
func spine(t *testing.T, cfg AttachSessionConfig, maint MaintenanceConfig,
	onPanic PanicReporter, observe RequestObserver, handler http.Handler) http.Handler {
	t.Helper()
	gate := RequireAuth(AuthConfig{
		Authenticator: SessionAuthenticator(AuthTypeSession),
		AcceptedTypes: []string{AuthTypeSession},
	})
	h := gate(handler)
	h = AttachSession(cfg)(h)
	h = Maintenance(maint)(h)
	h = SecurityHeaders(SecurityHeadersConfig{AllowedOrigins: []string{"example.test"}})(h)
	h = RequestLogging(RequestLogConfig{Observe: observe})(h)
	h = Recovery(onPanic)(h)
	return h
}

type compResolver struct{ data UserSessionData }

func (c compResolver) Resolve(context.Context, string) (UserSessionData, time.Time, error) {
	return c.data, time.Time{}, nil
}

func goodSession() AttachSessionConfig {
	return AttachSessionConfig{
		CookieName: "sid",
		Resolver:   compResolver{data: UserSessionData{UserID: "u-1", Provider: "google"}},
	}
}

func authedRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/protected", nil)
	r.AddCookie(&http.Cookie{Name: "sid", Value: "tok"})
	return r
}

func TestSpine_AdmitsAnAuthenticatedRequestAndStampsIt(t *testing.T) {
	var sawUser string
	var logged bool
	h := spine(t, goodSession(), MaintenanceConfig{}, nil,
		func(*http.Request, RequestRecord) { logged = true },
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sawUser = ExtractUserID(r.Context())
			w.WriteHeader(http.StatusOK)
		}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authedRequest())

	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if sawUser != "u-1" {
		t.Errorf("handler read user %q, want u-1 — the stamp did not survive the chain", sawUser)
	}
	if !logged {
		t.Error("request logging observed nothing")
	}
}

// A denial must still carry the security headers: they are set on the way in, so a
// response written by a gate above the handler is covered too.
func TestSpine_DeniesAnonymousAndStillSetsSecurityHeaders(t *testing.T) {
	reached := false
	h := spine(t, goodSession(), MaintenanceConfig{}, nil, nil,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/protected", nil))

	if reached {
		t.Fatal("an anonymous request reached the handler")
	}
	if rec.Code == http.StatusOK {
		t.Fatalf("code = %d, want a denial", rec.Code)
	}
	if rec.Header().Get("X-Content-Type-Options") == "" {
		t.Error("a denied response carried no security headers")
	}
}

// Streaming must survive every wrapper. Recovery and RequestLogging both wrap the
// ResponseWriter; a wrapper that implements only Write/WriteHeader silently breaks
// SSE for every handler behind it, and the handler cannot tell.
func TestSpine_PreservesFlusherForStreamingHandlers(t *testing.T) {
	var flushable bool
	h := spine(t, goodSession(), MaintenanceConfig{}, nil, func(*http.Request, RequestRecord) {},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, flushable = w.(http.Flusher)
			w.WriteHeader(http.StatusOK)
		}))

	h.ServeHTTP(httptest.NewRecorder(), authedRequest())
	if !flushable {
		t.Fatal("http.Flusher did not survive the chain — SSE and streaming responses are broken " +
			"for every handler behind it, with no error at the point of breakage")
	}
}

// The same for connection upgrades: a wrapper that drops Hijacker breaks every
// WebSocket route behind it.
func TestSpine_PreservesHijackerForUpgrades(t *testing.T) {
	var hijackable bool
	h := spine(t, goodSession(), MaintenanceConfig{}, nil, func(*http.Request, RequestRecord) {},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, hijackable = w.(http.Hijacker)
			w.WriteHeader(http.StatusOK)
		}))

	h.ServeHTTP(&hijackableRecorder{ResponseRecorder: httptest.NewRecorder()}, authedRequest())
	if !hijackable {
		t.Fatal("http.Hijacker did not survive the chain — WebSocket upgrades are broken behind it")
	}
}

func TestSpine_PanicBecomes500AndIsReportedWithoutLeaking(t *testing.T) {
	var reported any
	var logged bool
	h := spine(t, goodSession(), MaintenanceConfig{}, func(_ *http.Request, rec any, _ []byte) {
		reported = rec
	}, func(*http.Request, RequestRecord) { logged = true },
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			panic("token=SECRET-abc123 rejected")
		}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authedRequest())

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "SECRET-abc123") {
		t.Error("the panic value reached the response body — a panic message quotes the argument " +
			"that caused it, and this hands it back to the caller")
	}
	if reported == nil {
		t.Error("the panic reporter saw nothing")
	}
	if !logged {
		t.Error("a panicking request was not logged — logging must sit inside Recovery")
	}
}

// Maintenance runs BEFORE auth, so a closed service answers without consulting the
// session store at all.
func TestSpine_MaintenanceGatesBeforeTheSessionStoreIsConsulted(t *testing.T) {
	consulted := false
	cfg := AttachSessionConfig{
		CookieName: "sid",
		Resolver: resolverFunc(func() (UserSessionData, time.Time, error) {
			consulted = true
			return UserSessionData{UserID: "u-1"}, time.Time{}, nil
		}),
	}
	h := spine(t, cfg, MaintenanceConfig{Enabled: true, Reason: "planned"}, nil, nil,
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("handler ran while maintenance was enabled")
		}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, authedRequest())

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
	if consulted {
		t.Error("the session store was consulted during maintenance — the gate is mounted below " +
			"AttachSession, so a closed service still loads sessions it will not use")
	}
}

type resolverFunc func() (UserSessionData, time.Time, error)

func (f resolverFunc) Resolve(context.Context, string) (UserSessionData, time.Time, error) {
	return f()
}
