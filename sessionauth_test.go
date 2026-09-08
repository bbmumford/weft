package weft

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type authStubResolver struct {
	data      UserSessionData
	expiresAt time.Time
	err       error
}

func (s authStubResolver) Resolve(context.Context, string) (UserSessionData, time.Time, error) {
	return s.data, s.expiresAt, s.err
}

type chainResult struct {
	code     int
	userID   string
	scopes   []string
	authType string
	reached  bool
	denyWhy  string
}

// buildChain mounts the full session path a consumer would: attach, then gate.
// withAttach:false mounts the gate ALONE, which is the mis-ordered mount.
func buildChain(cfg AttachSessionConfig, auth AuthConfig, withAttach bool) (http.Handler, *chainResult) {
	got := &chainResult{}
	auth.OnDeny = func(_ *http.Request, reason string, _ error) { got.denyWhy = reason }

	var h http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.reached = true
		got.userID = ExtractUserID(r.Context())
		got.scopes = ExtractScopes(r.Context())
		got.authType = GetAuthType(r.Context())
	})
	h = RequireAuth(auth)(h)
	if withAttach {
		h = AttachSession(cfg)(h)
	}
	return h, got
}

func runChain(t *testing.T, h http.Handler, got *chainResult, cookie *http.Cookie) *chainResult {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	h.ServeHTTP(rec, req)
	got.code = rec.Code
	return got
}

func sessionOnlyAuth() AuthConfig {
	return AuthConfig{
		Authenticator: SessionAuthenticator(AuthTypeSession),
		AcceptedTypes: []string{AuthTypeSession},
	}
}

func TestSessionAuth_AttachThenGateAdmitsAndStamps(t *testing.T) {
	now := time.Now()
	cfg := AttachSessionConfig{
		CookieName: "sid",
		Resolver:   authStubResolver{data: UserSessionData{UserID: "u-7", Provider: "google"}, expiresAt: now.Add(time.Hour)},
	}
	h, got := buildChain(cfg, sessionOnlyAuth(), true)
	runChain(t, h, got, &http.Cookie{Name: "sid", Value: "tok"})

	if !got.reached {
		t.Fatalf("handler not reached, code=%d deny=%q", got.code, got.denyWhy)
	}
	if got.userID != "u-7" {
		t.Fatalf("ExtractUserID = %q, want u-7", got.userID)
	}
	if got.authType != AuthTypeSession {
		t.Fatalf("GetAuthType = %q, want %q", got.authType, AuthTypeSession)
	}
	// A session says who, not what: no scopes are conferred by authenticating.
	if len(got.scopes) != 0 {
		t.Fatalf("session conferred scopes %v, want none", got.scopes)
	}
}

// The gate mounted WITHOUT the attacher ahead of it must deny every request,
// not admit them. A mis-ordered mount fails on the first request.
func TestSessionAuth_GateWithoutAttacherDeniesEveryRequest(t *testing.T) {
	cfg := AttachSessionConfig{
		CookieName: "sid",
		Resolver:   authStubResolver{data: UserSessionData{UserID: "u-7"}},
	}
	h, got := buildChain(cfg, sessionOnlyAuth(), false)
	runChain(t, h, got, &http.Cookie{Name: "sid", Value: "tok"})

	if got.reached {
		t.Fatal("handler reached with no session attached")
	}
	if got.denyWhy != DenyNoCredential {
		t.Fatalf("deny reason = %q, want %q", got.denyWhy, DenyNoCredential)
	}
}

// The expiry check must survive composition: an expired session is never
// stamped, so the gate has nothing to admit.
func TestSessionAuth_ExpiredSessionIsDeniedThroughTheWholeChain(t *testing.T) {
	now := time.Now()
	cfg := AttachSessionConfig{
		CookieName: "sid",
		Resolver:   authStubResolver{data: UserSessionData{UserID: "u-7"}, expiresAt: now.Add(-time.Minute)},
		Now:        func() time.Time { return now },
	}
	h, got := buildChain(cfg, sessionOnlyAuth(), true)
	runChain(t, h, got, &http.Cookie{Name: "sid", Value: "tok"})

	if got.reached {
		t.Fatal("expired session admitted")
	}
	if got.denyWhy != DenyNoCredential {
		t.Fatalf("deny reason = %q, want %q", got.denyWhy, DenyNoCredential)
	}
}

func TestSessionAuth_NoCookieIsDenied(t *testing.T) {
	cfg := AttachSessionConfig{
		CookieName: "sid",
		Resolver:   authStubResolver{data: UserSessionData{UserID: "u-7"}},
	}
	h, got := buildChain(cfg, sessionOnlyAuth(), true)
	runChain(t, h, got, nil)
	if got.reached {
		t.Fatal("anonymous request admitted")
	}
}

// A resolver that hands back an empty subject must not authenticate anyone,
// through either guard.
func TestSessionAuth_EmptySubjectIsDenied(t *testing.T) {
	cfg := AttachSessionConfig{
		CookieName: "sid",
		Resolver:   authStubResolver{data: UserSessionData{Provider: "google"}},
	}
	h, got := buildChain(cfg, sessionOnlyAuth(), true)
	runChain(t, h, got, &http.Cookie{Name: "sid", Value: "tok"})
	if got.reached {
		t.Fatal("a session with no subject was admitted")
	}
}

// The label must match the mount's accepted vocabulary by exact string.
func TestSessionAuth_TypeMismatchIsDenied(t *testing.T) {
	cfg := AttachSessionConfig{
		CookieName: "sid",
		Resolver:   authStubResolver{data: UserSessionData{UserID: "u-7"}},
	}
	auth := AuthConfig{
		Authenticator: SessionAuthenticator(AuthTypeSession),
		AcceptedTypes: []string{AuthTypeMTLS},
	}
	h, got := buildChain(cfg, auth, true)
	runChain(t, h, got, &http.Cookie{Name: "sid", Value: "tok"})
	if got.reached {
		t.Fatal("a session was admitted on an mtls-only mount")
	}
	if got.denyWhy != DenyAuthType {
		t.Fatalf("deny reason = %q, want %q", got.denyWhy, DenyAuthType)
	}
}

func TestSessionAuth_EmptyAuthTypeCannotBeAccepted(t *testing.T) {
	cfg := AttachSessionConfig{
		CookieName: "sid",
		Resolver:   authStubResolver{data: UserSessionData{UserID: "u-7"}},
	}
	auth := AuthConfig{
		Authenticator: SessionAuthenticator(""),
		AcceptedTypes: []string{AuthTypeSession},
	}
	h, got := buildChain(cfg, auth, true)
	runChain(t, h, got, &http.Cookie{Name: "sid", Value: "tok"})
	if got.reached {
		t.Fatal("an unlabelled subject was admitted")
	}
}

func TestSessionAuthenticator_ReturnsErrNoSessionDirectly(t *testing.T) {
	_, err := SessionAuthenticator(AuthTypeSession).Authenticate(
		httptest.NewRequest(http.MethodGet, "/x", nil))
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("err = %v, want ErrNoSession", err)
	}
}
