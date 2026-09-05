/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// okAuth accepts every request as subject with the given type.
func okAuth(id, authType string, scopes ...string) Authenticator {
	return AuthenticatorFunc(func(*http.Request) (Subject, error) {
		return Subject{ID: id, AuthType: authType, Scopes: scopes}, nil
	})
}

// run drives one request through RequireAuth and reports the response plus
// whether the protected handler was reached and what it saw.
type reached struct {
	called        bool
	userID        string
	scopes        []string
	authType      string
	sessionID     string
	authenticated bool
}

func run(t *testing.T, cfg AuthConfig) (*httptest.ResponseRecorder, *reached) {
	t.Helper()
	got := &reached{}
	h := RequireAuth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.called = true
		got.userID = ExtractUserID(r.Context())
		got.scopes = ExtractScopes(r.Context())
		got.authType = GetAuthType(r.Context())
		got.sessionID = ExtractSessionID(r.Context())
		got.authenticated = IsAuthenticated(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/protected", nil))
	return rec, got
}

func TestRequireAuthZeroValueDeniesEveryRequest(t *testing.T) {
	rec, got := run(t, AuthConfig{})
	if got.called {
		t.Fatal("zero-value AuthConfig admitted a request; an unconfigured mount must deny")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequireAuthNilAuthenticatorDenies(t *testing.T) {
	_, got := run(t, AuthConfig{AcceptAnyType: true})
	if got.called {
		t.Fatal("nil Authenticator admitted a request instead of denying")
	}
}

func TestRequireAuthContradictoryTypeConfigDenies(t *testing.T) {
	_, got := run(t, AuthConfig{
		Authenticator: okAuth("u1", "session"),
		AcceptedTypes: []string{"session"},
		AcceptAnyType: true,
	})
	if got.called {
		t.Fatal("AcceptAnyType alongside AcceptedTypes admitted a request; the two disagree and must fail closed")
	}
}

func TestRequireAuthEmptyTypeListWithoutAnyDenies(t *testing.T) {
	var sawReason string
	_, got := run(t, AuthConfig{
		Authenticator: okAuth("u1", "session"),
		OnDeny:        func(_ *http.Request, reason string, _ error) { sawReason = reason },
	})
	if got.called {
		t.Fatal("empty AcceptedTypes admitted a request; an unset list must not mean any")
	}
	// The deny is over-determined — an empty list also fails the per-request type
	// match — so the reason is what distinguishes a mount that can never admit
	// anyone from one rejecting this particular credential. An operator reading
	// auth_type here would go looking for the caller's type instead of the mount.
	if sawReason != DenyUnconfigured {
		t.Fatalf("OnDeny reason = %q, want %q", sawReason, DenyUnconfigured)
	}
}

func TestRequireAuthCredentialErrorDenies(t *testing.T) {
	var sawReason string
	var sawErr error
	boom := errors.New("no cookie")
	rec, got := run(t, AuthConfig{
		Authenticator: AuthenticatorFunc(func(*http.Request) (Subject, error) { return Subject{}, boom }),
		AcceptAnyType: true,
		OnDeny:        func(_ *http.Request, reason string, err error) { sawReason, sawErr = reason, err },
	})
	if got.called {
		t.Fatal("a failed Authenticate admitted the request")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if sawReason != DenyNoCredential || !errors.Is(sawErr, boom) {
		t.Fatalf("OnDeny got (%q, %v), want (%q, %v)", sawReason, sawErr, DenyNoCredential, boom)
	}
	if body := rec.Body.String(); body != http.StatusText(http.StatusUnauthorized)+"\n" {
		t.Fatalf("response body %q leaks detail; want the bare status text", body)
	}
}

func TestRequireAuthEmptySubjectIDDenies(t *testing.T) {
	var sawReason string
	_, got := run(t, AuthConfig{
		Authenticator: okAuth("", "session"),
		AcceptAnyType: true,
		OnDeny:        func(_ *http.Request, reason string, _ error) { sawReason = reason },
	})
	if got.called {
		t.Fatal("a subject with an empty ID was admitted; it is indistinguishable from anonymous downstream")
	}
	if sawReason != DenyEmptySubject {
		t.Fatalf("OnDeny reason = %q, want %q", sawReason, DenyEmptySubject)
	}
}

func TestRequireAuthUnacceptedTypeDenies(t *testing.T) {
	var sawReason string
	_, got := run(t, AuthConfig{
		Authenticator: okAuth("u1", "api-key"),
		AcceptedTypes: []string{"session", "bearer"},
		OnDeny:        func(_ *http.Request, reason string, _ error) { sawReason = reason },
	})
	if got.called {
		t.Fatal("a valid credential of an unlisted type was admitted")
	}
	if sawReason != DenyAuthType {
		t.Fatalf("OnDeny reason = %q, want %q", sawReason, DenyAuthType)
	}
}

func TestRequireAuthAcceptedTypeStampsSubject(t *testing.T) {
	rec, got := run(t, AuthConfig{
		Authenticator: AuthenticatorFunc(func(*http.Request) (Subject, error) {
			return Subject{ID: "u1", AuthType: "session", Scopes: []string{"a.read"}, SessionID: "s9"}, nil
		}),
		AcceptedTypes: []string{"session"},
	})
	if !got.called {
		t.Fatalf("an accepted credential was denied; status %d", rec.Code)
	}
	if got.userID != "u1" || got.authType != "session" || got.sessionID != "s9" || !got.authenticated {
		t.Fatalf("stamped subject = (%q, %q, %q, auth=%v), want (u1, session, s9, true)",
			got.userID, got.authType, got.sessionID, got.authenticated)
	}
	if len(got.scopes) != 1 || got.scopes[0] != "a.read" {
		t.Fatalf("stamped scopes = %v, want [a.read]", got.scopes)
	}
}

func TestRequireAuthAcceptAnyTypeAdmitsUnlistedType(t *testing.T) {
	_, got := run(t, AuthConfig{Authenticator: okAuth("u1", "mtls"), AcceptAnyType: true})
	if !got.called {
		t.Fatal("AcceptAnyType denied a valid credential")
	}
}

func TestRequireAuthEmptySessionIDIsNotStamped(t *testing.T) {
	_, got := run(t, AuthConfig{Authenticator: okAuth("u1", "session"), AcceptedTypes: []string{"session"}})
	if got.sessionID != "" {
		t.Fatalf("session id = %q, want \"\" — an absent id must not be stamped blank", got.sessionID)
	}
}

func TestRequireAuthGateDenialPreservesGateResponse(t *testing.T) {
	rec, got := run(t, AuthConfig{
		Authenticator: okAuth("u1", "session"),
		AcceptAnyType: true,
		Gates: []Gate{GateFunc(func(w http.ResponseWriter, _ *http.Request, _ *Subject) bool {
			http.Redirect(w, httptest.NewRequest(http.MethodGet, "/x", nil), "/2fa", http.StatusFound)
			return false
		})},
	})
	if got.called {
		t.Fatal("a denying gate did not stop the request")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 — the gate owns its response", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/2fa" {
		t.Fatalf("Location = %q, want /2fa", loc)
	}
}

func TestRequireAuthSilentGateDenialGetsForbidden(t *testing.T) {
	var sawReason string
	rec, got := run(t, AuthConfig{
		Authenticator: okAuth("u1", "session"),
		AcceptAnyType: true,
		Gates:         []Gate{GateFunc(func(http.ResponseWriter, *http.Request, *Subject) bool { return false })},
		OnDeny:        func(_ *http.Request, reason string, _ error) { sawReason = reason },
	})
	if got.called {
		t.Fatal("a denying gate did not stop the request")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 — a gate that denies without writing must not yield 200", rec.Code)
	}
	if sawReason != DenyGate {
		t.Fatalf("OnDeny reason = %q, want %q", sawReason, DenyGate)
	}
}

func TestRequireAuthGateMayAppendScopes(t *testing.T) {
	_, got := run(t, AuthConfig{
		Authenticator: okAuth("u1", "session", "a.read"),
		AcceptAnyType: true,
		Gates: []Gate{GateFunc(func(_ http.ResponseWriter, _ *http.Request, s *Subject) bool {
			s.Scopes = append(s.Scopes, "b.write")
			return true
		})},
	})
	if !got.called {
		t.Fatal("an admitting gate blocked the request")
	}
	if len(got.scopes) != 2 || got.scopes[1] != "b.write" {
		t.Fatalf("stamped scopes = %v, want [a.read b.write] — a gate's grants must reach the handler", got.scopes)
	}
}

func TestRequireAuthGatesRunInOrderAndStopAtFirstDenial(t *testing.T) {
	var order []string
	_, got := run(t, AuthConfig{
		Authenticator: okAuth("u1", "session"),
		AcceptAnyType: true,
		Gates: []Gate{
			GateFunc(func(http.ResponseWriter, *http.Request, *Subject) bool { order = append(order, "first"); return true }),
			GateFunc(func(http.ResponseWriter, *http.Request, *Subject) bool { order = append(order, "second"); return false }),
			GateFunc(func(http.ResponseWriter, *http.Request, *Subject) bool { order = append(order, "third"); return true }),
		},
	})
	if got.called {
		t.Fatal("a denying gate did not stop the request")
	}
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("gate order = %v, want [first second] — a gate after a denial must not run", order)
	}
}

func TestRequireAuthGateSeesUnstampedContext(t *testing.T) {
	var stampedInGate bool
	run(t, AuthConfig{
		Authenticator: okAuth("u1", "session"),
		AcceptAnyType: true,
		Gates: []Gate{GateFunc(func(_ http.ResponseWriter, r *http.Request, _ *Subject) bool {
			stampedInGate = IsAuthenticated(r.Context())
			return true
		})},
	})
	if stampedInGate {
		t.Fatal("the context was stamped before the gates ran; a refused request must never leave a stamped context behind")
	}
}
