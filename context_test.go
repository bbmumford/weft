package weft

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestSessionData_RoundTrip(t *testing.T) {
	ctx := SetSessionDataInContext(context.Background(), UserSessionData{UserID: "user-7", Provider: "github"})
	got, ok := GetSessionDataFromContext(ctx)
	if !ok {
		t.Fatal("GetSessionDataFromContext ok = false after stamping, want true")
	}
	if got.UserID != "user-7" || got.Provider != "github" {
		t.Errorf("session = %+v, want {user-7 github}", got)
	}
	if p := GetProviderFromContext(ctx); p != "github" {
		t.Errorf("provider = %q, want github", p)
	}
}

func TestSessionData_AbsentReadsAsUnauthenticated(t *testing.T) {
	ctx := context.Background()
	if _, ok := GetSessionDataFromContext(ctx); ok {
		t.Error("ok = true on an unstamped context, want false")
	}
	if p := GetProviderFromContext(ctx); p != "" {
		t.Errorf("absent provider = %q, want empty", p)
	}
	r := httptest.NewRequest("GET", "/", nil)
	if _, ok := GetUserIDFromContext(r); ok {
		t.Error("GetUserIDFromContext ok = true on an unstamped request, want false")
	}
}

// A stamped session whose UserID is empty must read as unauthenticated, so a
// handler cannot act for the anonymous "" user.
func TestGetUserIDFromContext_EmptyUserIDIsNotAuthenticated(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(SetSessionDataInContext(r.Context(), UserSessionData{Provider: "github"}))
	if id, ok := GetUserIDFromContext(r); ok || id != "" {
		t.Errorf("GetUserIDFromContext = (%q, %v), want (\"\", false)", id, ok)
	}
}

// The carriers store UserSessionData by value. A writer that stamps a POINTER
// under the same key leaves every reader's type assertion failing, and that
// failure is silent — it reads as "no session" rather than as an error. This
// pins the value semantics so a consumer swapping its writer onto weft cannot
// half-migrate without a test failing.
func TestSessionData_PointerStampIsNotReadable(t *testing.T) {
	ctx := context.WithValue(context.Background(), sessionContextKey, &UserSessionData{UserID: "user-7"})
	if _, ok := GetSessionDataFromContext(ctx); ok {
		t.Error("a pointer-stamped session read back as a value; the carriers no longer pin value semantics")
	}
}

// The session key must not collide with the auth-context or request-metadata
// carriers: stamping all of them leaves each independently readable.
func TestSessionData_NoKeyCollisionWithOtherCarriers(t *testing.T) {
	ctx := SetSessionDataInContext(context.Background(), UserSessionData{UserID: "user-7", Provider: "github"})
	ctx = SetAuthContext(ctx, "user-7", []string{"a:b"}, "session")
	ctx = WithClientIP(ctx, "198.51.100.9")
	sd, ok := GetSessionDataFromContext(ctx)
	if !ok || sd.Provider != "github" || ExtractUserID(ctx) != "user-7" || ExtractClientIP(ctx) != "198.51.100.9" {
		t.Errorf("carrier collision: session=%+v ok=%v uid=%q ip=%q",
			sd, ok, ExtractUserID(ctx), ExtractClientIP(ctx))
	}
}
