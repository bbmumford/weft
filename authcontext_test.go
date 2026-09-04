package weft

import (
	"context"
	"testing"
)

func TestAuthContext_RoundTrip(t *testing.T) {
	ctx := SetAuthContext(context.Background(), "user-42", []string{"orbtr.ai:model.read", "billing:invoice.read"}, "session")
	if got := ExtractUserID(ctx); got != "user-42" {
		t.Errorf("user id = %q, want user-42", got)
	}
	if got := ExtractScopes(ctx); len(got) != 2 || got[0] != "orbtr.ai:model.read" {
		t.Errorf("scopes = %v, want the two stamped", got)
	}
	if !IsAuthenticated(ctx) {
		t.Error("IsAuthenticated = false after SetAuthContext, want true")
	}
	if got := GetAuthType(ctx); got != "session" {
		t.Errorf("auth type = %q, want session", got)
	}
}

func TestAuthContext_AbsentDefaults(t *testing.T) {
	ctx := context.Background()
	if got := ExtractUserID(ctx); got != "" {
		t.Errorf("absent user id = %q, want empty", got)
	}
	if got := ExtractScopes(ctx); got == nil || len(got) != 0 {
		t.Errorf("absent scopes = %v, want empty non-nil slice", got)
	}
	if IsAuthenticated(ctx) {
		t.Error("IsAuthenticated = true on unstamped ctx, want false")
	}
	if got := GetAuthType(ctx); got != "unknown" {
		t.Errorf("absent auth type = %q, want unknown", got)
	}
	if got := ExtractSessionID(ctx); got != "" {
		t.Errorf("absent session id = %q, want empty", got)
	}
}

func TestSessionIDCarrier_RoundTrip(t *testing.T) {
	ctx := WithSessionID(context.Background(), "sess-abc")
	if got := ExtractSessionID(ctx); got != "sess-abc" {
		t.Errorf("session id = %q, want sess-abc", got)
	}
}

// A subject-carrier key must not collide with the request-metadata carriers
// (carriers.go) or the session-struct key (context.go): stamping all of them
// leaves each independently readable.
func TestAuthContext_NoKeyCollisionWithOtherCarriers(t *testing.T) {
	ctx := SetAuthContext(context.Background(), "user-1", []string{"a:b"}, "bearer")
	ctx = WithSessionID(ctx, "sess-1")
	ctx = WithClientIP(ctx, "198.51.100.9")
	ctx = WithUserAgent(ctx, "go-test")
	if ExtractUserID(ctx) != "user-1" || ExtractSessionID(ctx) != "sess-1" ||
		ExtractClientIP(ctx) != "198.51.100.9" || ExtractUserAgent(ctx) != "go-test" {
		t.Errorf("carrier collision: uid=%q sid=%q ip=%q ua=%q",
			ExtractUserID(ctx), ExtractSessionID(ctx), ExtractClientIP(ctx), ExtractUserAgent(ctx))
	}
}
