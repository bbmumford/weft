package weft

import (
	"context"
	"testing"
)

func TestIdentityMap_CarriesTheStampedSubject(t *testing.T) {
	ctx := SetAuthContext(context.Background(), "u-1", []string{"a.read", "b.write"}, AuthTypeSession)
	ctx = WithSessionID(ctx, "s-9")
	m := IdentityMap(ctx)

	for k, want := range map[string]string{
		KeyUserID:      "u-1",
		KeyUserIDCamel: "u-1",
		KeySessionID:   "s-9",
		KeyAuthType:    AuthTypeSession,
		KeyScopes:      "a.read b.write",
	} {
		if m[k] != want {
			t.Errorf("m[%q] = %q, want %q", k, m[k], want)
		}
	}
}

// Both spellings must come from ONE value, so a reader of either sees the same
// caller and they cannot drift.
func TestIdentityMap_BothUserIDSpellingsAgree(t *testing.T) {
	ctx := SetAuthContext(context.Background(), "u-1", nil, AuthTypeSession)
	m := IdentityMap(ctx)
	if m[KeyUserID] != m[KeyUserIDCamel] {
		t.Fatalf("%q = %q but %q = %q", KeyUserID, m[KeyUserID], KeyUserIDCamel, m[KeyUserIDCamel])
	}
	if m[KeyUserID] == "" {
		t.Fatal("neither spelling was emitted")
	}
}

// The map is merged into one a dispatch layer already populated, so an absent
// value must be OMITTED rather than written blank and overwriting it.
func TestIdentityMap_OmitsUnsetValuesRatherThanBlanking(t *testing.T) {
	if m := IdentityMap(context.Background()); len(m) != 0 {
		t.Fatalf("bare context produced %v, want an empty map", m)
	}

	// Authenticated, but no session id and no scopes.
	ctx := SetAuthContext(context.Background(), "u-1", nil, AuthTypeSession)
	m := IdentityMap(ctx)
	if _, present := m[KeySessionID]; present {
		t.Errorf("session_id emitted as %q with none stamped", m[KeySessionID])
	}
	if _, present := m[KeyScopes]; present {
		t.Errorf("scopes emitted as %q with none stamped", m[KeyScopes])
	}
}

func TestIdentityMap_EmitsPartitionAxesUnderTheirOwnNames(t *testing.T) {
	ctx := WithPartition(context.Background(), "estate", "e-1")
	ctx = WithPartition(ctx, "region", "r-9")
	m := IdentityMap(ctx)
	if m["estate"] != "e-1" || m["region"] != "r-9" {
		t.Fatalf("axes = %v, want estate=e-1 region=r-9", m)
	}
}

// A partition names which data a call reaches. It must never be able to rewrite
// WHO is making it, however the consumer named its axis.
func TestIdentityMap_PartitionAxisCannotDisplaceTheSubject(t *testing.T) {
	ctx := SetAuthContext(context.Background(), "real-user", []string{"a.read"}, AuthTypeSession)
	ctx = WithSessionID(ctx, "real-session")
	ctx = WithPartitions(ctx, map[string]string{
		KeyUserID:      "forged-user",
		KeyUserIDCamel: "forged-user",
		KeySessionID:   "forged-session",
		KeyAuthType:    "forged-type",
		KeyScopes:      "forged.everything",
	})
	m := IdentityMap(ctx)

	for k, want := range map[string]string{
		KeyUserID:      "real-user",
		KeyUserIDCamel: "real-user",
		KeySessionID:   "real-session",
		KeyAuthType:    AuthTypeSession,
		KeyScopes:      "a.read",
	} {
		if m[k] != want {
			t.Errorf("a partition axis displaced %q: got %q, want %q", k, m[k], want)
		}
	}
}

// With no subject stamped, a colliding axis is all there is — it must not be
// mistaken for an authenticated caller by the absence of a guard, so record the
// behaviour explicitly.
func TestIdentityMap_AxisAloneIsEmittedWhenNoSubjectIsStamped(t *testing.T) {
	ctx := WithPartition(context.Background(), KeyUserID, "axis-value")
	m := IdentityMap(ctx)
	if m[KeyUserID] != "axis-value" {
		t.Fatalf("m[%q] = %q, want axis-value", KeyUserID, m[KeyUserID])
	}
	if _, present := m[KeyUserIDCamel]; present {
		t.Fatal("the camel spelling was emitted for an axis, not a subject — a reader of that key would see a caller the subject carriers never authenticated")
	}
}

func TestIdentityMap_ScopesAreSpaceJoinedInOrder(t *testing.T) {
	ctx := SetAuthContext(context.Background(), "u-1", []string{"z.last", "a.first"}, AuthTypeSession)
	if got := IdentityMap(ctx)[KeyScopes]; got != "z.last a.first" {
		t.Fatalf("scopes = %q, want %q", got, "z.last a.first")
	}
}

func TestIdentityMap_BlankAxisEntriesAreDropped(t *testing.T) {
	ctx := WithPartitions(context.Background(), map[string]string{"estate": "e-1", "blank": ""})
	m := IdentityMap(ctx)
	if _, present := m["blank"]; present {
		t.Fatalf("blank axis emitted: %v", m)
	}
	if m["estate"] != "e-1" {
		t.Fatalf("estate = %q, want e-1", m["estate"])
	}
}

// GetAuthType reports the sentinel when nothing stamped a type. Forwarding it
// would overwrite a real type in the merged map with one that reads as a
// credential.
func TestIdentityMap_DoesNotForwardTheUnknownSentinel(t *testing.T) {
	ctx := WithPartition(context.Background(), "estate", "e-1")
	if got := GetAuthType(ctx); got != AuthTypeUnknown {
		t.Fatalf("precondition: GetAuthType = %q, want %q", got, AuthTypeUnknown)
	}
	if v, present := IdentityMap(ctx)[KeyAuthType]; present {
		t.Fatalf("auth_type emitted as %q for an unauthenticated context", v)
	}
}
