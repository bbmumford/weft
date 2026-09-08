package weft

import (
	"context"
	"strings"
)

// Wire keys IdentityMap emits. THE STRINGS ARE THE CONTRACT, not the
// identifiers: a dispatch layer reads them by exact name out of a plain
// string map, so renaming one here does not fail to compile anywhere — it
// makes the receiving side stop finding the caller, and an unidentified
// call is refused rather than diagnosed.
//
// KeyUserIDCamel duplicates KeyUserID deliberately. Accessors on the far side
// disagree about the spelling, and emitting one alone leaves whichever reads
// the other seeing an anonymous call. Both are emitted from the same value, so
// they cannot drift apart.
const (
	KeyUserID      = "user_id"
	KeyUserIDCamel = "userId"
	KeySessionID   = "session_id"
	KeyAuthType    = "auth_type"
	KeyScopes      = "scopes"
)

// IdentityMap flattens the identity stamped on ctx into the string map a
// dispatch layer carries, so an authenticated HTTP handler can hand its caller
// to an outbound call:
//
//	ctx = rpc.WithRPCContext(ctx, weft.IdentityMap(r.Context()))
//
// weft neither performs the call nor imports whatever makes it — it emits the
// values and the consumer chooses the carrier. That is why this returns a map
// rather than middleware.
//
// Only set values are emitted. An empty string is omitted rather than written
// blank, because the map is usually MERGED into one a dispatch layer already
// populated, and a blank would overwrite a value established there with
// something that reads as absent.
//
// Scopes are space-joined into one entry, the form a single string field can
// carry. A scope containing a space would therefore arrive as two, so a
// consumer minting scopes must keep them space-free — nothing here can detect
// the difference after the join.
//
// Partition axes are emitted under the axis names the consumer chose, and are
// written BEFORE the subject keys so an axis that happens to be named "user_id"
// cannot displace the authenticated subject. A partition says which data a call
// reaches and must never be able to rewrite who is making it.
func IdentityMap(ctx context.Context) map[string]string {
	m := make(map[string]string, 8)

	for axis, value := range Partitions(ctx) {
		if axis == "" || value == "" {
			continue
		}
		m[axis] = value
	}

	if v := ExtractUserID(ctx); v != "" {
		m[KeyUserID] = v
		m[KeyUserIDCamel] = v
	}
	if v := ExtractSessionID(ctx); v != "" {
		m[KeySessionID] = v
	}
	// GetAuthType reports AuthTypeUnknown when nothing stamped a type, which is
	// the absence of a credential rather than one. Forwarding it would overwrite
	// a real type already in the map with a value that reads as authenticated.
	if v := GetAuthType(ctx); v != "" && v != AuthTypeUnknown {
		m[KeyAuthType] = v
	}
	if v := ExtractScopes(ctx); len(v) > 0 {
		m[KeyScopes] = strings.Join(v, " ")
	}
	return m
}
