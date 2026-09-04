package weft

import (
	"context"
)

// Authenticated-subject context carriers: userID, scopes, auth-type, the
// authenticated flag, and sessionID. An ingress/auth middleware stamps them
// once via SetAuthContext/WithSessionID; downstream handlers read them via
// Extract*/Is*/Get* without re-parsing credentials. weft interprets none of
// these values — scopes are opaque capability strings a consumer's authority
// layer (a CapabilityPolicy) evaluates, never weft. These carriers name a
// SUBJECT and its granted capabilities, never a partition/ownership axis, so
// no store selector keys on them.
//
// Keys are weft-package-scoped by the unexported contextKey type (declared in
// context.go), so a value stamped through another package's carrier is not
// visible here: a consumer swaps its With*/Extract* pair to weft's together
// per endpoint so the stamp and the read share weft's key.
const (
	userIDKey        = contextKey("user_id")
	scopesKey        = contextKey("scopes")
	authenticatedKey = contextKey("authenticated")
	authTypeKey      = contextKey("auth_type")
	sessionIDKey     = contextKey("session_id")
)

// SetAuthContext stamps the authenticated subject onto ctx in one call: userID,
// its granted scopes, the authenticated flag (true), and the auth-type label an
// auth middleware resolved. Handlers then read via ExtractUserID/ExtractScopes/
// IsAuthenticated/GetAuthType. Use WithSessionID separately when a session id is
// known.
func SetAuthContext(ctx context.Context, userID string, scopes []string, authType string) context.Context {
	ctx = context.WithValue(ctx, userIDKey, userID)
	ctx = context.WithValue(ctx, scopesKey, scopes)
	ctx = context.WithValue(ctx, authenticatedKey, true)
	ctx = context.WithValue(ctx, authTypeKey, authType)
	return ctx
}

// ExtractUserID reads the authenticated subject id stamped by SetAuthContext,
// or "" when absent.
func ExtractUserID(ctx context.Context) string {
	if userID, ok := ctx.Value(userIDKey).(string); ok {
		return userID
	}
	return ""
}

// ExtractScopes reads the granted scope strings stamped by SetAuthContext, or an
// empty (non-nil) slice when absent. weft returns them verbatim; matching a
// required scope against this set is the authority layer's job, not weft's.
func ExtractScopes(ctx context.Context) []string {
	if scopes, ok := ctx.Value(scopesKey).([]string); ok {
		return scopes
	}
	return []string{}
}

// IsAuthenticated reports whether SetAuthContext stamped an authenticated
// subject onto ctx. Returns false on an unstamped context.
func IsAuthenticated(ctx context.Context) bool {
	if authenticated, ok := ctx.Value(authenticatedKey).(bool); ok {
		return authenticated
	}
	return false
}

// GetAuthType reads the auth-type label stamped by SetAuthContext, or "unknown"
// when absent — the sentinel a caller distinguishes from a real label.
func GetAuthType(ctx context.Context) string {
	if authType, ok := ctx.Value(authTypeKey).(string); ok {
		return authType
	}
	return "unknown"
}

// WithSessionID stamps the session id onto ctx; call from the session
// middleware that resolved it.
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, sessionIDKey, sessionID)
}

// ExtractSessionID reads the session id stamped by WithSessionID, or "" when
// absent.
func ExtractSessionID(ctx context.Context) string {
	if sessionID, ok := ctx.Value(sessionIDKey).(string); ok {
		return sessionID
	}
	return ""
}
