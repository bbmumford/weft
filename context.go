/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"context"
	"net/http"
)

// UserSessionData is the authenticated session a session middleware resolved and
// stamped onto the request context, for handlers to read without re-reading the
// cookie or re-hitting the session store.
//
// It carries the subject and the provider that authenticated it, and nothing
// else: no partition, org or tenant field. A handler that needs a partition
// reads it from the sealed authority identity, not from here, so that stamping
// a session can never widen what a caller may reach.
type UserSessionData struct {
	UserID   string
	Provider string
}

// Context key for session
type contextKey string

const sessionContextKey = contextKey("session")

// GetSessionContextKey returns the context key session data is stamped under.
// The key's type is unexported, so a package outside weft cannot construct an
// equal key and stamp session data that these readers would honour.
func GetSessionContextKey() contextKey {
	return sessionContextKey
}

// SetSessionDataInContext stamps the resolved session onto ctx. Call it from the
// session middleware once per request; the readers below are the only supported
// way back out.
//
// The value is stored BY VALUE. SetSessionDataInContext and every reader here
// must move together in a consumer swap: a writer that stamps a pointer leaves
// these type assertions failing, and a failed assertion is indistinguishable
// from an unauthenticated request — it reads as an empty user, not an error.
func SetSessionDataInContext(ctx context.Context, sessionData UserSessionData) context.Context {
	return context.WithValue(ctx, sessionContextKey, sessionData)
}

// GetSessionDataFromContext reads the session stamped by SetSessionDataInContext.
// ok is false when no session middleware stamped one, which a caller must treat
// as unauthenticated rather than as an empty session.
func GetSessionDataFromContext(ctx context.Context) (UserSessionData, bool) {
	data, ok := ctx.Value(sessionContextKey).(UserSessionData)
	return data, ok
}

// GetUserIDFromContext retrieves the authenticated user ID from the request.
// Use it in handlers mounted behind session-validation middleware. ok is false
// both when nothing was stamped and when the stamped session carries an empty
// UserID, so a caller cannot mistake an anonymous request for a named one.
func GetUserIDFromContext(r *http.Request) (userID string, ok bool) {
	data, ok := r.Context().Value(sessionContextKey).(UserSessionData)
	if !ok || data.UserID == "" {
		return "", false
	}
	return data.UserID, true
}

// GetProviderFromContext returns the provider that authenticated the session, or
// "" when no session was stamped.
func GetProviderFromContext(ctx context.Context) string {
	data, ok := ctx.Value(sessionContextKey).(UserSessionData)
	if !ok {
		return ""
	}
	return data.Provider
}
