package weft

import (
	"errors"
	"net/http"
)

// ErrNoSession is what SessionAuthenticator returns when the request carries no
// stamped session. RequireAuth reports it to OnDeny as DenyNoCredential.
var ErrNoSession = errors.New("weft: no session stamped on the request")

// SessionAuthenticator resolves the subject that AttachSession stamped, so the
// two compose into a session-gated mount:
//
//	router.Use(weft.AttachSession(weft.AttachSessionConfig{...}))
//	protected := router.With(weft.RequireAuth(weft.AuthConfig{
//	    Authenticator: weft.SessionAuthenticator(weft.AuthTypeSession),
//	    AcceptedTypes: []string{weft.AuthTypeSession},
//	}))
//
// It reads only what AttachSession already resolved and never touches the cookie
// or the session store itself. That split is why the ordering above is required
// rather than stylistic: mounted without AttachSession ahead of it, this
// authenticator finds nothing and RequireAuth denies every request. The failure
// is total and immediate rather than intermittent, so a mis-ordered mount shows
// up on the first request instead of under some condition.
//
// authType labels the credential and must be one RequireAuth's AcceptedTypes
// lists, compared by exact string — pass the AuthType* constants rather than a
// literal. An empty authType yields a subject RequireAuth cannot accept under
// any AcceptedTypes list, so it denies.
//
// The subject carries NO scopes: a session says who is calling, not what they
// may reach. A mount needing scopes attaches a Gate that loads them for the
// stamped subject, which keeps the store lookup out of the credential path and
// off requests that are denied before it.
func SessionAuthenticator(authType string) Authenticator {
	return AuthenticatorFunc(func(r *http.Request) (Subject, error) {
		data, ok := GetSessionDataFromContext(r.Context())
		if !ok || data.UserID == "" {
			return Subject{}, ErrNoSession
		}
		return Subject{ID: data.UserID, AuthType: authType}, nil
	})
}
