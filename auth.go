/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

import "net/http"

// Subject is the authenticated caller an Authenticator resolved from a request.
// It names WHO is calling and WHAT they hold. It carries no partition or
// ownership axis, for the reason given on SetAuthContext: nothing keyed on a
// store selector may be read from here.
//
// DO NOT ADD A TENANT, ORG, PARTITION OR OWNER FIELD. An Authenticator resolving
// a credential is exactly where one looks natural — the credential usually knows
// which partition it belongs to — but the axis carrier is loom's scope.Axis /
// id.Scope pair, which is non-aliasing by construction: a value stamped on one
// axis cannot be read back on another. A second axis carrier here would be
// aliasing by construction instead, since every axis would arrive as the same
// plain string field, and a selector reading it could not tell a platform-level
// value from a customer-level one. Stamp the axis through loom alongside this,
// never inside it.
type Subject struct {
	// ID identifies the caller. An empty ID is never treated as authenticated —
	// RequireAuth denies instead of stamping it, because ExtractUserID returns ""
	// for both an anonymous request and a subject stamped with an empty id, and a
	// handler comparing that against a record owner cannot tell them apart.
	ID string

	// Scopes are opaque capability strings. weft neither parses nor matches them;
	// a Gate may append to them, and the consumer's authority layer evaluates the
	// result after the request is stamped.
	Scopes []string

	// AuthType labels the credential that was accepted. RequireAuth matches it
	// against AuthConfig.AcceptedTypes by exact string, so it must be drawn from
	// the same vocabulary the consumer lists there; a label that differs by case
	// or spelling denies every request carrying it.
	AuthType string

	// SessionID is stamped via WithSessionID when non-empty, and left unstamped
	// when empty so ExtractSessionID keeps returning "" rather than a blank id.
	SessionID string
}

// Authenticator resolves a request's credential into a Subject. It is the ONLY
// thing that decides what a credential is: weft reads no cookie, header, or
// certificate of its own, so a consumer's session format, token grammar, and
// user store stay entirely on the consumer's side of this seam.
//
// It returns an error when the request carries no valid credential. The error
// reaches AuthConfig.OnDeny and is never written to the response, because its
// text is derived from the credential the caller supplied.
type Authenticator interface {
	Authenticate(r *http.Request) (Subject, error)
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(r *http.Request) (Subject, error)

// Authenticate implements Authenticator.
func (f AuthenticatorFunc) Authenticate(r *http.Request) (Subject, error) { return f(r) }

// Gate is an admission check that runs after a credential is accepted and
// before the request is stamped. It exists because authenticating a caller and
// deciding that this particular request may proceed are separate questions: a
// membership policy, a device-trust requirement, or an allow-list keyed on the
// request's own host or address cannot be answered by the credential alone.
//
// Admit reports whether the request proceeds. A gate that denies OWNS the
// response — it may write any status, including a redirect to a step-up flow,
// and RequireAuth writes nothing further. A gate that denies without writing
// gets a 403 written for it, so a forgotten write cannot pass an unwritten 200
// back to the caller.
//
// The Subject is a pointer so a gate may append to Scopes: a policy check that
// resolves additional grants for this request adds them here, and everything
// downstream reads them through ExtractScopes. A gate must not clear Scopes to
// revoke — a revocation the authority layer must honour belongs in the scope set
// the Authenticator returns, where the layer that evaluates capabilities can see
// it, not in a slice truncation this package cannot interpret.
type Gate interface {
	Admit(w http.ResponseWriter, r *http.Request, s *Subject) bool
}

// GateFunc adapts a function to Gate.
type GateFunc func(w http.ResponseWriter, r *http.Request, s *Subject) bool

// Admit implements Gate.
func (f GateFunc) Admit(w http.ResponseWriter, r *http.Request, s *Subject) bool {
	return f(w, r, s)
}

// AuthConfig parameterises RequireAuth on values and seams, never on a
// consumer's own config or identity types.
//
// The zero value denies every request. That is deliberate: each field below
// fails toward less access when unset, so a middleware that was mounted but
// never configured returns 401 rather than admitting anonymous callers to the
// routes it was mounted to protect.
type AuthConfig struct {
	// Authenticator resolves the credential. A nil Authenticator denies every
	// request rather than passing them through — an unwired check that admits
	// everything is indistinguishable from a route that was never protected.
	Authenticator Authenticator

	// AcceptedTypes lists the Subject.AuthType values this mount admits, matched
	// by exact string. A subject whose type is absent is denied even though its
	// credential was valid, which is how one mount admits interactive sessions
	// while another admits only service credentials.
	//
	// Leaving it empty denies everything unless AcceptAnyType is set. An empty
	// list cannot mean "any": the same empty value would then be produced by a
	// caller who meant to list types and by one who forgot, and only one of those
	// wants a mount that admits service keys on a route intended for sessions.
	AcceptedTypes []string

	// AcceptAnyType admits any type the Authenticator accepted, for a mount that
	// genuinely only requires a valid credential.
	//
	// Setting it alongside a non-empty AcceptedTypes is a contradiction and denies
	// every request: the two fields disagree about whether the listed types are
	// the whole set, and honouring either reading would silently discard the
	// other's intent.
	AcceptAnyType bool

	// Gates run in order after the type check passes. The first to deny ends the
	// request; a later gate does not run and cannot see the scopes an earlier one
	// appended, so a gate that depends on another's grants must be ordered after
	// it.
	Gates []Gate

	// OnDeny observes a denial RequireAuth itself made — no authenticator, an
	// unaccepted or empty credential, or a gate that denied. It cannot write to
	// the response, so an observer cannot turn a denial into a reply. It is not
	// called for a denial a gate wrote itself; a gate that needs to be observed
	// reports its own.
	OnDeny func(r *http.Request, reason string, err error)
}

// Denial reasons passed to AuthConfig.OnDeny.
const (
	DenyUnconfigured = "unconfigured"  // no Authenticator, or the type fields contradict
	DenyNoCredential = "no_credential" // the Authenticator returned an error
	DenyEmptySubject = "empty_subject" // accepted with no Subject.ID
	DenyAuthType     = "auth_type"     // valid credential, type not accepted here
	DenyGate         = "gate"          // a Gate refused admission
)

// RequireAuth authenticates a request, admits it through the configured gates,
// and stamps the resulting subject onto the request context via SetAuthContext
// so downstream handlers read it through ExtractUserID/ExtractScopes rather than
// re-parsing the credential.
//
// The stamp happens LAST, once every check has passed. Nothing downstream ever
// observes a context stamped for a request that was then refused, so
// IsAuthenticated answering true is sufficient on its own — a handler need not
// re-check what admitted the caller.
func RequireAuth(cfg AuthConfig) func(http.Handler) http.Handler {
	// A configuration that cannot admit anyone is settled once here rather than
	// per request: the fields are read-only for the life of the mount, and a
	// mount that denies unconditionally should say so at the same place every
	// time regardless of what a request carries.
	unconfigured := cfg.Authenticator == nil ||
		(cfg.AcceptAnyType && len(cfg.AcceptedTypes) > 0) ||
		(!cfg.AcceptAnyType && len(cfg.AcceptedTypes) == 0)

	deny := func(w http.ResponseWriter, r *http.Request, reason string, err error, status int) {
		if cfg.OnDeny != nil {
			cfg.OnDeny(r, reason, err)
		}
		http.Error(w, http.StatusText(status), status)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if unconfigured {
				deny(w, r, DenyUnconfigured, nil, http.StatusUnauthorized)
				return
			}

			subject, err := cfg.Authenticator.Authenticate(r)
			if err != nil {
				deny(w, r, DenyNoCredential, err, http.StatusUnauthorized)
				return
			}
			if subject.ID == "" {
				deny(w, r, DenyEmptySubject, nil, http.StatusUnauthorized)
				return
			}
			if !cfg.AcceptAnyType && !accepts(cfg.AcceptedTypes, subject.AuthType) {
				deny(w, r, DenyAuthType, nil, http.StatusUnauthorized)
				return
			}

			for _, gate := range cfg.Gates {
				// The gate writes its own denial, so it gets a writer that records
				// whether it did. A gate that returns false having written nothing
				// would otherwise end the request with an unwritten 200 and an empty
				// body — the one outcome a refused request must never produce.
				gw := &denyWriter{ResponseWriter: w}
				if gate.Admit(gw, r, &subject) {
					continue
				}
				if !gw.wrote {
					deny(w, r, DenyGate, nil, http.StatusForbidden)
				} else if cfg.OnDeny != nil {
					cfg.OnDeny(r, DenyGate, nil)
				}
				return
			}

			ctx := SetAuthContext(r.Context(), subject.ID, subject.Scopes, subject.AuthType)
			if subject.SessionID != "" {
				ctx = WithSessionID(ctx, subject.SessionID)
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// accepts reports whether authType is listed, by exact match.
func accepts(accepted []string, authType string) bool {
	for _, a := range accepted {
		if a == authType {
			return true
		}
	}
	return false
}

// denyWriter records whether a Gate wrote a response, so RequireAuth can supply
// one when a gate refuses admission without writing. It tracks only that a write
// began; the gate remains the author of whatever it did write.
type denyWriter struct {
	http.ResponseWriter
	wrote bool
}

func (d *denyWriter) WriteHeader(status int) {
	d.wrote = true
	d.ResponseWriter.WriteHeader(status)
}

func (d *denyWriter) Write(b []byte) (int, error) {
	d.wrote = true
	return d.ResponseWriter.Write(b)
}
