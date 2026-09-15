/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package weft

// Canonical auth-type labels — the vocabulary for the authType argument of
// SetAuthContext and the value GetAuthType reads back. They name HOW a caller
// authenticated, never who it is or what it may reach.
//
// ⚠ THE VALUES ARE THE CONTRACT, NOT THE IDENTIFIERS. Comparison is exact
// string match, so a producer and a consumer agree only if their strings agree
// byte for byte — and drift rejects VALID auth with a 401 rather than failing
// loudly at the seam. These values are therefore fixed and must not be
// "tidied": AuthTypeAPIKey stays "api-key" (hyphen, not underscore, not
// "apikey"), and every label stays lowercase.
//
// Anything producing an auth type must use these constants rather than a
// literal, so a typo is a compile error instead of a runtime denial.
const (
	// AuthTypeSession — an interactive session cookie.
	AuthTypeSession = "session"
	// AuthTypeMTLS — a mutually-authenticated TLS peer, i.e. a service.
	AuthTypeMTLS = "mtls"
	// AuthTypeAPIKey — a long-lived issued key, typically service-to-service.
	AuthTypeAPIKey = "api-key"
	// AuthTypeBearer — a bearer token presented in the Authorization header.
	AuthTypeBearer = "bearer"
	// AuthTypeDev — a development-only bypass. A production build must never
	// admit it; treat its presence in a live path as a defect.
	//
	// ⚠ NOT AuthTypeDevice. This one is the bypass; that one is an enrolled
	// device's credential and is admitted in production. The identifiers differ
	// by three characters and this is the prefix of that, so an editor offers
	// both — reaching for the wrong one here admits a bypass on a live path.
	AuthTypeDev = "dev"
	// AuthTypeDevice — an enrolled device's own credential. It authenticates a
	// device against the partition it was enrolled into, which is why a reader
	// asking "is this a service rather than a person" answers yes for it: a
	// device holds no membership of its own, so treating it as interactive sends
	// it to a membership lookup that has no row to find and refuses every call.
	//
	// ⚠ NOT AuthTypeDev. See the warning there.
	AuthTypeDevice = "device"

	// AuthTypeUnknown is what GetAuthType reports when NOTHING stamped a type.
	// It is a sentinel for "not authenticated here", never a credential: no
	// Authenticator may return it and no AcceptedTypes list may contain it,
	// because admitting it would admit every unstamped request.
	//
	// It is named so a caller distinguishing "no type" from a real one compares
	// against this rather than a literal — the comparison is easy to omit, and
	// omitting it forwards "unknown" onward as though it were a credential.
	AuthTypeUnknown = "unknown"
)
