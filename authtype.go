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
	AuthTypeDev = "dev"
)
