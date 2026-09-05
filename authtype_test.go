package weft

import "testing"

// The VALUES are the contract: comparison is exact string match, so a drift
// between a producer and a consumer rejects valid auth with a 401 instead of
// failing at the seam. This pins them so a later "tidy" (api_key, apikey,
// APIKey) is a test failure rather than a production denial.
func TestAuthTypeValuesArePinned(t *testing.T) {
	for _, tc := range []struct{ got, want, name string }{
		{AuthTypeSession, "session", "AuthTypeSession"},
		{AuthTypeMTLS, "mtls", "AuthTypeMTLS"},
		{AuthTypeAPIKey, "api-key", "AuthTypeAPIKey"},
		{AuthTypeBearer, "bearer", "AuthTypeBearer"},
		{AuthTypeDev, "dev", "AuthTypeDev"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q — the value is the wire contract, not the identifier",
				tc.name, tc.got, tc.want)
		}
	}
}

// The labels must stay distinct, or two auth methods collapse into one and an
// allowed-type list admits a method it never named.
func TestAuthTypesAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for label, name := range map[string]string{
		AuthTypeSession: "AuthTypeSession",
		AuthTypeMTLS:    "AuthTypeMTLS",
		AuthTypeAPIKey:  "AuthTypeAPIKey",
		AuthTypeBearer:  "AuthTypeBearer",
		AuthTypeDev:     "AuthTypeDev",
	} {
		if prev, dup := seen[label]; dup {
			t.Errorf("%s and %s share the value %q", prev, name, label)
		}
		seen[label] = name
	}
}

// The constants are the vocabulary SetAuthContext stamps and GetAuthType reads,
// so a round trip through the carriers must return the same label.
func TestAuthTypeRoundTripsThroughTheCarrier(t *testing.T) {
	for _, at := range []string{AuthTypeSession, AuthTypeMTLS, AuthTypeAPIKey, AuthTypeBearer, AuthTypeDev} {
		ctx := SetAuthContext(t.Context(), "user-1", nil, at)
		if got := GetAuthType(ctx); got != at {
			t.Errorf("round trip of %q returned %q", at, got)
		}
	}
}
