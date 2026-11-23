package weft

import "testing"

// A relative target a browser would resolve to another host is refused: a
// browser reads '\' as '/' and drops tabs, newlines and other control
// characters, so each of these becomes "//evil.example" in the Location it
// follows. The paths that stay on the site keep passing.
func TestValidateRedirectRefusesAPathABrowserReadsAsAnotherHost(t *testing.T) {
	for _, target := range []string{
		`/\evil.example`,
		`/\\evil.example`,
		"/\t/evil.example",
		"/\n/evil.example",
		"/\r/evil.example",
		"/\x00/evil.example",
		"/\x7f/evil.example",
		`/x\..\evil`,
	} {
		if got, ok := ValidateRedirect(target, nil, true); ok {
			t.Errorf("ValidateRedirect(%q) = %q, true; a browser resolves it off the site", target, got)
		}
	}
	for target, want := range map[string]string{
		"/dashboard":          "/dashboard",
		"/a/b?c=d":            "/a/b?c=d",
		"/a/b#frag":           "/a/b",
		"/search?q=%2F%2Fx":   "/search?q=%2F%2Fx",
		"/files/name%20x.txt": "/files/name%20x.txt",
	} {
		if got, ok := ValidateRedirect(target, nil, true); !ok || got != want {
			t.Errorf("ValidateRedirect(%q) = %q, %v; want %q, true", target, got, ok, want)
		}
	}
}
