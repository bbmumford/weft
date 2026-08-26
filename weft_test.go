package weft

import (
	"os"
	"testing"
	"time"
)

func TestGenerateIDs(t *testing.T) {
	u, err := GenerateCondensedUUID()
	if err != nil || u == "" {
		t.Fatalf("GenerateCondensedUUID: %q %v", u, err)
	}
	a, err := GenerateAlphanumericID(12)
	if err != nil || len(a) != 12 {
		t.Fatalf("GenerateAlphanumericID(12)=%q (len %d) %v", a, len(a), err)
	}
	if u2, _ := GenerateCondensedUUID(); u2 == u {
		t.Fatal("two UUIDs must differ")
	}
}

func TestDBTimeRoundTrip(t *testing.T) {
	now := time.Date(2026, 8, 26, 10, 30, 0, 0, time.UTC)
	s := DBFormat(now)
	got, err := DBParse(s)
	if err != nil {
		t.Fatalf("DBParse(%q): %v", s, err)
	}
	if !got.Equal(now) {
		t.Fatalf("roundtrip: %v != %v", got, now)
	}
}

func TestRequireEnvDefault(t *testing.T) {
	if got := RequireEnvDefault("WEFT_NOT_SET_XYZ", "fallback"); got != "fallback" {
		t.Fatalf("absent env → default; got %q", got)
	}
	t.Setenv("WEFT_SET_XYZ", "value")
	if got := RequireEnvDefault("WEFT_SET_XYZ", "fallback"); got != "value" {
		t.Fatalf("present env → value; got %q", got)
	}
	os.Unsetenv("WEFT_SET_XYZ")
}

func TestValidateRedirect(t *testing.T) {
	// relative allowed
	if _, ok := ValidateRedirect("/dashboard", nil, true); !ok {
		t.Fatal("relative redirect should be allowed when allowRelative=true")
	}
	// relative rejected when not allowed
	if _, ok := ValidateRedirect("/dashboard", nil, false); ok {
		t.Fatal("relative redirect must be rejected when allowRelative=false")
	}
	// off-host absolute rejected
	if _, ok := ValidateRedirect("https://evil.example.com/x", []string{"trusted.example.com"}, false); ok {
		t.Fatal("off-allowlist host must be rejected (open-redirect guard)")
	}
}
