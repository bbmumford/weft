package weft

import (
	"errors"
	"net/netip"
	"testing"
)

// A deployment's declared edge prefixes are refused whole when any entry does
// not parse, so a mistyped prefix stops the boot instead of being dropped.
func TestParseTrustedEdgePrefixesRefusesAMalformedPrefix(t *testing.T) {
	for _, set := range [][]string{{"fdaa::/16", "10.0.0.0/33"}, {"not-a-prefix"}, {"fdaa::/16", ""}} {
		if got, err := ParseTrustedEdgePrefixes(set); !errors.Is(err, ErrTrustedEdgePrefix) || got != nil {
			t.Errorf("ParseTrustedEdgePrefixes(%q) = %v, %v; want nil, ErrTrustedEdgePrefix", set, got, err)
		}
	}
	got, err := ParseTrustedEdgePrefixes([]string{" fdaa:0:1::/48 ", "127.0.0.1/32", "10.1.2.3/8"})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("fdaa:0:1::/48"), netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("10.0.0.0/8")}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("prefix %d = %v, want %v", i, got[i], want[i])
		}
	}
	if got, err := ParseTrustedEdgePrefixes(nil); err != nil || len(got) != 0 {
		t.Errorf("an empty set = %v, %v; want no prefixes and no error", got, err)
	}
}
