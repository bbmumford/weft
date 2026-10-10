package weft

import (
	"net"
	"net/http/httptest"
	"testing"
)

// defaultClientIPCase is one request shape and the address the shared rule must
// read from it. The cases are the shapes the surfaces calling DefaultClientIP
// actually see: a request from the platform proxy carrying a forwarded chain, and
// a request straight off the internet carrying a chain it wrote itself.
type defaultClientIPCase struct {
	name       string
	remoteAddr string
	headers    map[string]string
	want       string
	why        string
}

// defaultClientIPCases is the fixture. DefaultClientIP takes no arguments, so a
// caller cannot pass its own trust set and these defaults are the whole rule for
// every surface that reads the caller through it: mcp.orbtr.io's credential
// validation, app.orbtr.io's two switch-context dials, and anything judging a
// request by address. Each case states what breaks if the rule moves.
var defaultClientIPCases = []defaultClientIPCase{
	{
		name:       "a chain from inside the edge reads its last entry",
		remoteAddr: "127.0.0.1:44100",
		headers:    map[string]string{"X-Forwarded-For": "9.9.9.9, 8.8.8.8, 10.0.0.5"},
		want:       "10.0.0.5",
		why: "the last entry is the view of the proxy immediately upstream; the " +
			"earlier entries are whatever the caller before it wrote",
	},
	{
		name:       "a provider header from inside the edge outranks the chain",
		remoteAddr: "127.0.0.1:44100",
		headers:    map[string]string{"Fly-Client-IP": "203.0.113.7", "X-Forwarded-For": "9.9.9.9"},
		want:       "203.0.113.7",
		why:        "Fly-Client-IP is first in the default order, and the platform proxy sets it",
	},
	{
		name:       "a forged chain from outside the edge is ignored",
		remoteAddr: "198.51.100.9:5555",
		headers:    map[string]string{"X-Forwarded-For": "10.0.0.5"},
		want:       "198.51.100.9",
		why: "a caller dialling directly is not inside the trusted prefixes, so its " +
			"header is spoofable and the peer address is the only fact about it",
	},
	{
		name:       "a forged provider header from outside the edge is ignored",
		remoteAddr: "198.51.100.9:5555",
		headers:    map[string]string{"Fly-Client-IP": "10.0.0.5"},
		want:       "198.51.100.9",
		why:        "the same holds for every header in the default order, not only the chain",
	},
	{
		name:       "a single-entry chain from inside the edge reads that entry",
		remoteAddr: "127.0.0.1:44100",
		headers:    map[string]string{"X-Forwarded-For": "203.0.113.9"},
		want:       "203.0.113.9",
		why:        "one hop is the common shape and must not fall back to the proxy's own address",
	},
	{
		name:       "no header reads the peer",
		remoteAddr: "127.0.0.1:44100",
		want:       "127.0.0.1",
		why:        "a request the proxy forwards without a client-IP header has only its peer",
	},
}

// TestDefaultClientIPReadsTheSharedRule drives the fixture. It is the positive
// leg: every case must read the address its row names.
func TestDefaultClientIPReadsTheSharedRule(t *testing.T) {
	for _, c := range defaultClientIPCases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remoteAddr
			for k, v := range c.headers {
				r.Header.Set(k, v)
			}
			if got := DefaultClientIP(r); got != c.want {
				t.Errorf("DefaultClientIP = %q, want %q — %s", got, c.want, c.why)
			}
		})
	}
}

// TestADirectCallerCannotChooseTheAddressItIsJudgedBy is the negative leg, stated
// as the property rather than as a row: whatever a caller outside the trusted
// prefixes puts in any header in the default order, the answer stays its peer
// address.
//
// Without this leg, widening DefaultTrustedEdgeCIDRs to a prefix the open
// internet falls inside, or reading the chain's first entry, would leave every
// caller of DefaultClientIP taking an attacker-supplied address while each
// caller's own tests still passed: an address allowlist admits whoever names a
// permitted one, and a rate-limit bucket is chosen by the caller it is meant to
// bound.
func TestADirectCallerCannotChooseTheAddressItIsJudgedBy(t *testing.T) {
	const peer = "198.51.100.9"
	forged := []string{"10.0.0.5", "127.0.0.1", "::1", "9.9.9.9, 10.0.0.5", "10.0.0.5, 9.9.9.9"}
	for _, header := range DefaultTrustedHeaderOrder {
		for _, value := range forged {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = peer + ":5555"
			r.Header.Set(header, value)
			if got := DefaultClientIP(r); got != peer {
				t.Errorf("%s: %s=%q read as %q, want the peer %q — a direct caller chose the address it is judged by",
					header, header, value, got, peer)
			}
		}
	}
}

// TestTheTrustedEdgeSetExcludesThePublicInternet checks the set the rule rests on
// rather than the rule's output, so a prefix that admits a public address is
// reported at the set instead of only through whichever case happens to use that
// address.
func TestTheTrustedEdgeSetExcludesThePublicInternet(t *testing.T) {
	if len(DefaultTrustedPrefixes) == 0 {
		t.Fatal("DefaultTrustedPrefixes is empty, so no forwarded header is ever read and every " +
			"caller reads as its proxy's address")
	}
	for _, public := range []string{"198.51.100.9", "203.0.113.1", "8.8.8.8", "2001:db8::1"} {
		r := httptest.NewRequest("GET", "/", nil)
		// net.JoinHostPort, not public+":5555": an IPv6 peer must arrive bracketed
		// or net.SplitHostPort refuses it, the address never parses, and the case
		// would pass on the unparsed-peer fallback instead of on the trust set.
		r.RemoteAddr = net.JoinHostPort(public, "5555")
		r.Header.Set("X-Forwarded-For", "10.0.0.5")
		if got := DefaultClientIP(r); got != public {
			t.Errorf("a peer at %s had its header read (got %q), so the default trusted set reaches "+
				"the public internet and the header is no longer the proxy's word", public, got)
		}
	}
}
