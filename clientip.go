package weft

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// DefaultTrustedEdgeCIDRs is the default set of prefixes a request's RemoteAddr
// must fall inside before its forwarded-IP headers are trusted. It covers the
// common private-edge/loopback origins; a deployment behind a different proxy
// passes its own prefixes to ClientIPFromRequest. Outside this set the headers
// are treated as spoofable and RemoteAddr wins.
var DefaultTrustedEdgeCIDRs = []string{
	"fdaa::/16", // private 6PN edge
	"127.0.0.1/32",
	"::1/128",
}

// DefaultTrustedHeaderOrder is the order forwarded client-IP headers are
// consulted; the first with a non-empty value wins. A deployment that must read
// a provider header first (e.g. CF-Connecting-IP) supplies its own order.
// X-Forwarded-For is always read last-entry-first regardless of position.
var DefaultTrustedHeaderOrder = []string{
	"Fly-Client-IP",
	"X-Real-IP",
	"X-Forwarded-For",
}

// ClientIPFromRequest is the trusted-proxy-aware client-IP extractor for rate
// limiting, audit logging, and any site identifying the remote caller.
//
// Trust model: parse RemoteAddr (the TCP/UDP peer); honour forwarded-IP headers
// ONLY when RemoteAddr is inside trustedPrefixes (the upstream proxy controls
// them there — outside, a direct client could forge them). headerOrder selects
// which headers and in what precedence; the first non-empty wins. For
// X-Forwarded-For, take the LAST entry (the immediately-upstream trusted proxy's
// view), never the first (which an untrusted client can write). The chosen value
// must parse as an IP address (netip.ParseAddr) and is returned in its canonical
// form, an IPv4-mapped IPv6 address as IPv4; a value that does not parse is not
// an address and RemoteAddr wins, so no header text reaches a rate-limit key or
// an allowlist as a caller address. A nil/empty headerOrder disables header
// extraction (RemoteAddr only). Falls back to RemoteAddr on any miss.
func ClientIPFromRequest(r *http.Request, trustedPrefixes []netip.Prefix, headerOrder []string) string {
	if r == nil {
		return ""
	}
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	hostAddr, hostErr := netip.ParseAddr(host)

	if hostErr == nil && isTrustedPrefix(hostAddr, trustedPrefixes) {
		for _, name := range headerOrder {
			v := r.Header.Get(name)
			if v == "" {
				continue
			}
			if strings.EqualFold(name, "X-Forwarded-For") {
				parts := strings.Split(v, ",")
				v = parts[len(parts)-1]
			}
			if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				return a.Unmap().String()
			}
			return host
		}
	}
	return host
}

// isTrustedPrefix reports whether ip falls inside any of prefixes.
func isTrustedPrefix(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTrustedPrefixes converts CIDR strings to netip.Prefix values, dropping
// (and logging) malformed entries. Empty input returns nil — callers treat nil
// as "no trust set" and disable header extraction. A deployment's declared edge
// prefixes are read with ParseTrustedEdgePrefixes, which refuses instead.
func ParseTrustedPrefixes(s []string) []netip.Prefix {
	if len(s) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(s))
	for _, raw := range s {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			log.Printf("weft/clientip: dropping malformed trusted-proxy CIDR %q: %v", raw, err)
			continue
		}
		out = append(out, p)
	}
	return out
}

// ErrTrustedEdgePrefix is returned by ParseTrustedEdgePrefixes for a prefix that
// does not parse.
var ErrTrustedEdgePrefix = errors.New("weft/clientip: malformed trusted edge prefix")

// ParseTrustedEdgePrefixes converts a deployment's declared trusted edge
// prefixes to netip.Prefix values for ClientIPFromRequest, refusing the whole
// set when any entry does not parse (ErrTrustedEdgePrefix), so a boot that reads
// a mistyped prefix stops rather than trusting a narrower or wider set than the
// one declared. An empty set is no trust set: header extraction is off.
func ParseTrustedEdgePrefixes(s []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(s))
	for _, raw := range s {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrTrustedEdgePrefix, raw, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// DefaultTrustedPrefixes is the parsed DefaultTrustedEdgeCIDRs, memoised once per
// process. Exposed so a caller building its own extractor reuses the same set.
var DefaultTrustedPrefixes = ParseTrustedPrefixes(DefaultTrustedEdgeCIDRs)

// DefaultClientIP wraps ClientIPFromRequest with the default trust set and header
// order — the standard extractor for audit capture and callers wanting no extra
// configuration.
func DefaultClientIP(r *http.Request) string {
	return ClientIPFromRequest(r, DefaultTrustedPrefixes, DefaultTrustedHeaderOrder)
}
