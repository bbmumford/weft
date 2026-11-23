/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package weft

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// MaintenanceConfig parameterises the maintenance gate on VALUES, not on a
// consumer's config struct: an app-wide settings type would drag whatever else
// it carries — including identity fields — into this package.
type MaintenanceConfig struct {
	// Enabled serves the maintenance response to everyone not allow-listed.
	Enabled bool
	// Reason is shown to the caller. Empty is fine.
	Reason string
	// AllowedIPs bypass the gate. Entries are plain addresses or CIDR blocks.
	AllowedIPs []string

	// WindowCheck reports an externally scheduled maintenance window. It is a
	// SEAM, not a transport: the caller owns the wire types and the service it
	// asks, so this package needs no protocol dependency of its own. nil
	// disables the check entirely.
	//
	// It is polled in the background rather than called per request, because a
	// gate that makes a network call on every request fails whenever the thing
	// it asks is the thing that is down.
	WindowCheck func(ctx context.Context) (open bool, reason string)

	// PollInterval controls how often WindowCheck runs. Zero means one minute.
	PollInterval time.Duration

	// TrustedProxies and IPHeaderOrder resolve the caller's address for the
	// allow-list. They are REQUIRED to be set deliberately when AllowedIPs is
	// non-empty: with no trusted proxy the address comes from the connection,
	// which is the only source a caller cannot forge.
	TrustedProxies []string
	IPHeaderOrder  []string
}

type maintenanceWindow struct {
	mu     sync.RWMutex
	open   bool
	reason string
}

func (c *maintenanceWindow) set(open bool, reason string) {
	c.mu.Lock()
	c.open, c.reason = open, reason
	c.mu.Unlock()
}

func (c *maintenanceWindow) get() (bool, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.open, c.reason
}

// Maintenance gates a handler behind a maintenance response, letting through
// health probes and allow-listed addresses.
//
// Liveness paths are exempt: a gate that hides them makes an intentional
// maintenance window indistinguishable from an outage to whatever is watching.
func Maintenance(cfg MaintenanceConfig) func(http.Handler) http.Handler {
	window := &maintenanceWindow{}

	if cfg.WindowCheck != nil {
		interval := cfg.PollInterval
		if interval <= 0 {
			interval = time.Minute
		}
		go func() {
			open, reason := cfg.WindowCheck(context.Background())
			window.set(open, reason)
			for range time.Tick(interval) {
				open, reason := cfg.WindowCheck(context.Background())
				window.set(open, reason)
			}
		}()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/heartbeat" || r.URL.Path == "/health" {
				next.ServeHTTP(w, r)
				return
			}
			if maintenanceAllows(r, cfg) {
				next.ServeHTTP(w, r)
				return
			}
			if cfg.Enabled {
				serveMaintenance(w, r, cfg.Reason)
				return
			}
			if open, reason := window.get(); open {
				serveMaintenance(w, r, reason)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// maintenanceAllows reports whether the caller's address is allow-listed. An
// empty list allows nobody — an allow-list that admits everyone when unset would
// turn a missing config value into an open door.
func maintenanceAllows(r *http.Request, cfg MaintenanceConfig) bool {
	if len(cfg.AllowedIPs) == 0 {
		return false
	}
	clientIP := clientIPForMaintenance(r, cfg)
	if clientIP == "" {
		return false
	}
	ip := net.ParseIP(clientIP)
	for _, allowed := range cfg.AllowedIPs {
		if strings.Contains(allowed, "/") {
			if _, network, err := net.ParseCIDR(allowed); err == nil && ip != nil && network.Contains(ip) {
				return true
			}
			continue
		}
		if clientIP == allowed {
			return true
		}
	}
	return false
}

func serveMaintenance(w http.ResponseWriter, r *http.Request, reason string) {
	w.Header().Set("Retry-After", "3600")
	accept := r.Header.Get("Accept")
	if strings.Contains(r.URL.Path, "/api/") || strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"error":"maintenance","reason":%q,"path":%q}`, reason, r.URL.Path)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprintf(w, maintenancePage, htmlEscape(reason))
}

const maintenancePage = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Maintenance</title><style>
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#0f1115;color:#e6e8eb;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:2rem}
main{max-width:32rem;text-align:center}h1{font-size:1.5rem;margin:0 0 .75rem}
p{color:#9aa3ad;line-height:1.6;margin:0}</style></head>
<body><main><h1>Down for maintenance</h1><p>%s</p></main></body></html>`

// htmlEscape keeps a caller-supplied reason from becoming markup in the page.
func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return r.Replace(s)
}

// clientIPForMaintenance resolves the caller's address through weft's own
// client-IP rules, so the allow-list and the rest of the stack agree on who the
// caller is. An unparseable trusted-proxy entry is DROPPED rather than treated
// as trusted: a typo must narrow the trusted set, never widen it.
func clientIPForMaintenance(r *http.Request, cfg MaintenanceConfig) string {
	prefixes := make([]netip.Prefix, 0, len(cfg.TrustedProxies))
	for _, p := range cfg.TrustedProxies {
		if pfx, err := netip.ParsePrefix(p); err == nil {
			prefixes = append(prefixes, pfx)
			continue
		}
		// A bare address is a /32 or /128 trusted hop.
		if addr, err := netip.ParseAddr(p); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}
	return ClientIPFromRequest(r, prefixes, cfg.IPHeaderOrder)
}
