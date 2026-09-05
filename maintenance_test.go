package weft

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func maintenanceProbe(t *testing.T, cfg MaintenanceConfig, path, remote string) (int, string, bool) {
	t.Helper()
	reached := false
	h := Maintenance(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(200)
	}))
	r := httptest.NewRequest("GET", path, nil)
	if remote != "" {
		r.RemoteAddr = remote + ":1234"
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code, w.Body.String(), reached
}

// Liveness paths stay reachable while the gate is closed: hiding them makes an
// intentional maintenance window look identical to an outage to whatever watches.
func TestMaintenanceLetsHealthProbesThrough(t *testing.T) {
	for _, p := range []string{"/heartbeat", "/health"} {
		if code, _, reached := maintenanceProbe(t, MaintenanceConfig{Enabled: true}, p, ""); !reached || code != 200 {
			t.Errorf("%s was gated: code=%d reached=%v", p, code, reached)
		}
	}
}

func TestMaintenanceGatesOrdinaryTraffic(t *testing.T) {
	code, body, reached := maintenanceProbe(t, MaintenanceConfig{Enabled: true, Reason: "upgrading"}, "/dashboard", "")
	if reached || code != 503 {
		t.Fatalf("gate did not close: code=%d reached=%v", code, reached)
	}
	if !strings.Contains(body, "upgrading") {
		t.Errorf("reason not shown to the caller: %q", body)
	}
}

// An EMPTY allow-list must admit nobody. The dangerous reading is the other one:
// treating "unset" as "everyone", which turns a missing config value into an
// open door precisely when the gate is meant to be closed.
func TestEmptyAllowListAdmitsNobody(t *testing.T) {
	if _, _, reached := maintenanceProbe(t, MaintenanceConfig{Enabled: true}, "/x", "203.0.113.7"); reached {
		t.Error("an empty AllowedIPs admitted a caller")
	}
}

func TestAllowListAdmitsByAddressAndCIDR(t *testing.T) {
	cfg := MaintenanceConfig{Enabled: true, AllowedIPs: []string{"203.0.113.7", "198.51.100.0/24"}}
	for _, ip := range []string{"203.0.113.7", "198.51.100.42"} {
		if _, _, reached := maintenanceProbe(t, cfg, "/x", ip); !reached {
			t.Errorf("allow-listed %s was gated", ip)
		}
	}
	if _, _, reached := maintenanceProbe(t, cfg, "/x", "203.0.113.8"); reached {
		t.Error("a non-listed address was admitted")
	}
}

// API callers get a machine-readable refusal; browsers get the page. A JSON
// client handed HTML sees a parse error instead of the actual reason.
func TestMaintenanceAnswersInTheCallersFormat(t *testing.T) {
	_, body, _ := maintenanceProbe(t, MaintenanceConfig{Enabled: true, Reason: "db upgrade"}, "/api/v1/things", "")
	if !strings.Contains(body, `"error":"maintenance"`) || !strings.Contains(body, "db upgrade") {
		t.Errorf("API path did not get JSON: %q", body)
	}
	_, html, _ := maintenanceProbe(t, MaintenanceConfig{Enabled: true}, "/dashboard", "")
	if !strings.Contains(html, "<html") {
		t.Errorf("browser path did not get HTML: %q", html)
	}
}

// The reason is operator-supplied text rendered into a page, so it must not be
// able to become markup.
func TestReasonCannotInjectMarkup(t *testing.T) {
	_, body, _ := maintenanceProbe(t,
		MaintenanceConfig{Enabled: true, Reason: `<script>alert(1)</script>`}, "/dashboard", "")
	if strings.Contains(body, "<script>") {
		t.Errorf("reason was rendered as markup: %q", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("reason was not escaped into the page: %q", body)
	}
}

// With the gate off and no window seam wired, traffic flows.
func TestDisabledGateIsTransparent(t *testing.T) {
	if code, _, reached := maintenanceProbe(t, MaintenanceConfig{}, "/dashboard", ""); !reached || code != 200 {
		t.Errorf("a disabled gate blocked traffic: code=%d reached=%v", code, reached)
	}
}
