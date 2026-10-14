package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHostAllowed(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:19091": true,
		"localhost:19091": true,
		"[::1]:19091":     true,
		"127.0.0.1":       true,
		"evil.com:19091":  false, // DNS name => rebinding vector
		"example.com":     false,
		"":                false,
	}
	for host, want := range cases {
		if got := hostAllowed(host); got != want {
			t.Errorf("hostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestOriginAllowed(t *testing.T) {
	cases := []struct {
		origin, host string
		want         bool
	}{
		{"http://127.0.0.1:19091", "127.0.0.1:19091", true},
		{"http://localhost:19091", "127.0.0.1:19091", true},  // loopback family, same port
		{"http://127.0.0.1:18080", "127.0.0.1:19091", false}, // port mismatch
		{"http://evil.com", "127.0.0.1:19091", false},        // foreign origin
		{"null", "127.0.0.1:19091", false},
	}
	for _, c := range cases {
		if got := originAllowed(c.origin, c.host); got != c.want {
			t.Errorf("originAllowed(%q,%q) = %v, want %v", c.origin, c.host, got, c.want)
		}
	}
}

func TestIsActiveOp(t *testing.T) {
	active := []struct{ m, p string }{
		{"POST", "/api/hook/attach"},
		{"POST", "/api/inline/send"},
		{"POST", "/api/inline/rules"},
		{"DELETE", "/api/rules/rule-1"},
		{"POST", "/api/mem/mem-1/write"},
		{"POST", "/api/mem/mem-1/freeze"},
		{"POST", "/api/scripts"},
		{"POST", "/api/proxy/ws/replay"},
	}
	for _, c := range active {
		if !isActiveOp(c.m, c.p) {
			t.Errorf("isActiveOp(%q,%q) = false, want true", c.m, c.p)
		}
	}
	passive := []struct{ m, p string }{
		{"GET", "/api/flows"},
		{"GET", "/api/rules"},
		{"POST", "/api/repeater/send"},
		{"POST", "/api/captures"},
		{"GET", "/api/mem/mem-1/results"},
		{"POST", "/api/policy"}, // policy toggle must not be self-gated
		{"POST", "/api/setup/prepare"},
		{"POST", "/api/setup/browser"},
		{"POST", "/api/setup/ca/install"},
		{"POST", "/api/setup/sysproxy/on"},
		{"POST", "/api/setup/sysproxy/off"},
		{"POST", "/api/wxhook/capture/start"},
		{"POST", "/api/proxy/transparent/start"},
	}
	for _, c := range passive {
		if isActiveOp(c.m, c.p) {
			t.Errorf("isActiveOp(%q,%q) = true, want false", c.m, c.p)
		}
	}
}

// newTestGuard returns a guard with a fixed token and no rate limiting in the
// way (large burst), auth on, active off.
func newTestGuard() *guard {
	g := &guard{token: "secret", authOn: true, auditCap: 100, rlRate: 1e6, rlBurst: 1e6}
	g.rlTokens = g.rlBurst
	return g
}

func TestWrapRejectsMissingToken(t *testing.T) {
	g := newTestGuard()
	h := g.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	req := httptest.NewRequest("GET", "http://127.0.0.1:19091/api/flows", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", rec.Code)
	}

	req = httptest.NewRequest("GET", "http://127.0.0.1:19091/api/flows", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("valid token: got %d, want 200", rec.Code)
	}
}

func TestDownloadAuthAcceptsQueryTokenAndPlain401(t *testing.T) {
	g := newTestGuard()
	h := g.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "http://127.0.0.1:19091/api/proxy/ca", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth ca: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "application/json") {
		t.Fatalf("unauth download must not be JSON, got %q / %s", ct, rec.Body.String())
	}

	req = httptest.NewRequest("GET", "http://127.0.0.1:19091/api/proxy/ca?token=secret", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("query token: got %d, want 200", rec.Code)
	}
}

func TestPortScopedAuthCookie(t *testing.T) {
	g := newTestGuard()
	h := g.setAuthCookie(g.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })))

	req := httptest.NewRequest("GET", "http://127.0.0.1:19095/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Result().Cookies()[0].Name != "capx_token_19095" {
		t.Fatalf("cookie name = %q, want capx_token_19095", rec.Result().Cookies()[0].Name)
	}

	req = httptest.NewRequest("GET", "http://127.0.0.1:19095/api/flows", nil)
	req.AddCookie(&http.Cookie{Name: "capx_token_19091", Value: "secret"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong port cookie: got %d, want 401", rec.Code)
	}

	req = httptest.NewRequest("GET", "http://127.0.0.1:19095/api/flows", nil)
	req.AddCookie(&http.Cookie{Name: "capx_token_19095", Value: "secret"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("right port cookie: got %d, want 200", rec.Code)
	}
}

func TestWrapRejectsDNSRebinding(t *testing.T) {
	g := newTestGuard()
	h := g.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	req := httptest.NewRequest("GET", "http://127.0.0.1:19091/api/flows", nil)
	req.Host = "evil.com" // rebound DNS name
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rebinding host: got %d, want 403", rec.Code)
	}
}

func TestWrapGatesActiveOps(t *testing.T) {
	g := newTestGuard() // active off
	h := g.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	mk := func() *http.Request {
		req := httptest.NewRequest("POST", "http://127.0.0.1:19091/api/hook/attach", nil)
		req.Header.Set("Authorization", "Bearer secret")
		return req
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, mk())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("active op with active off: got %d, want 403", rec.Code)
	}

	g.SetActive(true, "test")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, mk())
	if rec.Code != 200 {
		t.Fatalf("active op with active on: got %d, want 200", rec.Code)
	}
	// The denied + allowed attempts should both be audited.
	if n := len(g.recentAudit()); n < 2 {
		t.Fatalf("audit entries = %d, want >= 2", n)
	}
}
