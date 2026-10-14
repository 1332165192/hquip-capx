package api

import (
	"mime"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/hquip/capx/internal/mobilevpn"
)

func TestMobileVPNAPISafeLifecycle(t *testing.T) {
	s := &Server{mobileVPN: mobilevpn.New(t.TempDir(), nil)}
	defer s.mobileVPN.Stop()
	w := httptest.NewRecorder()
	s.mobileVPNStart(w, httptest.NewRequest("POST", "/api/mobile/vpn/start", strings.NewReader(`{}`)))
	if w.Code != 409 || s.mobileVPN.Status().Running {
		t.Fatal("empty request implicitly redirected full phone")
	}
	w = httptest.NewRecorder()
	s.mobileVPNStart(w, httptest.NewRequest("POST", "/api/mobile/vpn/start", strings.NewReader(`{"routes":["127.0.0.0/8"],"packages":["com.example.fixture"]}`)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"running":true`) || strings.Contains(w.Body.String(), "PrivateKey") {
		t.Fatalf("start failed %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.mobileVPNConfig(w, httptest.NewRequest("GET", "/api/mobile/vpn/config", nil))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "IncludedApplications = com.example.fixture") {
		t.Fatal("bad private config download")
	}
	disposition, params, err := mime.ParseMediaType(w.Header().Get("Content-Disposition"))
	if err != nil || disposition != "attachment" || params["filename"] != "capx-phone.conf" {
		t.Fatalf("bad VPN config download filename: %q (%v)", w.Header().Get("Content-Disposition"), err)
	}
	// Android WireGuard uses the filename without .conf as the tunnel name.
	if !regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}\.conf$`).MatchString(params["filename"]) {
		t.Fatalf("VPN config filename is not an Android WireGuard tunnel name: %q", params["filename"])
	}
	w = httptest.NewRecorder()
	s.mobileVPNStop(w, httptest.NewRequest("POST", "/api/mobile/vpn/stop", nil))
	if w.Code != 200 || s.mobileVPN.Status().Running {
		t.Fatal("VPN stop failed")
	}
}

func TestMobileVPNPrivateConfigRequiresExistingAPIAuth(t *testing.T) {
	guard := newTestGuard()
	s := &Server{mobileVPN: mobilevpn.New("", nil)}
	if _, err := s.mobileVPN.Start(mobilevpn.Options{Routes: []string{"127.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	defer s.mobileVPN.Stop()
	handler := guard.wrap(http.HandlerFunc(s.mobileVPNConfig))
	req := httptest.NewRequest("GET", "http://127.0.0.1:19091/api/mobile/vpn/config", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "PrivateKey") {
		t.Fatal("private VPN config exposed without API authentication")
	}
	req.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated private config export failed")
	}
}
