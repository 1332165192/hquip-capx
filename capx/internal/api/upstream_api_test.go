package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hquip/capx/internal/mobilevpn"
)

func TestUpstreamAPIRejectsInvalidAndDirectRequests(t *testing.T) {
	s, _ := captureTransportServer(t)
	for _, body := range []string{`{`, `{"enabled":true,"url":"http://user:secret@127.0.0.1:8080"}`, `{"enabled":true,"url":"http://remote.invalid:8080"}`, `{"enabled":true,"url":"http://127.0.0.1:8080","unexpected":1}`} {
		w := httptest.NewRecorder()
		s.proxyUpstream(w, httptest.NewRequest("POST", "/api/proxy/upstream", strings.NewReader(body)))
		if w.Code == 200 || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("invalid config accepted or leaked: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	s.proxyUpstream(w, httptest.NewRequest("POST", "/api/proxy/upstream", strings.NewReader(`{"enabled":true,"url":"http://127.0.0.1:8080"}`)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"enabled":true`) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	for _, handler := range []http.HandlerFunc{s.intruderRun, s.turboRun} {
		w = httptest.NewRecorder()
		handler(w, httptest.NewRequest("POST", "/api/test", strings.NewReader("{}")))
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("direct path did not reject upstream: %d", w.Code)
		}
	}
}

func TestUpstreamAPICredentialsNeverReturnedAndVPNChangeGuard(t *testing.T) {
	s, _ := captureTransportServer(t)
	secret := "fixture-private-proxy-password"
	body := `{"enabled":true,"url":"http://127.0.0.1:18081","username":"fixture-user","password":"` + secret + `"}`
	response := httptest.NewRecorder()
	s.proxyUpstream(response, httptest.NewRequest("POST", "/api/proxy/upstream", strings.NewReader(body)))
	if response.Code != 200 || strings.Contains(response.Body.String(), secret) || strings.Contains(response.Body.String(), "fixture-user") || !strings.Contains(response.Body.String(), `"has_credentials":true`) || !strings.Contains(response.Body.String(), `"websocket":true`) || !strings.Contains(response.Body.String(), `"raw_vpn_udp":false`) {
		t.Fatalf("credential/capability response incorrect: %d %s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	s.proxyUpstream(response, httptest.NewRequest("POST", "/api/proxy/upstream", strings.NewReader(`{"enabled":true,"url":"http://127.0.0.1:18081","keep_credentials":true}`)))
	if response.Code != 200 || strings.Contains(response.Body.String(), secret) {
		t.Fatal("credential retention leaked or failed", response.Body.String())
	}
	response = httptest.NewRecorder()
	s.proxyUpstream(response, httptest.NewRequest("POST", "/api/proxy/upstream", strings.NewReader(`{"enabled":true,"url":"http://127.0.0.1:18081"} {"unexpected":1}`)))
	if response.Code != 400 {
		t.Fatal("trailing JSON accepted")
	}
	gateway := mobilevpn.New(t.TempDir(), nil)
	s.SetMobileVPN(gateway)
	if _, err := gateway.Start(mobilevpn.Options{Routes: []string{"127.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	defer gateway.Stop()
	response = httptest.NewRecorder()
	s.proxyUpstream(response, httptest.NewRequest("POST", "/api/proxy/upstream", strings.NewReader(`{"enabled":false,"url":""}`)))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "stop the mobile VPN") {
		t.Fatal("live raw sockets retained during route change", response.Code, response.Body.String())
	}
}
