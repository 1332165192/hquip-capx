package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hquip/capx/internal/mobile"
)

func TestMobileRejectsInvalidRequestsBeforeADB(t *testing.T) {
	s := &Server{mobile: mobile.New()}
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		body    string
		code    int
	}{
		{"use malformed", s.mobileUse, "{", http.StatusBadRequest},
		{"use empty", s.mobileUse, "", http.StatusBadRequest},
		{"stop malformed", s.mobileCaptureStop, "{", http.StatusBadRequest},
		{"stop invalid port", s.mobileCaptureStop, `{"proxy_port":-1}`, http.StatusBadRequest},
		{"tap missing y", s.mobileTap, `{"x":10}`, http.StatusBadRequest},
		{"tap missing locator", s.mobileTap, `{}`, http.StatusBadRequest},
		{"tap negative", s.mobileTap, `{"x":-1,"y":0}`, http.StatusBadRequest},
		{"start invalid port", s.mobileCaptureStart, `{"proxy_port":70000}`, http.StatusBadRequest},
		{"start no listener", s.mobileCaptureStart, `{"proxy_port":18080}`, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			tc.handler(rr, httptest.NewRequest(http.MethodPost, "/api/mobile/test", strings.NewReader(tc.body)))
			if rr.Code != tc.code {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.code, rr.Body.String())
			}
		})
	}
}

func TestMobileRejectsPortFromAnotherInstance(t *testing.T) {
	s, _ := captureTransportServer(t)
	s.SetMobile(mobile.New())
	if err := s.proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	running, port := s.mobileProxyPort()
	if !running || port == 0 {
		t.Fatal("cannot identify current listener")
	}
	wrongPort := port%65535 + 1
	rr := httptest.NewRecorder()
	s.mobileCaptureStart(rr, httptest.NewRequest(http.MethodPost, "/api/mobile/capture/start", strings.NewReader(fmt.Sprintf(`{"proxy_port":%d}`, wrongPort))))
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "监听端口") {
		t.Fatalf("accepted the wrong instance's proxy: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestMobileRequestSerialDoesNotChangeDefaultDevice(t *testing.T) {
	s := &Server{mobile: mobile.New()}
	s.mobile.Use("phone-one")
	r := httptest.NewRequest(http.MethodGet, "/api/mobile/status?serial=phone-two", nil)
	if serial, _ := s.mobileForRequest(r).Serial(); serial != "phone-two" {
		t.Fatalf("request bound to %q", serial)
	}
	if serial, _ := s.mobile.Serial(); serial != "phone-one" {
		t.Fatalf("request changed default to %q", serial)
	}
}

func TestMobileCARequiresAvailableCA(t *testing.T) {
	s := &Server{mobile: mobile.New()}
	rr := httptest.NewRecorder()
	s.mobileCA(rr, httptest.NewRequest(http.MethodPost, "/api/mobile/ca?serial=phone-one", strings.NewReader("{}")))
	if rr.Code != http.StatusConflict {
		t.Fatalf("missing CA: %d %s", rr.Code, rr.Body.String())
	}
}
