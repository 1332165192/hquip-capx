package api

import (
	"encoding/json"
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

func TestMobilePlatformsNeverFallBackToADB(t *testing.T) {
	s := &Server{mobile: mobile.New(), ios: mobile.NewIOS()}
	for _, path := range []string{"/api/mobile/status?platform=unknown", "/api/mobile/status?platform=ios&serial=another-phone"} {
		rr := httptest.NewRecorder()
		s.mobileStatus(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("invalid target accepted: %d %s", rr.Code, rr.Body.String())
		}
	}
	for _, handler := range []http.HandlerFunc{s.mobileCaptureStart, s.mobileCaptureStop, s.mobileCA} {
		rr := httptest.NewRecorder()
		handler(rr, httptest.NewRequest(http.MethodPost, "/api/mobile/test?platform=ios", strings.NewReader("{}")))
		if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "Wi-Fi") {
			t.Fatalf("iOS routed through ADB: %d %s", rr.Code, rr.Body.String())
		}
	}
}

func TestMobileWritesRequireBackendActivePolicy(t *testing.T) {
	for _, route := range []string{"tap", "input", "swipe", "key", "back", "home", "launch", "ca", "capture/start", "ios/connect", "ios/prepare"} {
		t.Run(route, func(t *testing.T) {
			g := newTestGuard()
			calls := 0
			h := g.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(http.StatusOK) }))
			request := func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19091/api/mobile/"+route, strings.NewReader("{}"))
				r.Header.Set("Authorization", "Bearer secret")
				return r
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, request())
			if rr.Code != http.StatusForbidden || calls != 0 {
				t.Fatalf("inactive device mutation reached handler: %d %d", rr.Code, calls)
			}
			g.active.Store(true)
			rr = httptest.NewRecorder()
			h.ServeHTTP(rr, request())
			if rr.Code != http.StatusOK || calls != 1 {
				t.Fatalf("authorized operation failed: %d %d", rr.Code, calls)
			}
		})
	}
}

func TestMobileIOSAPIUsesWDAController(t *testing.T) {
	gotInput := ""
	wda := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var value any
		switch r.URL.Path {
		case "/status":
			value = map[string]any{"ready": true}
		case "/session/test/window/size":
			value = map[string]any{"width": 414, "height": 896}
		case "/session/test/appium/settings":
		case "/session/test/wda/keys":
			var body struct {
				Value []string `json:"value"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if len(body.Value) == 1 {
				gotInput = body.Value[0]
			}
		default:
			t.Errorf("unexpected WDA route %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
	}))
	defer wda.Close()
	s := &Server{mobile: mobile.New(), ios: mobile.NewIOS()}
	if _, err := s.ios.Connect(wda.URL, "test"); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	s.mobileInput(rr, httptest.NewRequest(http.MethodPost, "/api/mobile/input?platform=ios&serial=ios-wda", strings.NewReader(`{"value":"小米"}`)))
	if rr.Code != http.StatusOK || gotInput != "小米" {
		t.Fatalf("iOS input failed: %d %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	s.mobileStatus(rr, httptest.NewRequest(http.MethodGet, "/api/mobile/status?platform=ios&serial=ios-wda", nil))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"coordinate_space":"points"`) {
		t.Fatalf("missing coordinate metadata: %d %s", rr.Code, rr.Body.String())
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
