package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/hquip/capx/internal/proxy"
	"github.com/hquip/capx/internal/setup"
	"github.com/hquip/capx/internal/store"
	"github.com/hquip/capx/internal/wxhook"
)

type inertWXCapture struct {
	mu                sync.Mutex
	available         bool
	options           wxhook.CaptureOptions
	status            wxhook.CaptureResult
	startErr, stopErr error
	starts, stops     int
}

func (f *inertWXCapture) Available() bool { return f.available }
func (f *inertWXCapture) CaptureStartWithOptions(opts wxhook.CaptureOptions, pids []uint32, watch bool) (*wxhook.CaptureResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	f.options = opts
	f.status = wxhook.CaptureResult{Enabled: true, Port: opts.Port, ExplicitPort: opts.ExplicitPort, UpstreamProxy: opts.UpstreamProxy, Watch: watch, PendingPIDs: []uint32{1234}}
	if f.startErr != nil {
		f.status.Errors = map[uint32]string{1234: f.startErr.Error()}
	}
	cp := f.status
	return &cp, f.startErr
}
func (f *inertWXCapture) CaptureStatus() *wxhook.CaptureResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := f.status
	return &cp
}
func (f *inertWXCapture) CaptureStop() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops++
	if f.stopErr != nil {
		return f.stopErr
	}
	f.status.Enabled = false
	f.status.Running = false
	return nil
}

func captureTransportServer(t *testing.T) (*Server, *inertWXCapture) {
	t.Helper()
	t.Setenv("CAPX_DATA_DIR", t.TempDir())
	st := store.New(64)
	p, err := proxy.New(st)
	if err != nil {
		t.Fatal(err)
	}
	f := &inertWXCapture{available: true}
	s := &Server{st: st, proxy: p, wxCaptureEngine: f, wxSystemProxy: func() (setup.SystemProxyConfig, error) { return setup.SystemProxyConfig{}, nil }}
	t.Cleanup(func() {
		f.stopErr = nil
		_ = s.CloseCaptureTools()
		_ = p.StopCaptureBridge()
		_ = p.StopTransparent()
		_ = p.Stop()
	})
	return s, f
}
func startWX(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.wxhookCaptureStart(w, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:19091/api/wxhook/capture/start", strings.NewReader(body)))
	return w
}

func TestCaptureSystemProxySelection(t *testing.T) {
	for _, tc := range []struct {
		cfg  setup.SystemProxyConfig
		want string
		bad  bool
	}{
		{setup.SystemProxyConfig{}, "", false},
		{setup.SystemProxyConfig{Enabled: true, Server: "127.0.0.1:7897"}, "http://127.0.0.1:7897", false},
		{setup.SystemProxyConfig{Enabled: true, Server: "http=127.0.0.1:7897;https=localhost:7897"}, "http://127.0.0.1:7897", false},
		{setup.SystemProxyConfig{Enabled: true, Server: "http=127.0.0.1:7897;https=127.0.0.1:7898"}, "", true},
		{setup.SystemProxyConfig{Enabled: true, Server: "socks=127.0.0.1:7897"}, "", true},
		{setup.SystemProxyConfig{Enabled: true, Server: "127.0.0.1:7897", PAC: true}, "", true},
		{setup.SystemProxyConfig{Enabled: true, Server: "http://user:secret@127.0.0.1:7897"}, "", true},
		{setup.SystemProxyConfig{Enabled: true, Server: "http://outside.test:7897"}, "", true},
		{setup.SystemProxyConfig{Enabled: true, Server: "http://[::1]:7897"}, "", true},
	} {
		got, err := captureSystemUpstream(tc.cfg)
		if (err != nil) != tc.bad || got != tc.want {
			t.Errorf("selection got=%q error=%v want=%q bad=%v", got, err, tc.want, tc.bad)
		}
	}
}

func TestWXCaptureAutomaticExistingProxyUsesExplicitBridge(t *testing.T) {
	s, f := captureTransportServer(t)
	var hits int
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.URL.Host != "fixture.invalid" {
			t.Errorf("lost target authority: %s", r.URL)
		}
		io.WriteString(w, "through-existing-proxy")
	}))
	defer upstream.Close()
	s.wxSystemProxy = func() (setup.SystemProxyConfig, error) {
		return setup.SystemProxyConfig{Enabled: true, Server: strings.TrimPrefix(upstream.URL, "http://")}, nil
	}
	w := startWX(t, s, `{"watch":true,"upstream_proxy":"auto"}`)
	if w.Code != 200 {
		t.Fatalf("capture start: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Mode      string                `json:"mode"`
		Capture   *wxhook.CaptureResult `json:"capture"`
		Transport wxCaptureTransport    `json:"capture_transport"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Mode != "proxy-chain" || out.Capture.Running || !out.Capture.Enabled || !out.Transport.BridgeRunning || !out.Transport.TransparentRunning {
		t.Fatalf("pending != ready, and both listeners required: %+v", out)
	}
	if f.options.ExplicitPort == 0 || f.options.ExplicitPort == f.options.Port || f.options.UpstreamProxy != upstream.URL {
		t.Fatalf("invalid agent destinations: %+v", f.options)
	}
	if on, _ := s.proxy.Status(); on {
		t.Fatal("capture unexpectedly started/changed ordinary explicit proxy")
	}
	bridge, _ := url.Parse("http://" + out.Transport.BridgeAddr)
	tr := &http.Transport{Proxy: http.ProxyURL(bridge)}
	defer tr.CloseIdleConnections()
	response, err := (&http.Client{Transport: tr}).Get("http://fixture.invalid/miniapp")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(data) != "through-existing-proxy" || hits != 1 {
		t.Fatalf("chain result=%q hits=%d err=%v", data, hits, err)
	}
	stop := httptest.NewRecorder()
	s.wxhookCaptureStop(stop, httptest.NewRequest(http.MethodPost, "/api/wxhook/capture/stop", nil))
	if stop.Code != 200 {
		t.Fatalf("stop failed: %s", stop.Body.String())
	}
	if on, _, _ := s.proxy.CaptureBridgeStatus(); on {
		t.Fatal("owned bridge still listening")
	}
	if on, _ := s.proxy.TransparentStatus(); on {
		t.Fatal("owned transparent listener still listening")
	}
}

func TestWXCaptureDirectAndInvalidConfigDoNotChangeOtherListeners(t *testing.T) {
	s, f := captureTransportServer(t)
	if err := s.proxy.Start("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if err := s.proxy.StartTransparent("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	_, normal := s.proxy.Status()
	_, transparent := s.proxy.TransparentStatus()
	for _, body := range []string{`{`, `{"upstream_proxy":"socks5://127.0.0.1:7897"}`, `{"upstream_proxy":"http://127.0.0.1:19091"}`, `{"upstream_proxy":"http://` + normal + `"}`} {
		w := startWX(t, s, body)
		if w.Code < 400 {
			t.Fatalf("bad config accepted: %s", body)
		}
	}
	if f.starts != 0 {
		t.Fatal("invalid configuration attached an agent")
	}
	w := startWX(t, s, `{"upstream_proxy":"direct"}`)
	if w.Code != 200 {
		t.Fatalf("direct: %s", w.Body.String())
	}
	if f.options.ExplicitPort != 0 || f.options.UpstreamProxy != "" {
		t.Fatal("direct mode gained an upstream")
	}
	stop := httptest.NewRecorder()
	s.wxhookCaptureStop(stop, httptest.NewRequest(http.MethodPost, "/stop", nil))
	if on, addr := s.proxy.Status(); !on || addr != normal {
		t.Fatal("stop changed pre-existing explicit listener")
	}
	if on, addr := s.proxy.TransparentStatus(); !on || addr != transparent {
		t.Fatal("stop changed pre-existing transparent listener")
	}
}

func TestWXCaptureFailureRollsBackOnlyOwnedResources(t *testing.T) {
	s, f := captureTransportServer(t)
	f.startErr = errors.New("fixture attach rejected")
	w := startWX(t, s, `{"upstream_proxy":"http://127.0.0.1:7897"}`)
	if w.Code != 409 || !strings.Contains(w.Body.String(), "1234") || !strings.Contains(w.Body.String(), "fixture attach rejected") {
		t.Fatalf("failure hidden: %d %s", w.Code, w.Body.String())
	}
	if on, _, _ := s.proxy.CaptureBridgeStatus(); on {
		t.Fatal("failed start leaked owned bridge")
	}
	if on, _ := s.proxy.TransparentStatus(); on {
		t.Fatal("failed start leaked transparent listener")
	}
}

func TestWXCapturePendingRejectsConfigChangeAndPreservesBridgeOnDetachFailure(t *testing.T) {
	s, f := captureTransportServer(t)
	w := startWX(t, s, `{"upstream_proxy":"http://127.0.0.1:7897"}`)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = startWX(t, s, `{"upstream_proxy":"http://127.0.0.1:7898"}`)
	if w.Code != 409 || f.starts != 1 {
		t.Fatal("pending capture silently changed its upstream")
	}
	f.stopErr = errors.New("fixture detach failure")
	w = httptest.NewRecorder()
	s.wxhookCaptureStop(w, httptest.NewRequest(http.MethodPost, "/stop", nil))
	if w.Code != 409 {
		t.Fatal("detach failure acknowledged")
	}
	if on, _, _ := s.proxy.CaptureBridgeStatus(); !on {
		t.Fatal("listener closed while hook may still redirect into it")
	}
}

func TestWXCaptureUnavailableNeverPretendsChainWorks(t *testing.T) {
	s, f := captureTransportServer(t)
	f.available = false
	w := startWX(t, s, `{"upstream_proxy":"http://127.0.0.1:7897"}`)
	if w.Code != 409 || f.starts != 0 {
		t.Fatalf("missing Frida acknowledged: %d", w.Code)
	}
	if on, _, _ := s.proxy.CaptureBridgeStatus(); on {
		t.Fatal("unavailable route opened an unused bridge")
	}
}
