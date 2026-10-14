package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hquip/capx/internal/wxdesk"
)

type deskFixture struct {
	available bool
	calls     int
	target    string
	options   wxdesk.PrepareOptions
}

func (f *deskFixture) Available() bool { return f.available }
func (f *deskFixture) Environment() wxdesk.Environment {
	return wxdesk.Environment{Mode: "sandbox-relay", Available: f.available, Note: "fixture"}
}
func (f *deskFixture) Prepare(options wxdesk.PrepareOptions) (wxdesk.Package, error) {
	f.calls++
	f.options = options
	return wxdesk.Package{Root: "fixture", SandboxInstalled: false}, nil
}

func TestInstallerSourceReachesPreparationWithoutHostDiscovery(t *testing.T) {
	fake := &deskFixture{}
	server := &Server{wxdesk: fake}
	w := httptest.NewRecorder()
	server.wxdeskPrepare(w, httptest.NewRequest("POST", "/api/wxdesk/prepare", strings.NewReader(`{"source":"installer","installer":"C:/downloads/WeChatSetup.exe"}`)))
	if w.Code != 200 || fake.options.Source != "installer" || fake.options.Installer != "C:/downloads/WeChatSetup.exe" || fake.options.WeChatExe != "" {
		t.Fatalf("wrong preparation options: status=%d options=%+v", w.Code, fake.options)
	}
}
func (f *deskFixture) StartEnvironment() error { f.calls++; return nil }
func (f *deskFixture) Windows() ([]wxdesk.Window, error) {
	f.calls++
	return []wxdesk.Window{{ID: "ff:12:34", Title: "隔离微信"}}, nil
}
func (f *deskFixture) Launch() error        { f.calls++; return nil }
func (f *deskFixture) Show(id string) error { f.calls++; f.target = id; return nil }
func (f *deskFixture) Screenshot(id string) ([]byte, error) {
	f.calls++
	f.target = id
	return []byte("\x89PNG\r\n\x1a\nfixture"), nil
}
func (f *deskFixture) Tap(id string, x, y, width, height int) error {
	f.calls++
	f.target = id
	return nil
}
func (f *deskFixture) Input(id, value string) error      { f.calls++; f.target = id; return nil }
func (f *deskFixture) Key(id, key string) error          { f.calls++; f.target = id; return nil }
func (f *deskFixture) Scroll(id string, delta int) error { f.calls++; f.target = id; return nil }

func TestDisconnectedIsolatedDeskDoesNotOperateHost(t *testing.T) {
	fake := &deskFixture{}
	s := &Server{wxdesk: fake}
	for _, handler := range []http.HandlerFunc{s.wxdeskWindows, s.wxdeskLaunch, s.wxdeskScreenshot, s.wxdeskAction} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest("GET", "/api/wxdesk/windows", nil))
		if w.Code != http.StatusConflict || fake.calls != 0 {
			t.Fatalf("disconnected environment called backend: %d %d", w.Code, fake.calls)
		}
	}
	w := httptest.NewRecorder()
	s.wxdeskEnvironment(w, httptest.NewRequest("GET", "/api/wxdesk/environment", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"available":false`) {
		t.Fatalf("environment: %s", w.Body.String())
	}
}

func TestDeskActionsRequireValidCoordinatesAndTarget(t *testing.T) {
	fake := &deskFixture{available: true}
	s := &Server{wxdesk: fake}
	for _, body := range []string{"{", `{}`, `{"window_id":"ff:12:34","x":-1,"y":0,"width":100,"height":100}`, `{"window_id":"ff:12:34","x":10,"width":100,"height":100}`, `{"window_id":"ff:12:34","x":100,"y":0,"width":100,"height":100}`} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/api/wxdesk/tap", strings.NewReader(body))
		req.SetPathValue("action", "tap")
		s.wxdeskAction(w, req)
		if w.Code != http.StatusBadRequest || fake.calls != 0 {
			t.Fatalf("invalid action accepted: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/wxdesk/tap", strings.NewReader(`{"window_id":"ff:12:34","x":10,"y":20,"width":100,"height":200}`))
	req.SetPathValue("action", "tap")
	s.wxdeskAction(w, req)
	if w.Code != http.StatusOK || fake.target != "ff:12:34" || fake.calls != 1 {
		t.Fatalf("wrong target: %d %+v", w.Code, fake)
	}
}

func TestDeskImageAndLoginClaims(t *testing.T) {
	fake := &deskFixture{available: true}
	s := &Server{wxdesk: fake}
	w := httptest.NewRecorder()
	s.wxdeskScreenshot(w, httptest.NewRequest("GET", "/api/wxdesk/screenshot?window_id=ff:12:34", nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "image/png" || !bytes.HasPrefix(w.Body.Bytes(), []byte("\x89PNG")) {
		t.Fatal("screenshot not returned as an image")
	}
	w = httptest.NewRecorder()
	s.wxdeskWindows(w, httptest.NewRequest("GET", "/api/wxdesk/windows", nil))
	var status map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &status)
	if status["login_status"] != "unknown" {
		t.Fatal("window discovery must not claim login success")
	}
}

func TestDeskWritesUseExistingActivePolicy(t *testing.T) {
	for _, path := range []string{"/api/wxdesk/prepare", "/api/wxdesk/start-environment", "/api/wxdesk/tap", "/api/wxdesk/input", "/api/wxdesk/show"} {
		if !isActiveOp(http.MethodPost, path) {
			t.Fatalf("unguarded desktop action: %s", path)
		}
		if isActiveOp(http.MethodGet, path) {
			t.Fatalf("read classified as write: %s", path)
		}
	}
}
