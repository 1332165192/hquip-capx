package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hquip/capx/internal/hook"
	"github.com/hquip/capx/internal/inline"
	"github.com/hquip/capx/internal/memscan"
	"github.com/hquip/capx/internal/script"
	"github.com/hquip/capx/internal/sniffer"
	"github.com/hquip/capx/internal/spoof"
	"github.com/hquip/capx/internal/store"
)

func newTestAPIServer(t *testing.T) *Server {
	t.Helper()
	st := store.New(200)
	return New(st, sniffer.New(), memscan.New(), nil,
		hook.New(st), inline.New(st), script.New(st), nil, spoof.New())
}

// newTestServer builds a fully-wired API server (stub backends) with auth
// disabled so handler behavior can be exercised directly.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	t.Setenv("CAPX_AUTH", "0")
	srv := newTestAPIServer(t)
	// Active mode on so write/active endpoints aren't gated in these tests.
	srv.SetActive(true)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func get(t *testing.T, url string) (int, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func postJSON(t *testing.T, url string, body any) (int, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.Bytes()
}

func TestHealthAndPolicy(t *testing.T) {
	ts := newTestServer(t)
	if code, body := get(t, ts.URL+"/health"); code != 200 {
		t.Fatalf("/health = %d", code)
	} else if strings.Contains(string(body), `"identity"`) {
		t.Fatalf("default /health unexpectedly exposed identity: %s", body)
	}
	code, body := get(t, ts.URL+"/api/policy")
	if code != 200 || !strings.Contains(string(body), "active_allowed") {
		t.Fatalf("/api/policy = %d %s", code, body)
	}
}

func TestSetupStatusAndPrepareWithoutProxy(t *testing.T) {
	ts := newTestServer(t)
	code, body := get(t, ts.URL+"/api/setup")
	if code != 200 {
		t.Fatalf("/api/setup = %d %s", code, body)
	}
	if !strings.Contains(string(body), `"os"`) {
		t.Fatalf("/api/setup missing os: %s", body)
	}
	code, body = postJSON(t, ts.URL+"/api/setup/prepare", map[string]any{"system_proxy": false})
	if code != http.StatusNotImplemented && code != http.StatusInternalServerError {
		t.Fatalf("/api/setup/prepare = %d %s", code, body)
	}
	if !strings.Contains(string(body), "proxy not available") && !strings.Contains(string(body), "only implemented") {
		t.Fatalf("/api/setup/prepare unexpected body: %s", body)
	}
}

func TestHealthIncludesConfiguredRuntimeIdentity(t *testing.T) {
	t.Setenv("CAPX_AUTH", "0")
	srv := newTestAPIServer(t)
	srv.SetRuntimeIdentity("test-instance", "test-generation")
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	code, body := get(t, ts.URL+"/health")
	if code != http.StatusOK {
		t.Fatalf("/health = %d %s", code, body)
	}
	var response struct {
		Identity map[string]string `json:"identity"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if response.Identity["instance_id"] != "test-instance" || response.Identity["generation"] != "test-generation" {
		t.Fatalf("identity = %#v", response.Identity)
	}
}

func TestRuntimeShutdownUsesGuardAndRunsOnce(t *testing.T) {
	t.Setenv("CAPX_AUTH", "1")
	t.Setenv("CAPX_TOKEN", "runtime-secret")
	srv := newTestAPIServer(t)
	var calls atomic.Int32
	called := make(chan struct{}, 2)
	srv.SetRuntimeShutdown(func() {
		calls.Add(1)
		called <- struct{}{}
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	code, _ := postJSON(t, ts.URL+"/api/runtime/shutdown", map[string]any{})
	if code != http.StatusUnauthorized {
		t.Fatalf("shutdown without token = %d, want %d", code, http.StatusUnauthorized)
	}

	post := func() int {
		req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/runtime/shutdown", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer runtime-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(); code != http.StatusAccepted {
		t.Fatalf("shutdown = %d, want %d", code, http.StatusAccepted)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("shutdown callback was not invoked")
	}
	if code := post(); code != http.StatusAccepted {
		t.Fatalf("second shutdown = %d, want %d", code, http.StatusAccepted)
	}
	select {
	case <-called:
		t.Fatal("shutdown callback was invoked more than once")
	case <-time.After(50 * time.Millisecond):
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("shutdown callback calls = %d, want 1", got)
	}
}

func TestKeylogRoundTrip(t *testing.T) {
	ts := newTestServer(t)
	code, _ := postJSON(t, ts.URL+"/api/keylog", map[string]any{"lines": []string{"CLIENT_RANDOM aa bb", "CLIENT_RANDOM aa bb"}})
	if code != 200 {
		t.Fatalf("post keylog = %d", code)
	}
	code, body := get(t, ts.URL+"/api/keylog/export")
	if code != 200 || !strings.Contains(string(body), "CLIENT_RANDOM aa bb") {
		t.Fatalf("export = %d %q", code, body)
	}
	// Duplicate line must have been de-duplicated.
	if strings.Count(string(body), "CLIENT_RANDOM") != 1 {
		t.Fatalf("expected dedup, got %q", body)
	}
}

func TestDecodeEndpoints(t *testing.T) {
	ts := newTestServer(t)
	// protobuf: field 1 varint 150, field 2 string "hi"
	code, body := postJSON(t, ts.URL+"/api/decode/protobuf", map[string]string{"hex": "089601120268 69"})
	if code != 200 || !strings.Contains(string(body), "\"field\":1") {
		t.Fatalf("decode protobuf = %d %s", code, body)
	}
	// bad input
	if code, _ := postJSON(t, ts.URL+"/api/decode/protobuf", map[string]string{"hex": "ff"}); code != 400 {
		t.Fatalf("bad protobuf should be 400, got %d", code)
	}
}

func TestScanAndProject(t *testing.T) {
	ts := newTestServer(t)
	// Seed an HTTP tx with a missing-CSP HTML response via the store directly.
	// (We post to /api/scan/passive which reads the store.)
	code, body := get(t, ts.URL+"/api/scan/passive")
	if code != 200 || !strings.Contains(string(body), "scanned") {
		t.Fatalf("scan = %d %s", code, body)
	}
	// Project export should produce a versioned bundle.
	code, body = get(t, ts.URL+"/api/project/export")
	if code != 200 || !strings.Contains(string(body), "\"version\"") {
		t.Fatalf("project export = %d %s", code, body)
	}
}

func TestHaERulesUploadAndScan(t *testing.T) {
	ts := newTestServer(t)
	rules := "rules:\n- group: G\n  rule:\n  - name: Email\n    loaded: true\n    f_regex: ([a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,})\n    s_regex: ''\n    format: '{0}'\n    color: yellow\n    scope: any\n    engine: dfa\n    sensitive: false\n"
	code, body := postJSON(t, ts.URL+"/api/hae/rules", map[string]string{"yaml": rules})
	if code != 200 || !strings.Contains(string(body), "\"loaded\":1") {
		t.Fatalf("upload = %d %s", code, body)
	}
	// Scan with no captured history still returns a well-formed result.
	code, body = get(t, ts.URL+"/api/hae/scan")
	if code != 200 || !strings.Contains(string(body), "scanned") {
		t.Fatalf("hae scan = %d %s", code, body)
	}
}

func TestStartCaptureStubBackendFailsFast(t *testing.T) {
	if sniffer.New().Backend() != "stub" {
		t.Skip("stub contract only; never start a real network capture in this unit test")
	}
	ts := newTestServer(t)
	code, body := postJSON(t, ts.URL+"/api/captures", map[string]any{"filter": "tcp"})
	if code != http.StatusNotImplemented {
		t.Fatalf("start capture = %d %s, want 501", code, body)
	}
	if !strings.Contains(string(body), "live capture not built in") {
		t.Fatalf("error body = %s", body)
	}
	code, body = get(t, ts.URL+"/api/captures")
	if code != 200 {
		t.Fatalf("list captures = %d %s", code, body)
	}
	if strings.Contains(string(body), `"running":true`) {
		t.Fatalf("stub start left a running capture: %s", body)
	}
}

func TestModulesRequiresSession(t *testing.T) {
	ts := newTestServer(t)
	// No such session => 404.
	if code, _ := get(t, ts.URL+"/api/mem/nope/modules"); code != 404 {
		t.Fatalf("modules unknown session = %d, want 404", code)
	}
}
