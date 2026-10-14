package mcp

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hquip/capx/internal/api"
	"github.com/hquip/capx/internal/store"
)

// Exercise MCP against the actual REST handlers using a self-owned package.
func TestWxapkgScanUnpackReadThroughREST(t *testing.T) {
	t.Setenv("CAPX_TOKEN", "wxapkg-test-token")
	t.Setenv("CAPX_ALLOW_ACTIVE", "1")
	root := t.TempDir()
	pkg := filepath.Join(root, "wx0123456789abcdef", "7", "APP.wxapkg")
	if err := os.MkdirAll(filepath.Dir(pkg), 0700); err != nil {
		t.Fatal(err)
	}
	name, content := "/app-config.json", `{"window":{"navigationBarTitleText":"Capx fixture"}}`
	entrySize := 4 + len(name) + 8
	var buf bytes.Buffer
	buf.WriteByte(0xbe)
	for _, n := range []uint32{0, uint32(entrySize), uint32(len(content))} {
		_ = binary.Write(&buf, binary.BigEndian, n)
	}
	buf.WriteByte(0xed)
	_ = binary.Write(&buf, binary.BigEndian, uint32(1))
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(name)))
	buf.WriteString(name)
	_ = binary.Write(&buf, binary.BigEndian, uint32(18+entrySize))
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(content)))
	buf.WriteString(content)
	if err := os.WriteFile(pkg, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	rest := api.New(store.New(10), nil, nil, nil, nil, nil, nil, nil, nil)
	backend := httptest.NewServer(rest.Handler())
	defer backend.Close()
	s := &Server{api: &apiClient{base: backend.URL, token: "wxapkg-test-token", http: backend.Client(), active: true}}
	for _, field := range []string{"root", "dir"} {
		args, _ := json.Marshal(map[string]any{field: root})
		value, err := s.callValue("capx_wxapkg_scan", args)
		if err != nil {
			t.Fatal(err)
		}
		result := value.(map[string]any)
		if result["root"] != root || result["count"] != float64(1) {
			t.Fatalf("%s selected wrong cache: %v", field, result)
		}
		app := result["apps"].([]any)[0].(map[string]any)
		if app["name"] != "Capx fixture" || app["path"] != pkg {
			t.Fatalf("wrong package: %v", app)
		}
	}
	args, _ := json.Marshal(map[string]any{"body": map[string]any{"path": pkg, "appid": "wx0123456789abcdef"}})
	value, err := s.callValue("capx_wxapkg_unpack", args)
	if err != nil {
		t.Fatal(err)
	}
	outdir := value.(map[string]any)["outdir"].(string)
	args, _ = json.Marshal(map[string]any{"dir": outdir, "name": "app-config.json"})
	value, err = s.callValue("capx_wxapkg_read", args)
	if err != nil || value.(map[string]any)["content"] != content {
		t.Fatalf("cannot read actual unpacked file: value=%v err=%v", value, err)
	}
	if _, err := s.callValue("capx_wxapkg_read", json.RawMessage(`{"dir":"unused"}`)); err == nil {
		t.Fatal("missing filename must fail before sending a request")
	}
}

func TestTokenFileAuthenticationAndRotation(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	t.Setenv("CAPX_TOKEN", "")
	t.Setenv("CAPX_TOKEN_FILE", tokenFile)
	want := "first-fixture-token"
	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer "+want {
			t.Errorf("wrong token selected")
		}
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backend.Close()
	t.Setenv("CAPX_API", backend.URL)
	c := newAPIClient()
	for _, next := range []string{"first-fixture-token", "rotated-fixture-token"} {
		want = next
		if err := os.WriteFile(tokenFile, []byte(next+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := c.getJSON("/api/policy", nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(tokenFile, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.getJSON("/api/policy", nil); err == nil || !strings.Contains(err.Error(), "CAPX_TOKEN_FILE") {
		t.Fatal("invalid explicit token file must not use an unrelated legacy token")
	}
	if calls != 2 {
		t.Fatalf("invalid credentials reached backend: %d", calls)
	}
	t.Setenv("CAPX_TOKEN", "explicit-fixture-token")
	want = "explicit-fixture-token"
	if _, err := newAPIClient().getJSON("/api/policy", nil); err != nil {
		t.Fatal(err)
	}
}
