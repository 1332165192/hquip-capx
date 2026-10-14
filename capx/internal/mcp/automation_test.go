package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func automationPNG(t *testing.T) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := png.Encode(&out, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func invokeAutomationTool(t *testing.T, s *Server, name string, args any) map[string]any {
	t.Helper()
	params, err := json.Marshal(map[string]any{"name": name, "arguments": args})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := s.handle(&out, rpcRequest{JSONRPC: "2.0", ID: json.RawMessage("1"), Method: "tools/call", Params: params}); err != nil {
		t.Fatal(err)
	}
	var response struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response.Result
}

func TestScreenshotsReachAIAsMCPImages(t *testing.T) {
	picture := automationPNG(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/mobile/screenshot" && r.URL.Query().Get("serial") != "phone A:B" {
			t.Errorf("wrong target device: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(picture)
	}))
	defer api.Close()
	s := &Server{api: &apiClient{base: api.URL, http: api.Client()}}
	for _, tc := range []struct {
		name string
		args any
	}{
		{"capx_wxauto_screenshot", map[string]any{}},
		{"capx_mobile_screenshot", map[string]any{"serial": "phone A:B"}},
		{"capx_api", map[string]any{"method": "GET", "path": "/api/mobile/screenshot", "query": map[string]any{"serial": "phone A:B"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := invokeAutomationTool(t, s, tc.name, tc.args)
			if result["isError"] != false {
				t.Fatalf("image request failed: %v", result)
			}
			content := result["content"].([]any)
			block := content[0].(map[string]any)
			if block["type"] != "image" || block["mimeType"] != "image/png" {
				t.Fatalf("AI received binary text instead of an image: %v", block)
			}
			data, err := base64.StdEncoding.DecodeString(block["data"].(string))
			if err != nil || !bytes.Equal(data, picture) {
				t.Fatal("PNG changed in transport")
			}
		})
	}
}

func TestIOSMobileToolsPreservePlatformAndUnicode(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("platform") != "ios" || r.URL.Query().Get("serial") != "ios-wda" {
			t.Errorf("wrong phone platform: %s", r.URL.RawQuery)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["value"] != "小米" || body["platform"] != nil || body["serial"] != nil {
			t.Errorf("lost text or target leaked into body: %v", body)
		}
		_, _ = w.Write([]byte(`{"input":"ok"}`))
	}))
	defer api.Close()
	s := &Server{api: &apiClient{base: api.URL, http: api.Client(), active: true}}
	for _, args := range []map[string]any{
		{"platform": "ios", "serial": "ios-wda", "body": map[string]any{"value": "小米"}},
		{"platform": "ios", "serial": "ios-wda", "value": "小米"},
	} {
		if result := invokeAutomationTool(t, s, "capx_mobile_input", args); result["isError"] != false {
			t.Fatal(result)
		}
	}
	s.api.active = false
	if result := invokeAutomationTool(t, s, "capx_mobile_ios_connect", map[string]any{"endpoint": "http://127.0.0.1:8100"}); result["isError"] != true {
		t.Fatal("inactive MCP accepted a WDA connection", result)
	}
}

func TestIOSScreenshotIncludesCoordinateMetadataForAI(t *testing.T) {
	picture := automationPNG(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("platform") != "ios" {
			t.Error("lost iOS platform")
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("X-Capx-Coordinate-Space", "points")
		w.Header().Set("X-Capx-Screen-Width", "414")
		w.Header().Set("X-Capx-Screen-Height", "896")
		_, _ = w.Write(picture)
	}))
	defer api.Close()
	s := &Server{api: &apiClient{base: api.URL, http: api.Client()}}
	result := invokeAutomationTool(t, s, "capx_mobile_screenshot", map[string]any{"platform": "ios", "serial": "ios-wda"})
	blocks := result["content"].([]any)
	if len(blocks) != 2 || blocks[0].(map[string]any)["type"] != "image" || !strings.Contains(blocks[1].(map[string]any)["text"].(string), `"coordinate_space": "points"`) {
		t.Fatal("AI did not receive screenshot coordinates", result)
	}
}

func TestSnapshotReturnsElementsAndImageWithoutBase64Text(t *testing.T) {
	picture := automationPNG(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("screenshot") != "true" {
			t.Error("screenshot option was dropped")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"route": "pages/home", "elements": []any{map[string]any{"text": "搜索"}}, "screenshot_base64": base64.StdEncoding.EncodeToString(picture)})
	}))
	defer api.Close()
	s := &Server{api: &apiClient{base: api.URL, http: api.Client()}}
	result := invokeAutomationTool(t, s, "capx_wxauto_snapshot", map[string]any{"screenshot": "true"})
	blocks := result["content"].([]any)
	if len(blocks) != 2 || blocks[1].(map[string]any)["type"] != "image" {
		t.Fatalf("snapshot image not available to AI: %v", result)
	}
	text := blocks[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "搜索") || strings.Contains(text, "screenshot_base64") {
		t.Fatalf("lost elements or duplicated image as text: %s", text)
	}
}

func TestMobileAIActionPreservesSerialAndBody(t *testing.T) {
	calls := 0
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/api/mobile/tap" || r.URL.Query().Get("serial") != "phone A:B" {
			t.Errorf("wrong device/action request: %s %s", r.Method, r.URL)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["x"] != float64(20) || body["y"] != float64(30) || body["serial"] != nil {
			t.Errorf("wrong click body: %v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	}))
	defer api.Close()
	s := &Server{api: &apiClient{base: api.URL, http: api.Client(), active: true}}
	for _, tc := range []struct {
		name string
		args any
	}{
		{"capx_mobile_tap", map[string]any{"serial": "phone A:B", "body": map[string]any{"x": 20, "y": 30}}},
		{"capx_mobile_tap", map[string]any{"serial": "phone A:B", "x": 20, "y": 30}},
		{"capx_api", map[string]any{"method": "POST", "path": "/api/mobile/tap", "query": map[string]any{"serial": "phone A:B"}, "body": map[string]any{"x": 20, "y": 30}}},
	} {
		if result := invokeAutomationTool(t, s, tc.name, tc.args); result["isError"] != false {
			t.Fatalf("action failed: %v", result)
		}
	}
	if calls != 3 {
		t.Fatalf("expected 3 actions, got %d", calls)
	}
	s.api.active = false
	for _, name := range []string{"capx_mobile_tap", "capx_api"} {
		args := map[string]any{"method": "POST", "path": "/api/mobile/tap", "serial": "phone A:B"}
		if result := invokeAutomationTool(t, s, name, args); result["isError"] != true {
			t.Fatalf("disabled active mode sent action: %v", result)
		}
	}
	if calls != 3 {
		t.Fatal("blocked action reached backend")
	}
}

func TestFailedScreenshotRemainsTextError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"CDP not connected"}`))
	}))
	defer api.Close()
	s := &Server{api: &apiClient{base: api.URL, http: api.Client()}}
	result := invokeAutomationTool(t, s, "capx_wxauto_screenshot", map[string]any{})
	block := result["content"].([]any)[0].(map[string]any)
	if result["isError"] != true || block["type"] != "text" || !strings.Contains(block["text"].(string), "CDP not connected") {
		t.Fatalf("lost screenshot error: %v", result)
	}
}

func TestOversizedScreenshotIsRejectedInsteadOfTruncated(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 8<<20)...))
	}))
	defer api.Close()
	s := &Server{api: &apiClient{base: api.URL, http: api.Client()}}
	result := invokeAutomationTool(t, s, "capx_mobile_screenshot", map[string]any{"serial": "phone-one"})
	if result["isError"] != true {
		t.Fatalf("truncated image returned as success: %v", result)
	}
}

func TestIsolatedWeChatMCPDoesNotExposeOrExecuteHostTools(t *testing.T) {
	s := &Server{api: &apiClient{isolatedWeChat: true}}
	for _, tool := range s.tools() {
		if tool.Name != "capx_health" && !strings.HasPrefix(tool.Name, "capx_wxdesk_") {
			t.Fatalf("isolated catalogue exposed %s", tool.Name)
		}
	}
	for _, name := range []string{"capx_api", "capx_wxauto_click", "capx_wxhook_enable", "capx_mobile_tap", "capx_runtime_shutdown"} {
		result := invokeAutomationTool(t, s, name, map[string]any{})
		if result["isError"] != true {
			t.Fatalf("isolated mode allowed %s", name)
		}
	}
}
