package mobile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestWDAEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{"", "https://127.0.0.1:8100", "http://192.168.0.2:8100", "http://example.com:8100", "http://127.0.0.1", "http://user:pass@127.0.0.1:8100", "http://127.0.0.1:8100/?token=x", "http://127.0.0.1:8100/other"} {
		if _, err := normalizeWDAEndpoint(endpoint); err == nil {
			t.Fatalf("accepted endpoint %q", endpoint)
		}
	}
	if endpoint, err := normalizeWDAEndpoint("http://localhost:8100/"); err != nil || endpoint != "http://127.0.0.1:8100" {
		t.Fatal(endpoint, err)
	}
}

func TestIOSExistingSessionScreenAndActions(t *testing.T) {
	var picture bytes.Buffer
	if err := png.Encode(&picture, image.NewRGBA(image.Rect(0, 0, 200, 400))); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	posts := map[string]map[string]any{}
	invalid := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "POST" {
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid request JSON")
			}
			posts[r.URL.Path] = body
		}
		var value any
		switch r.URL.Path {
		case "/status":
			value = map[string]any{"ready": true}
		case "/session":
			if r.Method != "GET" {
				t.Error("connecting replaced an existing session")
			}
			value = map[string]any{"sessionId": "existing"}
		case "/session/existing/window/size":
			value = map[string]any{"width": 100, "height": 200}
			if invalid {
				value = map[string]any{"error": "invalid session id", "message": "device session expired"}
			}
		case "/session/existing/screenshot":
			value = base64.StdEncoding.EncodeToString(picture.Bytes())
		case "/session/existing/source":
			if r.URL.Query().Get("format") != "xml" {
				t.Error("XML format missing")
			}
			value = `<AppiumAUT><XCUIElementTypeApplication><XCUIElementTypeButton type="XCUIElementTypeButton" name="toolbar/search" label="搜索" x="20" y="40" width="40" height="20" visible="true" enabled="true"/><XCUIElementTypeButton name="hidden" label="隐藏" x="0" y="0" width="10" height="10" visible="false"/></XCUIElementTypeApplication></AppiumAUT>`
		case "/wda/activeAppInfo":
			value = map[string]any{"bundleId": "com.example.app"}
		case "/session/existing/wda/tap", "/session/existing/wda/keys", "/session/existing/wda/dragfromtoforduration", "/session/existing/wda/apps/launch", "/session/existing/appium/settings", "/wda/homescreen":
			value = nil
		default:
			t.Errorf("unexpected WDA request: %s %s", r.Method, r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
	}))
	defer server.Close()
	c := NewIOS()
	status, err := c.Connect(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if status["coordinate_space"] != "points" || status["wired"] != false {
		t.Fatal(status)
	}
	data, size, err := c.ScreenshotWithSize()
	if err != nil || !bytes.Equal(data, picture.Bytes()) || size.Width != 100 || size.Height != 200 {
		t.Fatal(size, err)
	}
	if err := c.Tap(50, 80); err != nil {
		t.Fatal(err)
	}
	if err := c.Input("小米 capx"); err != nil {
		t.Fatal(err)
	}
	if err := c.Swipe(50, 150, 50, 50, 350); err != nil {
		t.Fatal(err)
	}
	if err := c.Home(); err != nil {
		t.Fatal(err)
	}
	if err := c.LaunchApp("com.example.app"); err != nil {
		t.Fatal(err)
	}
	if app, err := c.ForegroundApp(); err != nil || app != "com.example.app" {
		t.Fatal(app, err)
	}
	snapshot, err := c.SnapshotWithInfo()
	if err != nil || len(snapshot.Elements) != 1 || snapshot.Elements[0].X != 40 || snapshot.Elements[0].Y != 50 {
		t.Fatal(snapshot, err)
	}
	if _, err := c.Click(Locator{ResourceID: "toolbar/search"}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if posts["/session/existing/wda/keys"]["value"].([]any)[0] != "小米 capx" {
		t.Error("Unicode input changed")
	}
	if posts["/session/existing/wda/dragfromtoforduration"]["duration"] != .35 {
		t.Error("swipe duration changed")
	}
	if posts["/session/existing/appium/settings"]["settings"].(map[string]any)["defaultActiveApplication"] != "auto" {
		t.Error("did not select active app")
	}
	count := len(posts)
	invalid = true
	mu.Unlock()
	if err := c.Tap(10, 10); err == nil {
		t.Fatal("expired session accepted")
	}
	if err := c.Home(); err == nil {
		t.Fatal("global home command accepted an expired session")
	}
	mu.Lock()
	after := len(posts)
	mu.Unlock()
	if after != count {
		t.Fatal("failed operation recreated a session or retried a mutation")
	}
	c.Disconnect()
	if _, err := c.Screenshot(); err == nil {
		t.Fatal("disconnected controller returned a screenshot")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(posts) != count {
		t.Fatal("disconnect mutated the existing WDA session")
	}
}

func TestIOSNewSessionAndInvalidCoordinates(t *testing.T) {
	var mutations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var value any
		switch r.URL.Path {
		case "/status":
			value = map[string]any{"ready": true}
		case "/session":
			value = map[string]any{}
			if r.Method == "POST" {
				mutations.Add(1)
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				caps := body["capabilities"].(map[string]any)["alwaysMatch"].(map[string]any)
				if caps["shouldTerminateApp"] != false || caps["bundleId"] != nil {
					t.Error("session would launch or terminate an app")
				}
				value = map[string]any{"sessionId": "new-session"}
			}
		case "/session/new-session/window/size":
			value = map[string]any{"width": 100, "height": 200}
		case "/session/new-session/appium/settings":
		default:
			mutations.Add(1)
			t.Errorf("unexpected command %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
	}))
	defer server.Close()
	c := NewIOS()
	if _, err := c.Connect(server.URL, ""); err != nil {
		t.Fatal(err)
	}
	if err := c.Tap(200, 100); err == nil {
		t.Fatal("screenshot pixels accepted as points")
	}
	if err := c.Swipe(50, 100, 200, 100, 300); err == nil {
		t.Fatal("out of range swipe accepted")
	}
	if _, err := c.Connect(server.URL, "another-session"); err == nil {
		t.Fatal("silently switched sessions")
	}
	if mutations.Load() != 1 {
		t.Fatal("invalid request reached WDA")
	}
}

func TestWDARejectsRedirects(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetHits.Add(1) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer server.Close()
	if _, err := NewIOS().Connect(server.URL, ""); err == nil || targetHits.Load() != 0 {
		t.Fatal("redirect followed", targetHits.Load(), err)
	}
}

func TestIOSProtocolErrorsAreNotReportedAsSuccess(t *testing.T) {
	for _, response := range []string{`{"value":{"error":"invalid session id","message":"secret-input"}}`, `{"status":6,"value":{"message":"secret-input"}}`, `{"value":"unexpected"}`, `not-json`} {
		t.Run(response, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(response)) }))
			defer server.Close()
			_, err := NewIOS().Connect(server.URL, "")
			if err == nil || strings.Contains(err.Error(), "secret-input") {
				t.Fatal("missing or unredacted protocol error", err)
			}
		})
	}
}
