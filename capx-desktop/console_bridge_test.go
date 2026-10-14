package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestConsoleBridgeAuthenticatesAndPreservesBinary(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\nfixture")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing native backend credentials")
		}
		if r.URL.RawQuery != "window_id=fixture" {
			t.Error("wrong request target")
		}
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("X-Total-Count", "7")
		w.Header().Set("Set-Cookie", "secret-cookie=must-not-forward")
		_, _ = w.Write(png)
	}))
	defer server.Close()
	app := &App{base: server.URL, token: "fixture-token", hc: server.Client()}
	response, err := app.ApiRequest("GET", "/api/wxdesk/screenshot?window_id=fixture", "")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(response.Data)
	if err != nil || !bytes.Equal(decoded, png) || response.Status != 200 || response.Headers["X-Total-Count"] != "7" || response.Headers["Set-Cookie"] != "" {
		t.Fatalf("invalid binary transport: %+v err=%v", response, err)
	}
}

func TestConsoleBridgeKeepsWritesAndRejectsOtherOrigins(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		body, _ := io.ReadAll(r.Body)
		if r.Method != "POST" || string(body) != `{"value":"测试"}` {
			t.Errorf("wrong request: %s %s", r.Method, body)
		}
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"fixture conflict"}`))
	}))
	defer server.Close()
	app := &App{base: server.URL, hc: server.Client()}
	result, err := app.ApiRequest("POST", "/api/wxdesk/input", `{"value":"测试"}`)
	if err != nil || result.Status != 409 || calls != 1 {
		t.Fatalf("write response changed: %+v %v", result, err)
	}
	for _, path := range []string{"https://evil.test/api/x", "//evil.test/api/x", "/api/../private", "/api/%2e%2e/private", "/api/stream", "/private", "/api/x#fragment"} {
		if _, err := app.ApiRequest("GET", path, ""); err == nil {
			t.Fatalf("accepted target %q", path)
		}
	}
	if calls != 1 {
		t.Fatal("invalid request reached network")
	}
}
