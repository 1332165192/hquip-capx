package wxcdp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoverValidatesProviderAndTargetOrigin(t *testing.T) {
	var endpoint string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/json/list" {
			t.Error("unexpected provider path")
		}
		json.NewEncoder(w).Encode([]Target{{ID: "page-1", Title: "<unsafe title>", Type: "page", WebSocket: strings.Replace(endpoint, "http://", "ws://", 1) + "/devtools/page/1"}, {ID: "other-provider", WebSocket: "ws://127.0.0.1:1/devtools/page/2"}, {ID: "remote", WebSocket: "ws://192.168.1.1:9222/devtools/page/3"}})
	}))
	defer server.Close()
	endpoint = server.URL
	targets, err := Discover(context.Background(), endpoint)
	if err != nil || len(targets) != 1 || targets[0].ID != "page-1" {
		t.Fatal(targets, err)
	}
	for _, raw := range []string{"http://example.com:9222", "http://127.0.0.1", "http://user:password@127.0.0.1:9222", "http://127.0.0.1:9222/?key=secret"} {
		if _, err := Discover(context.Background(), raw); err == nil {
			t.Fatal("unsafe provider accepted", raw)
		}
	}
}

func TestDiscoverDoesNotFollowRedirects(t *testing.T) {
	hits := 0
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer server.Close()
	if _, err := Discover(context.Background(), server.URL); err == nil || hits != 0 {
		t.Fatal("discovery followed a redirect", err, hits)
	}
}
