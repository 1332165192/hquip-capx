package mobile

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestIOSReconnectFindsCurrentSessionAfterWDARestart(t *testing.T) {
	var generation atomic.Int32
	generation.Store(1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := "first"
		if generation.Load() == 2 {
			session = "second"
		}
		var value any
		switch {
		case r.URL.Path == "/status":
			value = map[string]any{"ready": true}
		case r.URL.Path == "/session":
			if r.Method != "GET" {
				t.Error("restart recovery replaced a live session")
			}
			value = map[string]any{"sessionId": session}
		case r.URL.Path == "/session/"+session+"/window/size":
			value = map[string]any{"width": 100, "height": 200}
		case r.URL.Path == "/session/"+session+"/appium/settings":
		default:
			value = map[string]any{"error": "invalid session id"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": value})
	}))
	defer server.Close()
	c := NewIOS()
	if _, err := c.Connect(server.URL, ""); err != nil {
		t.Fatal(err)
	}
	generation.Store(2)
	if _, err := c.Status(); err == nil {
		t.Fatal("expired session reported ready")
	}
	if _, err := c.Connect(server.URL, ""); err != nil {
		t.Fatal("explicit reconnect did not find current session", err)
	}
	if !strings.Contains(c.route("/window/size"), "/second/") {
		t.Fatal("old session retained")
	}
}
