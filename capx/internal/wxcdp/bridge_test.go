package wxcdp

import (
	"encoding/json"
	"golang.org/x/net/websocket"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExternalEndpointValidation(t *testing.T) {
	for _, endpoint := range []string{"", "ws://example.com:1234/", "ws://192.168.1.2:1234/", "ws://127.0.0.1/", "ws://user:pass@127.0.0.1:1234/", "ws://127.0.0.1:1234/?token=secret", "http://127.0.0.1:1234/"} {
		if _, err := normalizeEndpoint(endpoint); err == nil {
			t.Fatal("accepted", endpoint)
		}
	}
	if endpoint, err := normalizeEndpoint("ws://localhost:1234/devtools/page/test"); err != nil || endpoint != "ws://127.0.0.1:1234/devtools/page/test" {
		t.Fatal(endpoint, err)
	}
}

func TestExternalCallsAndStopCancelPending(t *testing.T) {
	server := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
		defer conn.Close()
		for {
			var raw string
			if err := websocket.Message.Receive(conn, &raw); err != nil {
				return
			}
			var command struct {
				ID     uint64 `json:"id"`
				Method string `json:"method"`
			}
			if err := json.Unmarshal([]byte(raw), &command); err != nil {
				return
			}
			if command.Method == "Runtime.wait" {
				continue
			}
			data, _ := json.Marshal(map[string]any{"id": command.ID, "result": map[string]any{"value": 42}})
			websocket.Message.Send(conn, string(data))
		}
	}))
	defer server.Close()
	t.Setenv("CAPX_CDP_WS", strings.Replace(server.URL, "http://", "ws://", 1))
	b := New(nil)
	defer b.Stop()
	if _, err := b.Start(); err != nil {
		t.Fatal(err)
	}
	if raw, err := b.Call("Runtime.evaluate", map[string]any{"expression": "42"}, time.Second); err != nil || !strings.Contains(string(raw), `"value":42`) {
		t.Fatal(string(raw), err)
	}
	if _, err := b.Call("Runtime.wait", nil, 10*time.Millisecond); err == nil {
		t.Fatal("timeout missing")
	}
	done := make(chan error, 1)
	go func() { _, err := b.Call("Runtime.wait", nil, time.Second); done <- err }()
	b.Stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stop did not cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("pending call hung")
	}
	if b.Status()["running"] != false {
		t.Fatal("status running after stop")
	}
}
