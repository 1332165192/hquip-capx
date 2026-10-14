package proxy

import (
	"net/http"
	"testing"

	"github.com/hquip/capx/internal/store"
)

func TestH2WSToH1Request(t *testing.T) {
	r, _ := http.NewRequest(http.MethodConnect, "https://example.com/chat", nil)
	r.Host = "example.com"
	r.Header.Set(":protocol", "websocket")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	got := h2WSToH1Request(r, "example.com")
	if got.Method != http.MethodGet {
		t.Fatalf("method = %s", got.Method)
	}
	if got.Header.Get("Upgrade") != "websocket" {
		t.Fatalf("upgrade = %q", got.Header.Get("Upgrade"))
	}
	if got.Header.Get("Sec-WebSocket-Key") == "" {
		t.Fatal("missing key")
	}
	if got.Header.Get(":protocol") != "" {
		t.Fatal("pseudo-header leaked")
	}
}

func TestHTTP3StartStop(t *testing.T) {
	t.Setenv("CAPX_DATA_DIR", t.TempDir())
	p, err := New(store.New(100))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.StartHTTP3("127.0.0.1:0"); err != nil {
		t.Fatalf("start http3: %v", err)
	}
	on, addr := p.HTTP3Status()
	if !on || addr == "" {
		t.Fatalf("status on=%v addr=%q", on, addr)
	}
	if err := p.StopHTTP3(); err != nil {
		t.Fatal(err)
	}
	on, _ = p.HTTP3Status()
	if on {
		t.Fatal("still running")
	}
}
