package proxy

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"testing"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

func TestBuildReadWSFrameRoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte("hi"),
		bytes.Repeat([]byte("a"), 125),   // 1-byte length
		bytes.Repeat([]byte("b"), 126),   // 16-bit extended length
		bytes.Repeat([]byte("c"), 70000), // 64-bit extended length
	}
	for _, masked := range []bool{false, true} {
		for _, p := range payloads {
			frame := buildWSFrame(0x1, p, masked)
			br := bufio.NewReader(bytes.NewReader(frame))
			_, opcode, got, err := readWSFrame(br)
			if err != nil {
				t.Fatalf("masked=%v len=%d: %v", masked, len(p), err)
			}
			if opcode != 0x1 {
				t.Fatalf("opcode = %#x", opcode)
			}
			if !bytes.Equal(got, p) {
				t.Fatalf("masked=%v len=%d: payload mismatch", masked, len(p))
			}
		}
	}
}

func TestInterceptWSFrameDisabled(t *testing.T) {
	p := newTestProxy() // WS interception off
	wc := &wsConn{scheme: "https", host: "x", path: "/"}
	out, drop, changed := p.interceptWSFrame(wc, model.WSSend, 0x1, []byte("hello"))
	if drop || changed || string(out) != "hello" {
		t.Fatalf("disabled WS interception must pass through: drop=%v changed=%v out=%q", drop, changed, out)
	}
}

func TestInterceptWSFrameEdit(t *testing.T) {
	p := newTestProxy()
	p.SetInterceptWSEnabled(true)
	wc := &wsConn{id: "ws-1", url: "wss://x/s", scheme: "https", host: "x", path: "/s"}

	type res struct {
		out     []byte
		drop    bool
		changed bool
	}
	ch := make(chan res, 1)
	go func() {
		out, drop, changed := p.interceptWSFrame(wc, model.WSSend, 0x1, []byte(`{"act":"ping"}`))
		ch <- res{out, drop, changed}
	}()

	held := waitForHeld(t, p)
	if held.Kind != "ws" || held.Dir != "send" || held.Opcode != "text" || held.ConnID != "ws-1" {
		t.Fatalf("unexpected held WS frame: %+v", held)
	}
	p.icept.Decide(held.ID, `{"act":"pwn"}`, false)

	r := <-ch
	if r.drop || !r.changed || string(r.out) != `{"act":"pwn"}` {
		t.Fatalf("edit result = %+v", r)
	}
}

func TestInterceptWSFrameDrop(t *testing.T) {
	p := newTestProxy()
	p.SetInterceptWSEnabled(true)
	wc := &wsConn{id: "ws-1", scheme: "https", host: "x", path: "/"}

	ch := make(chan bool, 1)
	go func() {
		_, drop, _ := p.interceptWSFrame(wc, model.WSRecv, 0x1, []byte("x"))
		ch <- drop
	}()
	held := waitForHeld(t, p)
	p.icept.Decide(held.ID, "", true)
	if !<-ch {
		t.Fatal("expected drop")
	}
}

func TestReplayWSInjectsMaskedFrame(t *testing.T) {
	p := newTestProxy()
	p.st = store.New(16)

	c1, c2 := net.Pipe() // c1 = "up" side capx writes to; c2 = upstream peer
	wc := &wsConn{url: "wss://x/s", scheme: "https", host: "x", path: "/s", up: c1}
	p.ws.register(wc)

	// Read what capx injects toward the server.
	type frameRes struct {
		payload []byte
		err     error
	}
	got := make(chan frameRes, 1)
	go func() {
		br := bufio.NewReader(c2)
		_, _, payload, err := readWSFrame(br)
		got <- frameRes{payload, err}
	}()

	if _, err := p.ReplayWS(wc.id, "send", "text", "replayed!"); err != nil {
		t.Fatalf("ReplayWS: %v", err)
	}
	fr := <-got
	if fr.err != nil {
		t.Fatalf("read injected frame: %v", fr.err)
	}
	if string(fr.payload) != "replayed!" {
		t.Fatalf("injected payload = %q", fr.payload)
	}
	// The frame should have been recorded in history.
	if msgs := p.st.ListWS(); len(msgs) != 1 || msgs[0].Data != "replayed!" {
		t.Fatalf("history = %+v", msgs)
	}
}

func TestReplayWSUnknownConn(t *testing.T) {
	p := newTestProxy()
	p.st = store.New(16)
	if _, err := p.ReplayWS("nope", "send", "text", "x"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got %v", err)
	}
}

func TestWSMatchReplaceTextFrame(t *testing.T) {
	p := newTestProxy()
	wc := &wsConn{url: "wss://x/s", scheme: "https", host: "x", path: "/s"}
	if _, err := p.wsRules.Add(&WSMatchRule{Enabled: true, URL: "x/s", Dir: "send", Opcode: "text", Match: `"role":"user"`, Replace: `"role":"admin"`}); err != nil {
		t.Fatal(err)
	}
	out, drop, changed := p.wsRules.apply(wc, model.WSSend, 0x1, []byte(`{"role":"user"}`))
	if drop || !changed || string(out) != `{"role":"admin"}` {
		t.Fatalf("apply = out=%q drop=%v changed=%v", out, drop, changed)
	}
	if got := p.wsRules.List()[0].Hits; got != 1 {
		t.Fatalf("hits = %d", got)
	}
}

func TestWSMatchDropBinaryFrame(t *testing.T) {
	p := newTestProxy()
	wc := &wsConn{url: "wss://x/s", scheme: "https", host: "x", path: "/s"}
	if _, err := p.wsRules.Add(&WSMatchRule{Enabled: true, Opcode: "binary", Match: "AQID", Action: "drop"}); err != nil {
		t.Fatal(err)
	}
	_, drop, changed := p.wsRules.apply(wc, model.WSRecv, 0x2, []byte{1, 2, 3})
	if !drop || changed {
		t.Fatalf("expected drop without changed, got drop=%v changed=%v", drop, changed)
	}
}
