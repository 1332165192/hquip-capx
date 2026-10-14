package proxy

import (
	"bufio"
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hquip/capx/internal/store"
)

func TestReadWSFrameContinuationAndFIN(t *testing.T) {
	first := buildWSFrame(0x1, []byte("hel"), false)
	first[0] &^= 0x80 // clear FIN
	cont := buildWSFrame(0x0, []byte("lo"), false)
	raw := append(append([]byte{}, first...), cont...)
	br := bufio.NewReader(bytes.NewReader(raw))
	_, h0, opcode, fin, payload, err := readWSFrameEx(br)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 0x1 || fin || string(payload) != "hel" || h0&0x80 != 0 {
		t.Fatalf("first frame opcode=%#x fin=%v payload=%q", opcode, fin, payload)
	}
	_, _, opcode, fin, payload, err = readWSFrameEx(br)
	if err != nil {
		t.Fatal(err)
	}
	if opcode != 0x0 || !fin || string(payload) != "lo" {
		t.Fatalf("cont opcode=%#x fin=%v payload=%q", opcode, fin, payload)
	}
}

func TestRecordOutOfScopeStillStored(t *testing.T) {
	st := store.New(20)
	p := &Proxy{st: st, scope: newScope()}
	p.scope.AddInclude(ScopeRule{Enabled: true, Host: "keep.example"})
	req, _ := http.NewRequest("GET", "http://drop.example/x", nil)
	req.Host = "drop.example"
	p.record("http", req, nil, "GET /x HTTP/1.1\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n", 0, time.Now(), "", "")
	txs := st.ListHTTPTx("")
	if len(txs) != 1 {
		t.Fatalf("expected out-of-scope tx recorded, got %d", len(txs))
	}
	if !txs[0].OutOfScope {
		t.Fatalf("expected OutOfScope: %+v", txs[0])
	}
	if txs[0].InScope {
		t.Fatalf("InScope should match OutOfScope inverse: %+v", txs[0])
	}
	if in := st.FilterHTTPTx(store.HTTPFilter{Scope: "in"}); len(in) != 0 {
		t.Fatalf("scope=in should hide it: %+v", in)
	}
	if out := st.FilterHTTPTx(store.HTTPFilter{Scope: "out"}); len(out) != 1 {
		t.Fatalf("scope=out want 1, got %d", len(out))
	}
}

func TestBodyCaptureLimitOverride(t *testing.T) {
	t.Cleanup(func() { SetMaxBodyCapture(0) })
	SetMaxBodyCapture(8)
	var b strings.Builder
	appendBody(&b, []byte("0123456789abcdef"))
	if !strings.Contains(b.String(), "truncated by capx") {
		t.Fatalf("expected truncationker, got %q", b.String())
	}
	if !rawTruncated(b.String()) {
		t.Fatal("rawTruncated false")
	}
}
