package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// newTestProxy builds a minimal Proxy wired for the interception helpers
// without binding a CA, listener, or store (those are unneeded for unit tests).
func newTestProxy() *Proxy {
	return &Proxy{scope: newScope(), icept: newIntercept(), rules: newRuleSet(), wsRules: newWSRuleSet(), conds: newCondSet(), ws: newWSHub()}
}

// waitForHeld polls the intercept queue until one entry appears (or fails).
func waitForHeld(t *testing.T, p *Proxy) *HeldRequest {
	t.Helper()
	for i := 0; i < 200; i++ {
		if q := p.icept.Queue(); len(q) > 0 {
			return q[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no held message appeared")
	return nil
}

func TestInterceptRequestDisabledIsPassthrough(t *testing.T) {
	p := newTestProxy() // interception off by default
	req, _ := http.NewRequest("GET", "http://x/", nil)
	req.Host = "x"
	gotReq, gotRaw, drop, err := p.interceptRequest("http", req, "raw")
	if err != nil || drop || gotReq != req || gotRaw != "raw" {
		t.Fatalf("disabled interception must pass through unchanged: drop=%v", drop)
	}
}

func TestInterceptRequestEdit(t *testing.T) {
	p := newTestProxy()
	p.SetInterceptEnabled(true)

	req, _ := http.NewRequest("POST", "http://x/login", strings.NewReader("user=guest"))
	req.Host = "x"
	reqRaw, _ := dumpRequest(req)

	type res struct {
		r    *http.Request
		raw  string
		drop bool
	}
	ch := make(chan res, 1)
	go func() {
		gr, raw, drop, _ := p.interceptRequest("http", req, reqRaw)
		ch <- res{gr, raw, drop}
	}()

	held := waitForHeld(t, p)
	if held.Kind != "request" {
		t.Fatalf("kind = %q, want request", held.Kind)
	}
	edited := "POST /login HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nuser=admin"
	if !p.icept.Decide(held.ID, edited, false) {
		t.Fatal("decide failed")
	}
	out := <-ch
	if out.drop {
		t.Fatal("unexpected drop")
	}
	body, _ := io.ReadAll(out.r.Body)
	if string(body) != "user=admin" {
		t.Fatalf("edited body = %q, want user=admin", body)
	}
}

func TestInterceptRequestDrop(t *testing.T) {
	p := newTestProxy()
	p.SetInterceptEnabled(true)
	req, _ := http.NewRequest("GET", "http://x/", nil)
	req.Host = "x"

	ch := make(chan bool, 1)
	go func() {
		_, _, drop, _ := p.interceptRequest("http", req, "raw")
		ch <- drop
	}()
	held := waitForHeld(t, p)
	p.icept.Decide(held.ID, "", true)
	if !<-ch {
		t.Fatal("expected drop=true")
	}
}

func TestInterceptResponseEditStatusAndBody(t *testing.T) {
	p := newTestProxy()
	p.SetInterceptRespEnabled(true)

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{"role":"user"}`)),
	}
	resp.Header.Set("Content-Length", "15")

	ch := make(chan bool, 1)
	go func() { drop, _ := p.interceptResponse("https", "x", resp); ch <- drop }()

	held := waitForHeld(t, p)
	if held.Kind != "response" {
		t.Fatalf("kind = %q, want response", held.Kind)
	}
	edited := "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{\"role\":\"admin\"}"
	p.icept.Decide(held.ID, edited, false)
	if <-ch {
		t.Fatal("unexpected drop")
	}
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != `{"role":"admin"}` {
		t.Fatalf("body = %q", body)
	}
	if resp.Header.Get("Content-Length") != "16" {
		t.Fatalf("content-length = %q, want 16", resp.Header.Get("Content-Length"))
	}
}
