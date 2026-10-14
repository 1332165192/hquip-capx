package proxy

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

// wsTestProxy builds a proxy wired for WS macro/auto-reply integration tests.
func wsTestProxy() *Proxy {
	return &Proxy{scope: newScope(), session: newSessionEngine(), ws: newWSHub(), st: store.New(16)}
}

// registerPipedConn registers a wsConn whose server side is a net.Pipe, and
// returns the peer end so the test can read frames capx injects toward the
// server (WSSend direction).
func registerPipedConn(p *Proxy, url string) (*wsConn, net.Conn) {
	c1, c2 := net.Pipe()
	wc := &wsConn{url: url, scheme: "https", host: "x", path: "/s", up: c1}
	p.ws.register(wc)
	return wc, c2
}

func readInjectedPayload(t *testing.T, peer net.Conn) []byte {
	t.Helper()
	type fr struct {
		p   []byte
		err error
	}
	ch := make(chan fr, 1)
	go func() {
		_, _, pl, err := readWSFrame(bufio.NewReader(peer))
		ch <- fr{pl, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("read injected frame: %v", r.err)
		}
		return r.p
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for injected frame")
		return nil
	}
}

func TestExtractWSValues(t *testing.T) {
	frame := `{"type":"auth","token":"WS-TOK-9","seq":12}`
	exs := []Extractor{
		{Name: "tok", Expr: `"token":"([^"]+)"`},
		{Name: "seq", Expr: `"seq":(\d+)`},
		{Name: "skip", Expr: ""},     // empty expr ignored
		{Name: "", Expr: `whatever`}, // empty name ignored
		{Name: "bad", Expr: `([`},    // invalid regex ignored
	}
	got := extractWSValues(frame, exs)
	if got["tok"] != "WS-TOK-9" || got["seq"] != "12" {
		t.Fatalf("extractWSValues = %#v", got)
	}
	if _, ok := got["skip"]; ok {
		t.Fatal("empty expr should be skipped")
	}
	if len(got) != 2 {
		t.Fatalf("unexpected extra captures: %#v", got)
	}
}

func TestEvalWSReplyMatchAndExtract(t *testing.T) {
	e := newSessionEngine()
	e.SetWSRules([]WSRule{{
		Enabled: true, Name: "pong", URL: "chat.example", OnDir: "recv",
		When: `"type":"ping"`, SendDir: "send", Opcode: "text",
		Data:    `{"type":"pong","echo":"{{nonce}}"}`,
		Extract: []Extractor{{Name: "nonce", Expr: `"nonce":"([^"]+)"`}},
	}})

	// Matching recv frame: extracts nonce, then substitutes it into the reply.
	out := e.evalWSReply("wss://chat.example/ws", "recv", `{"type":"ping","nonce":"N7"}`)
	if len(out) != 1 {
		t.Fatalf("want 1 reply, got %d", len(out))
	}
	if out[0].Dir != "send" || out[0].Opcode != "text" {
		t.Fatalf("reply dir/opcode = %s/%s", out[0].Dir, out[0].Opcode)
	}
	if out[0].Data != `{"type":"pong","echo":"N7"}` {
		t.Fatalf("reply data = %q", out[0].Data)
	}
	if v, _ := e.vars.Get("nonce"); v != "N7" {
		t.Fatalf("nonce var = %q", v)
	}
}

func TestEvalWSReplyNonMatches(t *testing.T) {
	e := newSessionEngine()
	e.SetWSRules([]WSRule{{
		Enabled: true, Name: "r", URL: "chat.example", OnDir: "recv",
		When: `"type":"ping"`, Data: "pong", MinIntervalMs: 1,
	}})
	cases := []struct {
		name, url, dir, frame string
	}{
		{"wrong url", "wss://other.test/ws", "recv", `{"type":"ping"}`},
		{"wrong dir", "wss://chat.example/ws", "send", `{"type":"ping"}`},
		{"no regex match", "wss://chat.example/ws", "recv", `{"type":"data"}`},
	}
	for _, c := range cases {
		if out := e.evalWSReply(c.url, c.dir, c.frame); len(out) != 0 {
			t.Fatalf("%s: expected no reply, got %#v", c.name, out)
		}
	}
}

func TestEvalWSReplyDisabledRuleSkipped(t *testing.T) {
	e := newSessionEngine()
	e.SetWSRules([]WSRule{{Enabled: false, Name: "off", When: "", Data: "x"}})
	if out := e.evalWSReply("wss://a/ws", "recv", "anything"); len(out) != 0 {
		t.Fatalf("disabled rule should not fire: %#v", out)
	}
}

func TestEvalWSReplyAnyDirAnyFrame(t *testing.T) {
	e := newSessionEngine()
	// Empty OnDir + empty When = match every frame in either direction.
	e.SetWSRules([]WSRule{{Enabled: true, Name: "all", OnDir: "", When: "", Data: "ack", MinIntervalMs: 1}})
	if out := e.evalWSReply("wss://a/ws", "send", "hello"); len(out) != 1 {
		t.Fatalf("send dir should match (any): %#v", out)
	}
	time.Sleep(2 * time.Millisecond)
	if out := e.evalWSReply("wss://a/ws", "recv", "world"); len(out) != 1 {
		t.Fatalf("recv dir should match (any): %#v", out)
	}
}

func TestEvalWSReplyThrottle(t *testing.T) {
	e := newSessionEngine()
	e.SetWSRules([]WSRule{{
		Enabled: true, Name: "hb", OnDir: "recv", When: "ping",
		Data: "pong", MinIntervalMs: 10_000, // effectively once for the test
	}})
	if out := e.evalWSReply("wss://a/ws", "recv", "ping"); len(out) != 1 {
		t.Fatalf("first fire should reply: %#v", out)
	}
	// Immediate second identical frame is throttled.
	if out := e.evalWSReply("wss://a/ws", "recv", "ping"); len(out) != 0 {
		t.Fatalf("second fire within interval should be throttled: %#v", out)
	}
	// A different connection URL has its own throttle bucket.
	if out := e.evalWSReply("wss://b/ws", "recv", "ping"); len(out) != 1 {
		t.Fatalf("different conn should fire independently: %#v", out)
	}
}

func TestWSMacroConfigRoundTrip(t *testing.T) {
	e := newSessionEngine()
	e.SetWSMacros([]WSMacro{
		{Name: "sub", Steps: []WSMacroStep{{Dir: "send", Opcode: "text", Data: "{{t}}"}}},
		{Name: ""}, // unnamed macros are dropped
	})
	got := e.WSMacros()
	if len(got) != 1 || got[0].Name != "sub" {
		t.Fatalf("WSMacros = %#v", got)
	}
	if _, ok := e.wsMacro("sub"); !ok {
		t.Fatal("wsMacro(sub) not found")
	}
	if _, ok := e.wsMacro("nope"); ok {
		t.Fatal("wsMacro(nope) should not exist")
	}
}

func TestRunWSMacroInjectsAndSubstitutes(t *testing.T) {
	p := wsTestProxy()
	p.session.vars.Set("t", "world")
	p.session.SetWSMacros([]WSMacro{{Name: "hello", Steps: []WSMacroStep{
		{Dir: "send", Opcode: "text", Data: "hi-{{t}}"},
	}}})
	wc, peer := registerPipedConn(p, "wss://x/s")
	defer peer.Close()

	type runRes struct {
		run WSMacroRun
		err error
	}
	rc := make(chan runRes, 1)
	go func() { run, err := p.RunWSMacro("hello", wc.id); rc <- runRes{run, err} }()

	if got := string(readInjectedPayload(t, peer)); got != "hi-world" {
		t.Fatalf("injected payload = %q, want hi-world", got)
	}
	r := <-rc
	if r.err != nil {
		t.Fatalf("RunWSMacro: %v", r.err)
	}
	if len(r.run.Steps) != 1 || r.run.Steps[0].Error != "" || r.run.Steps[0].Dir != "send" {
		t.Fatalf("transcript = %+v", r.run.Steps)
	}
	if msgs := p.st.ListWS(); len(msgs) != 1 || msgs[0].Data != "hi-world" {
		t.Fatalf("history = %+v", msgs)
	}
}

func TestRunWSMacroUnknownsErr(t *testing.T) {
	p := wsTestProxy()
	if _, err := p.RunWSMacro("nope", "conn"); err == nil {
		t.Fatal("expected error for unknown conn")
	}
	wc, peer := registerPipedConn(p, "wss://x/s")
	defer peer.Close()
	if _, err := p.RunWSMacro("nope", wc.id); err == nil {
		t.Fatal("expected error for unknown macro")
	}
}

func TestApplyWSAutoReplyInjectsReply(t *testing.T) {
	p := wsTestProxy()
	p.session.SetWSRules([]WSRule{{
		Enabled: true, Name: "pong", OnDir: "recv", When: `"type":"ping"`,
		SendDir: "send", Opcode: "text", Data: `pong-{{nonce}}`,
		Extract: []Extractor{{Name: "nonce", Expr: `"nonce":"([^"]+)"`}},
	}})
	wc, peer := registerPipedConn(p, "wss://x/s")
	defer peer.Close()

	go p.applyWSAutoReply(wc, model.WSRecv, 0x1, []byte(`{"type":"ping","nonce":"Q9"}`))

	if got := string(readInjectedPayload(t, peer)); got != "pong-Q9" {
		t.Fatalf("auto-reply payload = %q, want pong-Q9", got)
	}
	if v, _ := p.session.vars.Get("nonce"); v != "Q9" {
		t.Fatalf("nonce var = %q", v)
	}
}

func TestApplyWSAutoReplyNoRulesNoInject(t *testing.T) {
	p := wsTestProxy()
	wc, peer := registerPipedConn(p, "wss://x/s")
	defer peer.Close()
	// No rules configured: must return immediately without writing a frame.
	done := make(chan struct{})
	go func() { p.applyWSAutoReply(wc, model.WSRecv, 0x1, []byte("ping")); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("applyWSAutoReply blocked with no rules configured")
	}
	if msgs := p.st.ListWS(); len(msgs) != 0 {
		t.Fatalf("expected no recorded frames, got %+v", msgs)
	}
}

func TestApplyWSAutoReplyOutOfScopeSkipped(t *testing.T) {
	p := wsTestProxy()
	// Restrict scope so the test connection's host "x" is out of scope.
	p.scope.SetRules([]ScopeRule{{Enabled: true, Host: "only.example"}}, nil)
	p.session.SetWSRules([]WSRule{{Enabled: true, Name: "r", OnDir: "recv", When: "", Data: "x"}})
	wc, peer := registerPipedConn(p, "wss://x/s")
	defer peer.Close()
	done := make(chan struct{})
	go func() { p.applyWSAutoReply(wc, model.WSRecv, 0x1, []byte("ping")); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("applyWSAutoReply blocked for out-of-scope conn")
	}
	if msgs := p.st.ListWS(); len(msgs) != 0 {
		t.Fatalf("out-of-scope conn should not auto-reply, got %+v", msgs)
	}
}
