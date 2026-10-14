package script

import (
	"strings"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

func TestMutateResponse(t *testing.T) {
	st := store.New(100)
	e := New(st)
	src := `
capx.on_response(function(r)
  if r.status == 200 then
    return { body = string.gsub(r.body, "Example", "CAPX"), headers = { ["X-Capx"] = "1" } }
  end
end)`
	if _, err := e.Add("rw", src); err != nil {
		t.Fatal(err)
	}
	hdr := map[string]string{"Content-Type": "text/html"}
	nh, nb, changed := e.MutateResponse(200, hdr, []byte("Example Domain"))
	if !changed {
		t.Fatal("expected response to be changed")
	}
	if string(nb) != "CAPX Domain" {
		t.Fatalf("body = %q, want %q", nb, "CAPX Domain")
	}
	if nh["X-Capx"] != "1" {
		t.Fatalf("header X-Capx = %q, want 1", nh["X-Capx"])
	}

	// A non-200 response is left untouched (callback returns nil).
	_, _, changed = e.MutateResponse(404, hdr, []byte("Example Domain"))
	if changed {
		t.Fatal("non-200 should be unchanged")
	}
}

func TestMutateRequest(t *testing.T) {
	st := store.New(100)
	e := New(st)
	if _, err := e.Add("req", `capx.on_request(function(r) return { body = r.body .. "&injected=1" } end)`); err != nil {
		t.Fatal(err)
	}
	_, nb, changed := e.MutateRequest("POST", "http://x/", "x", map[string]string{}, []byte("a=1"))
	if !changed || string(nb) != "a=1&injected=1" {
		t.Fatalf("req body = %q changed=%v", nb, changed)
	}
}

func TestSandboxBlocksDangerousLibs(t *testing.T) {
	st := store.New(100)
	e := New(st)
	// os / io must be unavailable in the sandbox.
	for _, src := range []string{
		`os.execute("echo pwned")`,
		`io.open("x", "w")`,
		`local f = load("return 1")`,
		`require("os")`,
	} {
		if _, err := e.Add("bad", src); err == nil {
			t.Fatalf("sandbox allowed dangerous source: %q", src)
		}
	}
	// A safe script using string/table/math still loads.
	if _, err := e.Add("ok", `capx.log(string.upper("hi") .. tostring(math.floor(3.7)))`); err != nil {
		t.Fatalf("safe script rejected: %v", err)
	}
}

func TestScriptTimeout(t *testing.T) {
	st := store.New(100)
	e := New(st)
	// An infinite loop in load must be interrupted, not hang the test.
	done := make(chan error, 1)
	go func() {
		_, err := e.Add("loop", `while true do end`)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("infinite-loop script should fail to load (timeout)")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("script load was not interrupted by timeout")
	}
}

func TestLoadAndHTTPCallback(t *testing.T) {
	st := store.New(100)
	e := New(st)
	src := `
capx.on_http(function(tx)
  if tx.status == 200 then capx.log("ok " .. tx.url) end
end)`
	s, err := e.Add("t", src)
	if err != nil {
		t.Fatal(err)
	}
	e.dispatch(model.Event{Kind: "http_tx", Data: &model.HTTPTx{ID: 1, Status: 200, URL: "http://x/"}})
	e.dispatch(model.Event{Kind: "http_tx", Data: &model.HTTPTx{ID: 2, Status: 404, URL: "http://y/"}})

	lines, ok := e.Log(s.ID)
	if !ok {
		t.Fatal("no log")
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "ok http://x/") {
		t.Fatalf("log = %v", lines)
	}
}

func TestAlertPublishes(t *testing.T) {
	st := store.New(100)
	e := New(st)
	ch, unsub := st.Subscribe(16)
	defer unsub()

	_, err := e.Add("a", `capx.on_hook(function(ev) if ev.dir == "send" then capx.alert("leak from "..ev.peer) end end)`)
	if err != nil {
		t.Fatal(err)
	}
	e.dispatch(model.Event{Kind: "hook_tls", Data: &model.HookEvent{PID: 9, Func: "SSL_write", Dir: "send", Peer: "evil.com:443"}})

	deadline := time.After(2 * time.Second)
	for {
		select {
		case ev := <-ch:
			if ev.Kind == "script_alert" {
				m := ev.Data.(map[string]string)
				if !strings.Contains(m["msg"], "evil.com") {
					t.Fatalf("alert msg = %q", m["msg"])
				}
				return
			}
		case <-deadline:
			t.Fatal("no script_alert event published")
		}
	}
}

func TestBadScriptRejected(t *testing.T) {
	e := New(store.New(10))
	if _, err := e.Add("bad", "this is not lua $$"); err == nil {
		t.Fatal("expected compile error")
	}
}

func TestDelete(t *testing.T) {
	e := New(store.New(10))
	s, _ := e.Add("x", `capx.log("loaded")`)
	if len(e.List()) != 1 {
		t.Fatal("expected 1 script")
	}
	if !e.Delete(s.ID) || e.Delete(s.ID) {
		t.Fatal("delete semantics")
	}
}

func TestFlowCallback(t *testing.T) {
	st := store.New(100)
	e := New(st)
	src := `
capx.on_flow(function(flow)
  capx.log("flow " .. flow.l4 .. " " .. flow.src_ip .. ":" .. tostring(flow.src_port))
end)`
	_, err := e.Add("f", src)
	if err != nil {
		t.Fatal(err)
	}
	e.dispatch(model.Event{Kind: "flow_new", Data: &model.Flow{
		ID: "tcp|10.0.0.1:12345>10.0.0.2:80", L4: model.TCP,
		SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80,
	}})
	scripts := e.List()
	if len(scripts) != 1 {
		t.Fatal("expected 1 script")
	}
	lines, ok := e.Log(scripts[0].ID)
	if !ok {
		t.Fatal("no log")
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "flow tcp 10.0.0.1:12345") {
		t.Fatalf("log = %v", lines)
	}
}
