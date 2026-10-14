// Package script is the M7 Lua scripting layer. It lets operators load small
// Lua plugins that react to live capture events (HTTP transactions, TLS hook
// plaintext, flows) — e.g. to flag a token, count statuses, or raise an alert —
// without recompiling capx. It uses gopher-lua (pure Go), so no cgo and no
// build tags: scripting is always available.
//
// Concurrency model: a single dispatcher goroutine drains the store event bus
// and invokes each script's callbacks under the engine mutex, so each script's
// (non-thread-safe) *lua.LState is only ever touched from one goroutine.
package script

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	lua "github.com/yuin/gopher-lua"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

const maxLogLines = 200

// scriptTimeout bounds how long a single script callback (or its initial load)
// may run, so a buggy/malicious infinite loop cannot wedge the dispatcher.
const scriptTimeout = 500 * time.Millisecond

// Script is one loaded Lua plugin.
type Script struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Source  string `json:"source,omitempty"`

	// callMu serializes access to ls so a Delete (which Closes ls) can never
	// race with the dispatcher mid-callback.
	callMu sync.Mutex
	ls     *lua.LState
	closed bool
	onHTTP *lua.LFunction
	onHook *lua.LFunction
	onFlow *lua.LFunction
	onReq  *lua.LFunction // mutate outgoing requests
	onResp *lua.LFunction // mutate incoming responses

	logMu sync.Mutex
	log   []string
	Hits  uint64 `json:"hits"`
}

// MemAccess is the optional memory backend a script can drive through the
// `capx.mem` table. The api layer implements it over the live scan engine;
// when nil, the mem.* functions return errors. Types are short names:
// "i8","u8","i16","u16","i32","u32","i64","u64","f32","f64".
type MemAccess interface {
	Read(pid uint32, addr uint64, typ string) (float64, bool)
	Write(pid uint32, addr uint64, typ string, val float64) bool
	Scan(pid uint32, typ string, val float64, max int) []string
	Freeze(pid uint32, addr uint64, typ string, val float64, mode string) bool
	Unfreeze(pid uint32, addr uint64) bool
}

// Engine owns the loaded scripts and the event dispatcher.
type Engine struct {
	st *store.Store

	mu      sync.Mutex
	scripts []*Script
	seq     int
	mem     MemAccess

	started bool
	unsub   func()
}

// New returns a script engine bound to a store.
func New(st *store.Store) *Engine { return &Engine{st: st} }

// SetMem wires a memory backend so loaded scripts can read/write/scan/freeze
// process memory via the `capx.mem` table. Call before scripts are added.
func (e *Engine) SetMem(m MemAccess) {
	e.mu.Lock()
	e.mem = m
	e.mu.Unlock()
}

// Start begins draining store events into loaded scripts. Idempotent.
func (e *Engine) Start() {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	ch, unsub := e.st.Subscribe(512)
	e.started, e.unsub = true, unsub
	e.mu.Unlock()

	go func() {
		for ev := range ch {
			e.dispatch(ev)
		}
	}()
}

// Stop halts the dispatcher.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.unsub != nil {
		e.unsub()
		e.unsub = nil
	}
	e.started = false
}

// List returns a snapshot of loaded scripts (without LState internals).
func (e *Engine) List() []*Script {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*Script, 0, len(e.scripts))
	for _, s := range e.scripts {
		out = append(out, &Script{ID: s.ID, Name: s.Name, Enabled: s.Enabled, Hits: atomic.LoadUint64(&s.Hits)})
	}
	return out
}

// Log returns the captured log lines for a script id.
func (e *Engine) Log(id string) ([]string, bool) {
	e.mu.Lock()
	var target *Script
	for _, s := range e.scripts {
		if s.ID == id {
			target = s
			break
		}
	}
	e.mu.Unlock()
	if target == nil {
		return nil, false
	}
	target.logMu.Lock()
	defer target.logMu.Unlock()
	out := make([]string, len(target.log))
	copy(out, target.log)
	return out, true
}

// Add compiles and loads a Lua script. The script registers callbacks via the
// injected `capx` table; compilation errors are returned. The interpreter is
// sandboxed (no os/io/package/debug libs) and the load is time-bounded.
func (e *Engine) Add(name, source string) (*Script, error) {
	ls := newSandbox()
	s := &Script{Name: name, Enabled: true, Source: source, ls: ls}
	e.registerAPI(ls, s)

	ctx, cancel := context.WithTimeout(context.Background(), scriptTimeout)
	ls.SetContext(ctx)
	err := ls.DoString(source)
	ls.RemoveContext()
	cancel()
	if err != nil {
		ls.Close()
		return nil, fmt.Errorf("lua load error: %w", err)
	}

	e.mu.Lock()
	e.seq++
	s.ID = "script-" + strconv.Itoa(e.seq)
	e.scripts = append(e.scripts, s)
	e.mu.Unlock()

	// Auto-start the dispatcher on first script.
	e.Start()
	return s, nil
}

// ScriptDef is a serializable script definition for project bundles.
type ScriptDef struct {
	Name    string `json:"name"`
	Source  string `json:"source"`
	Enabled bool   `json:"enabled"`
}

// Export returns every loaded script's name + source for a project bundle.
func (e *Engine) Export() []ScriptDef {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]ScriptDef, 0, len(e.scripts))
	for _, s := range e.scripts {
		out = append(out, ScriptDef{Name: s.Name, Source: s.Source, Enabled: s.Enabled})
	}
	return out
}

// Delete unloads a script by id. It removes the script from the dispatch set
// first, then closes its LState under the script's callMu so a concurrent
// in-flight callback finishes before the state is freed.
func (e *Engine) Delete(id string) bool {
	e.mu.Lock()
	var target *Script
	for i, s := range e.scripts {
		if s.ID == id {
			target = s
			e.scripts = append(e.scripts[:i], e.scripts[i+1:]...)
			break
		}
	}
	e.mu.Unlock()
	if target == nil {
		return false
	}
	target.callMu.Lock()
	target.closed = true
	target.ls.Close()
	target.callMu.Unlock()
	return true
}

// newSandbox builds a Lua state with only the safe standard libraries (base,
// table, string, math) — no os/io/package/debug/coroutine — and strips the
// code-loading/file primitives from the base library, so a loaded plugin
// cannot execute commands, touch the filesystem, or load native code.
func newSandbox() *lua.LState {
	ls := lua.NewState(lua.Options{SkipOpenLibs: true})
	for _, lib := range []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
	} {
		ls.Push(ls.NewFunction(lib.fn))
		ls.Push(lua.LString(lib.name))
		ls.Call(1, 0)
	}
	for _, name := range []string{"dofile", "loadfile", "load", "loadstring", "require", "collectgarbage"} {
		ls.SetGlobal(name, lua.LNil)
	}
	return ls
}

// registerAPI installs the `capx` table with logging, callback registration,
// and alerting into a script's LState.
func (e *Engine) registerAPI(ls *lua.LState, s *Script) {
	tbl := ls.NewTable()
	ls.SetGlobal("capx", tbl)

	ls.SetField(tbl, "log", ls.NewFunction(func(l *lua.LState) int {
		s.appendLog(l.CheckString(1))
		return 0
	}))
	ls.SetField(tbl, "on_http", ls.NewFunction(func(l *lua.LState) int {
		s.onHTTP = l.CheckFunction(1)
		return 0
	}))
	ls.SetField(tbl, "on_hook", ls.NewFunction(func(l *lua.LState) int {
		s.onHook = l.CheckFunction(1)
		return 0
	}))
	ls.SetField(tbl, "on_flow", ls.NewFunction(func(l *lua.LState) int {
		s.onFlow = l.CheckFunction(1)
		return 0
	}))
	// on_request(fn) / on_response(fn): fn receives a table {method,url,host,
	// status,headers,body} and may return a table with modified {headers,body}
	// to rewrite the live request/response (mitmproxy-style transforms).
	ls.SetField(tbl, "on_request", ls.NewFunction(func(l *lua.LState) int {
		s.onReq = l.CheckFunction(1)
		return 0
	}))
	ls.SetField(tbl, "on_response", ls.NewFunction(func(l *lua.LState) int {
		s.onResp = l.CheckFunction(1)
		return 0
	}))
	// capx.alert(msg) publishes an event back onto the bus (visible in the UI
	// and SSE stream). Guard against feedback by using a distinct kind.
	ls.SetField(tbl, "alert", ls.NewFunction(func(l *lua.LState) int {
		msg := l.CheckString(1)
		s.appendLog("ALERT: " + msg)
		e.st.Publish(model.Event{Source: model.SourceProxy, Kind: "script_alert",
			Data: map[string]string{"script": s.Name, "msg": msg}})
		return 0
	}))

	e.registerMemAPI(ls, s, tbl)
}

// registerMemAPI installs the `capx.mem` sub-table: read/write/scan/freeze/
// unfreeze over the live memory engine. All functions no-op (returning nil /
// false) when no MemAccess backend is wired.
func (e *Engine) registerMemAPI(ls *lua.LState, s *Script, parent *lua.LTable) {
	mem := ls.NewTable()
	ls.SetField(parent, "mem", mem)

	// capx.mem.read(pid, addr, type) -> number|nil
	ls.SetField(mem, "read", ls.NewFunction(func(l *lua.LState) int {
		if e.mem == nil {
			l.Push(lua.LNil)
			return 1
		}
		v, ok := e.mem.Read(uint32(l.CheckInt(1)), uint64(l.CheckNumber(2)), l.CheckString(3))
		if !ok {
			l.Push(lua.LNil)
			return 1
		}
		l.Push(lua.LNumber(v))
		return 1
	}))

	// capx.mem.write(pid, addr, type, value) -> bool
	ls.SetField(mem, "write", ls.NewFunction(func(l *lua.LState) int {
		if e.mem == nil {
			l.Push(lua.LFalse)
			return 1
		}
		ok := e.mem.Write(uint32(l.CheckInt(1)), uint64(l.CheckNumber(2)), l.CheckString(3), float64(l.CheckNumber(4)))
		l.Push(lua.LBool(ok))
		return 1
	}))

	// capx.mem.scan(pid, type, value [, max]) -> table of hex address strings
	ls.SetField(mem, "scan", ls.NewFunction(func(l *lua.LState) int {
		out := ls.NewTable()
		if e.mem != nil {
			max := 1000
			if l.GetTop() >= 4 {
				max = l.CheckInt(4)
			}
			addrs := e.mem.Scan(uint32(l.CheckInt(1)), l.CheckString(2), float64(l.CheckNumber(3)), max)
			for i, a := range addrs {
				ls.RawSetInt(out, i+1, lua.LString(a))
			}
		}
		l.Push(out)
		return 1
	}))

	// capx.mem.freeze(pid, addr, type, value [, mode]) -> bool
	ls.SetField(mem, "freeze", ls.NewFunction(func(l *lua.LState) int {
		if e.mem == nil {
			l.Push(lua.LFalse)
			return 1
		}
		mode := "set"
		if l.GetTop() >= 5 {
			mode = l.CheckString(5)
		}
		ok := e.mem.Freeze(uint32(l.CheckInt(1)), uint64(l.CheckNumber(2)), l.CheckString(3), float64(l.CheckNumber(4)), mode)
		l.Push(lua.LBool(ok))
		return 1
	}))

	// capx.mem.unfreeze(pid, addr) -> bool
	ls.SetField(mem, "unfreeze", ls.NewFunction(func(l *lua.LState) int {
		if e.mem == nil {
			l.Push(lua.LFalse)
			return 1
		}
		ok := e.mem.Unfreeze(uint32(l.CheckInt(1)), uint64(l.CheckNumber(2)))
		l.Push(lua.LBool(ok))
		return 1
	}))
}

// WantsRequest reports whether any enabled script registered an on_request
// hook. Implements proxy.HTTPMutator so the proxy skips body rebuilding when no
// script needs the request.
func (e *Engine) WantsRequest() bool { return e.hasHook(true) }

// WantsResponse reports whether any enabled script registered an on_response hook.
func (e *Engine) WantsResponse() bool { return e.hasHook(false) }

func (e *Engine) hasHook(req bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.scripts {
		if !s.Enabled {
			continue
		}
		if req && s.onReq != nil {
			return true
		}
		if !req && s.onResp != nil {
			return true
		}
	}
	return false
}

// MutateRequest runs every loaded script's on_request callback over the given
// request, returning the (possibly modified) headers and body and whether any
// script changed them. Implements proxy.HTTPMutator.
func (e *Engine) MutateRequest(method, url, host string, headers map[string]string, body []byte) (map[string]string, []byte, bool) {
	return e.mutate(true, method, url, host, 0, headers, body)
}

// MutateResponse runs every loaded script's on_response callback over the given
// response. Implements proxy.HTTPMutator.
func (e *Engine) MutateResponse(status int, headers map[string]string, body []byte) (map[string]string, []byte, bool) {
	return e.mutate(false, "", "", "", status, headers, body)
}

func (e *Engine) mutate(isReq bool, method, url, host string, status int, headers map[string]string, body []byte) (map[string]string, []byte, bool) {
	e.mu.Lock()
	scripts := make([]*Script, len(e.scripts))
	copy(scripts, e.scripts)
	e.mu.Unlock()

	changed := false
	for _, s := range scripts {
		if !s.Enabled {
			continue
		}
		var fn *lua.LFunction
		if isReq {
			fn = s.onReq
		} else {
			fn = s.onResp
		}
		if fn == nil {
			continue
		}
		nh, nb, ok := s.callMutate(fn, method, url, host, status, headers, body)
		if ok {
			headers, body, changed = nh, nb, true
		}
	}
	return headers, body, changed
}

// callMutate invokes a request/response mutator callback under the script lock
// with a timeout, returning the modified headers/body when the script returned
// a table.
func (s *Script) callMutate(fn *lua.LFunction, method, url, host string, status int, headers map[string]string, body []byte) (map[string]string, []byte, bool) {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	if s.closed {
		return headers, body, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), scriptTimeout)
	defer cancel()
	s.ls.SetContext(ctx)
	defer s.ls.RemoveContext()

	ls := s.ls
	arg := ls.NewTable()
	ls.SetField(arg, "method", lua.LString(method))
	ls.SetField(arg, "url", lua.LString(url))
	ls.SetField(arg, "host", lua.LString(host))
	ls.SetField(arg, "status", lua.LNumber(status))
	ls.SetField(arg, "body", lua.LString(string(body)))
	ht := ls.NewTable()
	for k, v := range headers {
		ls.SetField(ht, k, lua.LString(v))
	}
	ls.SetField(arg, "headers", ht)

	ls.Push(fn)
	ls.Push(arg)
	if err := ls.PCall(1, 1, nil); err != nil {
		s.appendLog("ERROR(mutate): " + err.Error())
		return headers, body, false
	}
	ret := ls.Get(-1)
	ls.Pop(1)
	rt, ok := ret.(*lua.LTable)
	if !ok {
		return headers, body, false // nil / no change
	}
	atomic.AddUint64(&s.Hits, 1)
	newBody := body
	if bv, ok := ls.GetField(rt, "body").(lua.LString); ok {
		newBody = []byte(string(bv))
	}
	newHeaders := headers
	if hv, ok := ls.GetField(rt, "headers").(*lua.LTable); ok {
		newHeaders = make(map[string]string, len(headers))
		for k, v := range headers {
			newHeaders[k] = v
		}
		hv.ForEach(func(k, v lua.LValue) {
			newHeaders[k.String()] = v.String()
		})
	}
	return newHeaders, newBody, true
}

func (s *Script) appendLog(line string) {
	s.logMu.Lock()
	s.log = append(s.log, time.Now().UTC().Format("15:04:05")+" "+line)
	if len(s.log) > maxLogLines {
		s.log = s.log[len(s.log)-maxLogLines:]
	}
	s.logMu.Unlock()
}

// dispatch routes one event to every enabled script's matching callback. It
// snapshots the script set under the engine lock, then invokes callbacks
// without holding it, so a slow script cannot block List/Add/Delete or other
// scripts' management. Each script's LState is still only ever touched by this
// single dispatcher goroutine, serialized per-script via callMu.
func (e *Engine) dispatch(ev model.Event) {
	e.mu.Lock()
	scripts := make([]*Script, len(e.scripts))
	copy(scripts, e.scripts)
	e.mu.Unlock()

	for _, s := range scripts {
		if !s.Enabled {
			continue
		}
		switch ev.Kind {
		case "http_tx":
			if s.onHTTP != nil {
				if tx, ok := ev.Data.(*model.HTTPTx); ok {
					s.call(s.onHTTP, func(ls *lua.LState) lua.LValue { return httpTable(ls, tx) })
				}
			}
		case "hook_tls":
			if s.onHook != nil {
				if h, ok := ev.Data.(*model.HookEvent); ok {
					s.call(s.onHook, func(ls *lua.LState) lua.LValue { return hookTable(ls, h) })
				}
			}
		case "flow_new":
			if s.onFlow != nil {
				if f, ok := ev.Data.(*model.Flow); ok {
					s.call(s.onFlow, func(ls *lua.LState) lua.LValue { return flowTable(ls, f) })
				}
			}
		}
	}
}

// call invokes a script callback under the script's callMu (guarding against a
// concurrent Delete/Close) with a per-call timeout enforced via the LState
// context. mkArg builds the argument lazily so it is constructed on the right
// LState only when the script is still alive.
func (s *Script) call(fn *lua.LFunction, mkArg func(*lua.LState) lua.LValue) {
	s.callMu.Lock()
	defer s.callMu.Unlock()
	if s.closed {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), scriptTimeout)
	defer cancel()
	s.ls.SetContext(ctx)
	defer s.ls.RemoveContext()

	s.ls.Push(fn)
	s.ls.Push(mkArg(s.ls))
	if err := s.ls.PCall(1, 0, nil); err != nil {
		s.appendLog("ERROR: " + err.Error())
		return
	}
	atomic.AddUint64(&s.Hits, 1)
}

func httpTable(ls *lua.LState, tx *model.HTTPTx) *lua.LTable {
	t := ls.NewTable()
	ls.SetField(t, "id", lua.LNumber(tx.ID))
	ls.SetField(t, "flow_id", lua.LString(tx.FlowID))
	ls.SetField(t, "scheme", lua.LString(tx.Scheme))
	ls.SetField(t, "method", lua.LString(tx.Method))
	ls.SetField(t, "host", lua.LString(tx.Host))
	ls.SetField(t, "url", lua.LString(tx.URL))
	ls.SetField(t, "status", lua.LNumber(tx.Status))
	ls.SetField(t, "mime", lua.LString(tx.MIME))
	ls.SetField(t, "req", lua.LString(tx.ReqRaw))
	ls.SetField(t, "resp", lua.LString(tx.RespRaw))
	return t
}

func hookTable(ls *lua.LState, h *model.HookEvent) *lua.LTable {
	t := ls.NewTable()
	ls.SetField(t, "pid", lua.LNumber(h.PID))
	ls.SetField(t, "func", lua.LString(h.Func))
	ls.SetField(t, "dir", lua.LString(h.Dir))
	ls.SetField(t, "len", lua.LNumber(h.Len))
	ls.SetField(t, "peer", lua.LString(h.Peer))
	ls.SetField(t, "data", lua.LString(h.Data))
	return t
}

func flowTable(ls *lua.LState, f *model.Flow) *lua.LTable {
	t := ls.NewTable()
	ls.SetField(t, "id", lua.LString(f.ID))
	ls.SetField(t, "l4", lua.LString(string(f.L4)))
	ls.SetField(t, "src_ip", lua.LString(f.SrcIP))
	ls.SetField(t, "src_port", lua.LNumber(f.SrcPort))
	ls.SetField(t, "dst_ip", lua.LString(f.DstIP))
	ls.SetField(t, "dst_port", lua.LNumber(f.DstPort))
	ls.SetField(t, "bytes", lua.LNumber(f.Bytes))
	ls.SetField(t, "packets", lua.LNumber(f.Packets))
	return t
}
