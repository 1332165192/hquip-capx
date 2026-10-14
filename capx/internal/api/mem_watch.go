package api

// "Find out what accesses / writes this address" (CE's 找出是什么改写了这个地址):
// a hardware debug-register watchpoint on the target address records the
// instruction pointer of every access. Platform support lives in
// mem_watch_<os>.go; startWatcher returns an error where unsupported.

import (
	"net/http"
)

// watchHit is one unique instruction that touched a watched address. Regs and
// Insn are filled where the platform can capture them (Windows): the register
// snapshot at the most recent hit and the disassembled faulting instruction —
// the extra context CE shows in "find out what writes this address".
type watchHit struct {
	RIP   string            `json:"rip"`
	Count uint64            `json:"count"`
	Slot  int               `json:"slot"` // debug-register slot (DR0..DR3) that fired
	Insn  string            `json:"insn,omitempty"`
	Regs  map[string]string `json:"regs,omitempty"`
}

// watchSpec is one hardware breakpoint slot: an address, a width, and the
// access mode ("w" writes, "rw" reads+writes, "x" execute).
type watchSpec struct {
	Addr uint64
	Size int
	Mode string
}

// memWatcher is a running set of hardware watchpoints.
type memWatcher interface {
	Hits() []watchHit
	Err() error
	Stop()
	Context() map[string]string
}

// memWatchStart installs up to 4 hardware breakpoints. Accepts either a single
// {addr, size, mode} or a {watches:[{addr,size,mode},...]} batch. mode is
// "w" (writes), "rw" (accesses) or "x" (execute). Execute breakpoints ignore
// size (forced to 1, as x86 requires LEN=00).
func (s *Server) memWatchStart(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(sid)
	var req struct {
		Addr    string `json:"addr"`
		Size    int    `json:"size"`
		Mode    string `json:"mode"`
		Watches []struct {
			Addr string `json:"addr"`
			Size int    `json:"size"`
			Mode string `json:"mode"`
		} `json:"watches"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	// Normalise into a single list of raw {addr,size,mode}.
	type raw struct {
		addr string
		size int
		mode string
	}
	var raws []raw
	if len(req.Watches) > 0 {
		for _, x := range req.Watches {
			raws = append(raws, raw{x.Addr, x.Size, x.Mode})
		}
	} else {
		raws = append(raws, raw{req.Addr, req.Size, req.Mode})
	}
	if len(raws) > 4 {
		writeErr(w, http.StatusBadRequest, "at most 4 hardware breakpoints (DR0–DR3)")
		return
	}

	var specs []watchSpec
	for _, rw := range raws {
		addr, err := parseAddr(rw.addr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad addr (use 0x... or decimal)")
			return
		}
		mode := rw.mode
		if mode == "" {
			mode = "w"
		}
		if mode != "w" && mode != "rw" && mode != "x" {
			writeErr(w, http.StatusBadRequest, `mode must be "w" (writes), "rw" (accesses) or "x" (execute)`)
			return
		}
		size := rw.size
		if mode == "x" {
			size = 1 // execute breakpoints require LEN=00
		} else {
			if size == 0 {
				size = 4
			}
			if size != 1 && size != 2 && size != 4 && size != 8 {
				writeErr(w, http.StatusBadRequest, "size must be 1, 2, 4 or 8")
				return
			}
			if addr%uint64(size) != 0 {
				writeErr(w, http.StatusBadRequest, "addr must be aligned to size")
				return
			}
		}
		specs = append(specs, watchSpec{Addr: addr, Size: size, Mode: mode})
	}

	e.mu.Lock()
	if e.watch != nil {
		e.watch.Stop()
		e.watch = nil
	}
	wt, err := startWatcher(e.pid, specs)
	if err != nil {
		e.mu.Unlock()
		writeErr(w, http.StatusNotImplemented, err.Error())
		return
	}
	e.watch = wt
	e.mu.Unlock()

	watching := make([]map[string]any, len(specs))
	for i, sp := range specs {
		watching[i] = map[string]any{"slot": i, "addr": formatHex(sp.Addr), "size": sp.Size, "mode": sp.Mode}
	}
	// Keep the single-watch response fields for backwards compatibility.
	resp := map[string]any{
		"watches": watching,
		"count":   len(specs),
		"note":    "x86 硬件断点最多 4 个（DR0–DR3）。Windows 使用 DebugActiveProcess，目标可能被短暂暂停；macOS 需 -tags machwatch。",
	}
	if len(specs) == 1 {
		resp["watching"] = formatHex(specs[0].Addr)
		resp["size"] = specs[0].Size
		resp["mode"] = specs[0].Mode
	}
	writeJSON(w, http.StatusOK, resp)
}

// memWatchStatus reports recorded hits so far.
func (s *Server) memWatchStatus(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(sid)
	e.mu.Lock()
	wt := e.watch
	e.mu.Unlock()
	if wt == nil {
		writeJSON(w, http.StatusOK, map[string]any{"running": false, "hits": []watchHit{}})
		return
	}
	resp := map[string]any{"running": true, "hits": wt.Hits()}
	if err := wt.Err(); err != nil {
		resp["error"] = err.Error()
	}
	if ctx := wt.Context(); len(ctx) > 0 {
		resp["context"] = ctx
		if rsp := ctx["rsp"]; rsp != "" {
			resp["rsp"] = rsp
		}
		if rip := ctx["rip"]; rip != "" {
			resp["rip"] = rip
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// memWatchStop removes the watchpoint and detaches.
func (s *Server) memWatchStop(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(sid)
	e.mu.Lock()
	wt := e.watch
	e.watch = nil
	e.mu.Unlock()
	if wt != nil {
		wt.Stop()
	}
	writeJSON(w, http.StatusOK, map[string]any{"stopped": wt != nil})
}
