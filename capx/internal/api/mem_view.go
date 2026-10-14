package api

// Memory region browser (CE's "浏览相关内存区域"): region enumeration, hex
// view reads, and a pure-Go x86 disassembler (golang.org/x/arch).

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	"golang.org/x/arch/x86/x86asm"
)

// memRegions lists the mapped regions of the attached process.
func (s *Server) memRegions(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(sid)
	regions, err := listRegions(e.pid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	kind := r.URL.Query().Get("kind")
	writableOnly := r.URL.Query().Get("writable") == "1"
	out := make([]map[string]any, 0, len(regions))
	for _, rg := range regions {
		k := rg.kind()
		if !regionKindOK(k, kind) {
			continue
		}
		if writableOnly && !rg.writable() {
			continue
		}
		out = append(out, map[string]any{
			"start": formatHex(rg.Start),
			"end":   formatHex(rg.End),
			"size":  rg.End - rg.Start,
			"perms": rg.Perms,
			"path":  rg.Path,
			"kind":  k,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "regions": out})
}

// disasmOne decodes a single x86-64 instruction from code at pc and returns
// its Intel-syntax text (e.g. "mov [rax+0x10], ebx"), or "" on failure. Used by
// the watchpoint engine to show the faulting instruction CE-style.
func disasmOne(code []byte, pc uint64) string {
	inst, err := x86asm.Decode(code, 64)
	if err != nil {
		return ""
	}
	return x86asm.IntelSyntax(inst, pc, nil)
}

// memView reads a window of process memory for the hex viewer.
// Query: addr=0x...&len=256 (len capped at 64 KiB).
func (s *Server) memView(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	addr, err := parseAddr(r.URL.Query().Get("addr"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad addr (use 0x... or decimal)")
		return
	}
	length := 256
	if q := r.URL.Query().Get("len"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 {
			length = v
		}
	}
	if length > 64*1024 {
		length = 64 * 1024
	}
	buf := make([]byte, length)
	n, err := sess.Read(addr, buf)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if n < 0 {
		n = 0
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"addr": formatHex(addr), "len": n, "bytes": hex.EncodeToString(buf[:n]),
	})
}

// memDisasm disassembles x86 code at an address (CE's memory-view lower pane).
// Query: addr=0x...&count=32&bits=64.
func (s *Server) memDisasm(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	addr, err := parseAddr(r.URL.Query().Get("addr"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad addr (use 0x... or decimal)")
		return
	}
	count := 32
	if q := r.URL.Query().Get("count"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 512 {
			count = v
		}
	}
	bits := 64
	if r.URL.Query().Get("bits") == "32" {
		bits = 32
	}
	// x86 instructions are at most 15 bytes.
	buf := make([]byte, count*15)
	n, err := sess.Read(addr, buf)
	if err != nil || n <= 0 {
		writeErr(w, http.StatusInternalServerError, "cannot read code at address")
		return
	}
	buf = buf[:n]

	type insn struct {
		Addr  string `json:"addr"`
		Bytes string `json:"bytes"`
		Text  string `json:"text"`
	}
	out := make([]insn, 0, count)
	pc := addr
	off := 0
	for len(out) < count && off < len(buf) {
		inst, err := x86asm.Decode(buf[off:], bits)
		if err != nil {
			out = append(out, insn{
				Addr:  formatHex(pc),
				Bytes: hex.EncodeToString(buf[off : off+1]),
				Text:  fmt.Sprintf("db 0x%02X", buf[off]),
			})
			off++
			pc++
			continue
		}
		out = append(out, insn{
			Addr:  formatHex(pc),
			Bytes: hex.EncodeToString(buf[off : off+inst.Len]),
			Text:  x86asm.IntelSyntax(inst, pc, nil),
		})
		off += inst.Len
		pc += uint64(inst.Len)
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "insns": out})
}
