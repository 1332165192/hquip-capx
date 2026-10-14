package api

// Code patching / injection (CE's "code injection" + auto-assemble building
// blocks): write arbitrary bytes at an address (optionally saving the original
// for one-click revert), NOP out a byte range, and allocate executable memory
// in the target to host a code cave. These are mutating "active" operations and
// are gated by the security policy.

import (
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
)

// patchStore remembers original bytes per (sid, addr) so a patch can be reverted.
type patchStore struct {
	mu    sync.Mutex
	saved map[string]map[uint64][]byte // sid -> addr -> original bytes
}

func newPatchStore() *patchStore { return &patchStore{saved: map[string]map[uint64][]byte{}} }

func (p *patchStore) remember(sid string, addr uint64, orig []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := p.saved[sid]
	if m == nil {
		m = map[uint64][]byte{}
		p.saved[sid] = m
	}
	if _, exists := m[addr]; !exists { // keep the earliest original
		m[addr] = append([]byte(nil), orig...)
	}
}

func (p *patchStore) original(sid string, addr uint64) ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, ok := p.saved[sid][addr]
	return b, ok
}

// memPatch writes raw bytes at an address. With "nop":true it fills the range
// [addr, addr+len) with 0x90 (x86 NOP); otherwise it writes the hex "bytes".
// The original bytes are saved so memPatch with "revert":true restores them.
func (s *Server) memPatch(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Addr   string `json:"addr"`
		Bytes  string `json:"bytes"`  // hex, e.g. "90 90 90" or "9090"
		NOP    int    `json:"nop"`    // when >0, write this many 0x90 bytes
		Revert bool   `json:"revert"` // restore previously saved original bytes
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	addr, err := parseAddr(req.Addr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad addr (use 0x... or decimal)")
		return
	}

	if req.Revert {
		orig, ok := s.patches.original(sid, addr)
		if !ok {
			writeErr(w, http.StatusNotFound, "no saved original bytes for this address")
			return
		}
		n, err := sess.Write(addr, orig)
		if err != nil || n != len(orig) {
			writeErr(w, http.StatusInternalServerError, "revert write failed (need active + write access)")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"reverted": formatHex(addr), "bytes": n})
		return
	}

	var patch []byte
	if req.NOP > 0 {
		patch = make([]byte, req.NOP)
		for i := range patch {
			patch[i] = 0x90
		}
	} else {
		patch, err = hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(req.Bytes), " ", ""))
		if err != nil || len(patch) == 0 {
			writeErr(w, http.StatusBadRequest, "bytes must be non-empty hex (or set nop)")
			return
		}
	}

	// Save the original bytes for revert before overwriting.
	orig := make([]byte, len(patch))
	if n, err := sess.Read(addr, orig); err == nil && n == len(orig) {
		s.patches.remember(sid, addr, orig)
	}

	n, err := sess.Write(addr, patch)
	if err != nil || n != len(patch) {
		writeErr(w, http.StatusInternalServerError, "patch write failed (need active + write access to the page)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"patched": formatHex(addr), "bytes": n})
}

// memAlloc allocates memory in the target process (CE's "allocate memory" for
// code caves / trampolines). exec=true makes it executable+writable. Returns
// the base address. Only implemented on Windows for now.
func (s *Server) memAlloc(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Size uint64 `json:"size"`
		Exec bool   `json:"exec"`
		Near string `json:"near"` // optional preferred address (best-effort)
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Size == 0 {
		req.Size = 4096
	}
	var near uint64
	if req.Near != "" {
		near, _ = parseAddr(req.Near)
	}
	e := s.extFor(sid)
	addr, err := allocInProcess(e.pid, req.Size, req.Exec, near)
	if err != nil {
		writeErr(w, http.StatusNotImplemented, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"addr": formatHex(addr), "size": req.Size, "exec": req.Exec})
}
