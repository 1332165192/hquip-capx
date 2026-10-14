package api

// script_mem wires the Lua scripting layer's `capx.mem` table to the live
// memory-scan engine. The Server implements script.MemAccess: read/write are
// one-shot, scan runs a fresh first-scan, and freeze/unfreeze reuse the freeze
// loop keyed by a synthetic per-pid session so locks persist across calls.

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/hquip/capx/internal/memscan"
)

// typeFromName maps a short Lua type name to a ValueType.
func typeFromName(name string) (memscan.ValueType, bool) {
	switch name {
	case "i8":
		return memscan.I8, true
	case "u8", "byte":
		return memscan.U8, true
	case "i16":
		return memscan.I16, true
	case "u16":
		return memscan.U16, true
	case "i32":
		return memscan.I32, true
	case "u32":
		return memscan.U32, true
	case "i64":
		return memscan.I64, true
	case "u64":
		return memscan.U64, true
	case "f32":
		return memscan.F32, true
	case "f64":
		return memscan.F64, true
	}
	return 0, false
}

// encodeFloatVal renders a float64 (the only numeric type Lua passes) into
// little-endian bytes for the value type.
func encodeFloatVal(vt memscan.ValueType, v float64) []byte {
	switch vt {
	case memscan.U8, memscan.I8:
		return []byte{byte(int64(v))}
	case memscan.U16, memscan.I16:
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(int64(v)))
		return b
	case memscan.I32, memscan.U32:
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(int64(v)))
		return b
	case memscan.I64, memscan.U64:
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(int64(v)))
		return b
	case memscan.F32:
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, math.Float32bits(float32(v)))
		return b
	case memscan.F64:
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, math.Float64bits(v))
		return b
	}
	return nil
}

// decodeToFloat reads bytes of type vt as a float64 (lossy for u64/i64).
func decodeToFloat(vt memscan.ValueType, b []byte) float64 {
	if vt == memscan.F32 || vt == memscan.F64 {
		return toFloat(vt, b)
	}
	return float64(toInt(vt, b))
}

// luaSessionKey is the synthetic session id used for a pid's persistent
// scripting session (so freezes survive across script calls).
func luaSessionKey(pid uint32) string { return fmt.Sprintf("lua-%d", pid) }

// luaSession returns (opening if needed) the persistent scripting session for
// a pid. nil is returned when the engine is unavailable or the open fails.
func (s *Server) luaSession(pid uint32) (memscan.Session, string) {
	if !s.scanner.Available() {
		return nil, ""
	}
	sid := luaSessionKey(pid)
	s.mu.Lock()
	sess, ok := s.sessions[sid]
	s.mu.Unlock()
	if ok {
		return sess, sid
	}
	sess, err := s.scanner.Open(pid)
	if err != nil {
		return nil, ""
	}
	s.mu.Lock()
	// Re-check in case another goroutine opened it meanwhile.
	if existing, ok := s.sessions[sid]; ok {
		s.mu.Unlock()
		_ = sess.Close()
		return existing, sid
	}
	s.sessions[sid] = sess
	if s.ext[sid] == nil {
		s.ext[sid] = &memExt{pid: pid}
	}
	s.mu.Unlock()
	return sess, sid
}

// Read implements script.MemAccess.
func (s *Server) Read(pid uint32, addr uint64, typ string) (float64, bool) {
	vt, ok := typeFromName(typ)
	if !ok {
		return 0, false
	}
	sess, _ := s.luaSession(pid)
	if sess == nil {
		return 0, false
	}
	buf := make([]byte, vt.Width())
	n, err := sess.Read(addr, buf)
	if err != nil || n < len(buf) {
		return 0, false
	}
	return decodeToFloat(vt, buf), true
}

// Write implements script.MemAccess.
func (s *Server) Write(pid uint32, addr uint64, typ string, val float64) bool {
	vt, ok := typeFromName(typ)
	if !ok {
		return false
	}
	sess, _ := s.luaSession(pid)
	if sess == nil {
		return false
	}
	b := encodeFloatVal(vt, val)
	if b == nil {
		return false
	}
	n, err := sess.Write(addr, b)
	return err == nil && n == len(b)
}

// Scan implements script.MemAccess: a fresh first-scan for an exact value,
// returning up to max hit addresses as hex strings.
func (s *Server) Scan(pid uint32, typ string, val float64, max int) []string {
	vt, ok := typeFromName(typ)
	if !ok {
		return nil
	}
	if !s.scanner.Available() {
		return nil
	}
	sess, err := s.scanner.Open(pid)
	if err != nil {
		return nil
	}
	defer sess.Close()
	if max <= 0 || max > 100000 {
		max = 1000
	}
	b := encodeFloatVal(vt, val)
	if b == nil {
		return nil
	}
	if _, err := sess.FirstScan(vt, b); err != nil {
		return nil
	}
	addrs, err := sess.Results(max)
	if err != nil {
		return nil
	}
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = formatHex(a)
	}
	return out
}

// Freeze implements script.MemAccess: lock addr to val on the pid's persistent
// scripting session.
func (s *Server) Freeze(pid uint32, addr uint64, typ string, val float64, mode string) bool {
	vt, ok := typeFromName(typ)
	if !ok {
		return false
	}
	sess, sid := s.luaSession(pid)
	if sess == nil {
		return false
	}
	fm := freezeMode(mode)
	switch fm {
	case freezeSet, freezeInc, freezeDec:
	default:
		fm = freezeSet
	}
	b := encodeFloatVal(vt, val)
	if b == nil {
		return false
	}
	s.freezerFor(sid, sess).set(addr, vt, fm, b)
	return true
}

// Unfreeze implements script.MemAccess.
func (s *Server) Unfreeze(pid uint32, addr uint64) bool {
	sid := luaSessionKey(pid)
	s.mu.Lock()
	f := s.freezes[sid]
	s.mu.Unlock()
	if f == nil {
		return false
	}
	return f.clear(addr)
}
