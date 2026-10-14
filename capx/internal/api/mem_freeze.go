package api

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/hquip/capx/internal/memscan"
)

func formatHex(a uint64) string { return fmt.Sprintf("0x%X", a) }

// parseAddr accepts "0x1234ABCD" (hex) or a decimal string.
func parseAddr(s string) (uint64, error) { return strconv.ParseUint(s, 0, 64) }

// parseAddrDefault is parseAddr but treats an empty string as 0 (unset).
func parseAddrDefault(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	return parseAddr(s)
}

// freezeInterval is how often locked values are re-written into the target.
const freezeInterval = 50 * time.Millisecond

// freezeMode selects how a locked value reacts to the target changing it.
type freezeMode string

const (
	// freezeSet always writes the locked value back (classic Cheat Engine lock).
	freezeSet freezeMode = "set"
	// freezeInc treats the locked value as a floor: the target may grow it
	// (the floor follows up) but can never drop below the locked value.
	freezeInc freezeMode = "inc"
	// freezeDec treats the locked value as a ceiling: the target may shrink it
	// but can never rise above the locked value.
	freezeDec freezeMode = "dec"
)

type freezeEntry struct {
	vt   memscan.ValueType
	mode freezeMode
	val  []byte // current locked bytes (little-endian), width == vt.Width()
}

// memFreezer re-writes a set of locked addresses into one scan session on a
// fixed interval, mirroring Cheat Engine's "freeze" checkbox.
type memFreezer struct {
	sess memscan.Session

	mu      sync.Mutex
	entries map[uint64]*freezeEntry
	stop    chan struct{}
	running bool
}

func newMemFreezer(sess memscan.Session) *memFreezer {
	return &memFreezer{sess: sess, entries: make(map[uint64]*freezeEntry)}
}

// set adds or replaces a locked address and ensures the writer loop is running.
func (f *memFreezer) set(addr uint64, vt memscan.ValueType, mode freezeMode, val []byte) {
	f.mu.Lock()
	f.entries[addr] = &freezeEntry{vt: vt, mode: mode, val: val}
	if !f.running {
		f.running = true
		f.stop = make(chan struct{})
		go f.loop(f.stop)
	}
	f.mu.Unlock()
}

// clear removes a locked address. It returns true if the address was locked.
func (f *memFreezer) clear(addr uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.entries[addr]
	delete(f.entries, addr)
	if len(f.entries) == 0 && f.running {
		close(f.stop)
		f.running = false
	}
	return ok
}

// list returns a snapshot of currently locked addresses.
func (f *memFreezer) list() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]map[string]any, 0, len(f.entries))
	for addr, e := range f.entries {
		out = append(out, map[string]any{
			"addr":  formatHex(addr),
			"type":  uint32(e.vt),
			"mode":  string(e.mode),
			"value": decodeValue(e.vt, e.val),
		})
	}
	return out
}

// stopAll halts the writer loop (used when the session is closed).
func (f *memFreezer) stopAll() {
	f.mu.Lock()
	if f.running {
		close(f.stop)
		f.running = false
	}
	f.entries = make(map[uint64]*freezeEntry)
	f.mu.Unlock()
}

func (f *memFreezer) loop(stop chan struct{}) {
	t := time.NewTicker(freezeInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			f.tick()
		}
	}
}

func (f *memFreezer) tick() {
	// Copy entries under the lock, then do I/O without holding it.
	f.mu.Lock()
	type job struct {
		addr uint64
		e    *freezeEntry
	}
	jobs := make([]job, 0, len(f.entries))
	for addr, e := range f.entries {
		jobs = append(jobs, job{addr, e})
	}
	f.mu.Unlock()

	for _, j := range jobs {
		w := j.e.vt.Width()
		if w == 0 {
			continue
		}
		switch j.e.mode {
		case freezeInc, freezeDec:
			cur := make([]byte, w)
			if n, err := f.sess.Read(j.addr, cur); err != nil || n < w {
				continue
			}
			c := cmpValue(j.e.vt, cur, j.e.val)
			if j.e.mode == freezeInc {
				if c > 0 { // target grew past floor: raise the floor, don't write
					f.raise(j.addr, cur)
					continue
				}
			} else { // freezeDec
				if c < 0 { // target dropped below ceiling: lower it, don't write
					f.raise(j.addr, cur)
					continue
				}
			}
			_, _ = f.sess.Write(j.addr, j.e.val)
		default: // freezeSet
			_, _ = f.sess.Write(j.addr, j.e.val)
		}
	}
}

// raise updates the locked bytes for an address (used by inc/dec modes when the
// target legitimately moved the value in the allowed direction).
func (f *memFreezer) raise(addr uint64, val []byte) {
	f.mu.Lock()
	if e, ok := f.entries[addr]; ok {
		cp := make([]byte, len(val))
		copy(cp, val)
		e.val = cp
	}
	f.mu.Unlock()
}

// cmpValue returns -1/0/1 comparing a vs b interpreted as type vt (little-endian).
func cmpValue(vt memscan.ValueType, a, b []byte) int {
	w := vt.Width()
	if len(a) < w || len(b) < w {
		return 0
	}
	switch vt {
	case memscan.U8:
		return cmpUint(uint64(a[0]), uint64(b[0]))
	case memscan.I8:
		return cmpInt(int64(int8(a[0])), int64(int8(b[0])))
	case memscan.U16:
		return cmpUint(uint64(binary.LittleEndian.Uint16(a)), uint64(binary.LittleEndian.Uint16(b)))
	case memscan.I16:
		return cmpInt(int64(int16(binary.LittleEndian.Uint16(a))), int64(int16(binary.LittleEndian.Uint16(b))))
	case memscan.I32:
		return cmpInt(int64(int32(binary.LittleEndian.Uint32(a))), int64(int32(binary.LittleEndian.Uint32(b))))
	case memscan.U32:
		return cmpInt(int64(binary.LittleEndian.Uint32(a)), int64(binary.LittleEndian.Uint32(b)))
	case memscan.I64:
		return cmpInt(int64(binary.LittleEndian.Uint64(a)), int64(binary.LittleEndian.Uint64(b)))
	case memscan.U64:
		return cmpUint(binary.LittleEndian.Uint64(a), binary.LittleEndian.Uint64(b))
	case memscan.F32:
		return cmpFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(a))), float64(math.Float32frombits(binary.LittleEndian.Uint32(b))))
	case memscan.F64:
		return cmpFloat(math.Float64frombits(binary.LittleEndian.Uint64(a)), math.Float64frombits(binary.LittleEndian.Uint64(b)))
	}
	return 0
}

func cmpInt(x, y int64) int {
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	default:
		return 0
	}
}

func cmpUint(x, y uint64) int {
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	default:
		return 0
	}
}

func cmpFloat(x, y float64) int {
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	default:
		return 0
	}
}

// decodeValue renders little-endian bytes back to a JSON-friendly number.
func decodeValue(vt memscan.ValueType, b []byte) any {
	if len(b) < vt.Width() {
		return nil
	}
	switch vt {
	case memscan.U8:
		return b[0]
	case memscan.I8:
		return int8(b[0])
	case memscan.U16:
		return binary.LittleEndian.Uint16(b)
	case memscan.I16:
		return int16(binary.LittleEndian.Uint16(b))
	case memscan.I32:
		return int32(binary.LittleEndian.Uint32(b))
	case memscan.U32:
		return binary.LittleEndian.Uint32(b)
	case memscan.I64:
		return int64(binary.LittleEndian.Uint64(b))
	case memscan.U64:
		return binary.LittleEndian.Uint64(b)
	case memscan.F32:
		return math.Float32frombits(binary.LittleEndian.Uint32(b))
	case memscan.F64:
		return math.Float64frombits(binary.LittleEndian.Uint64(b))
	}
	return nil
}

// ----------------------------- HTTP handlers ------------------------------

type writeReq struct {
	Addr  string            `json:"addr"`
	Type  memscan.ValueType `json:"type"`
	Value json.Number       `json:"value"`
	Mode  freezeMode        `json:"mode"`
}

// freezerFor returns (creating if needed) the freezer bound to a session id.
func (s *Server) freezerFor(sid string, sess memscan.Session) *memFreezer {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.freezes[sid]
	if !ok {
		f = newMemFreezer(sess)
		s.freezes[sid] = f
	}
	return f
}

func (s *Server) memWrite(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req writeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	addr, err := parseAddr(req.Addr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad addr (use 0x... or decimal)")
		return
	}
	val, err := encodeValue(req.Type, req.Value)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := sess.Write(addr, val)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"addr": formatHex(addr), "written": n})
}

func (s *Server) memFreeze(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req writeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	addr, err := parseAddr(req.Addr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad addr (use 0x... or decimal)")
		return
	}
	val, err := encodeValue(req.Type, req.Value)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	mode := req.Mode
	switch mode {
	case freezeSet, freezeInc, freezeDec:
	case "":
		mode = freezeSet
	default:
		writeErr(w, http.StatusBadRequest, "bad mode (set|inc|dec)")
		return
	}
	s.freezerFor(sid, sess).set(addr, req.Type, mode, val)
	writeJSON(w, http.StatusOK, map[string]any{"frozen": formatHex(addr), "mode": string(mode)})
}

func (s *Server) memUnfreeze(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Addr string `json:"addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	addr, err := parseAddr(req.Addr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad addr (use 0x... or decimal)")
		return
	}
	s.mu.Lock()
	f := s.freezes[sid]
	s.mu.Unlock()
	cleared := false
	if f != nil {
		cleared = f.clear(addr)
	}
	writeJSON(w, http.StatusOK, map[string]any{"unfrozen": formatHex(addr), "was_locked": cleared})
}

func (s *Server) memFreezes(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	s.mu.Lock()
	f := s.freezes[sid]
	s.mu.Unlock()
	var list []map[string]any
	if f != nil {
		list = f.list()
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(list), "freezes": list})
}
