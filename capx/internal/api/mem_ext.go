package api

// CE-style extensions implemented in the Go layer on top of the FFI engine:
// compare-to-first-scan, all-types scan, group scan, and binary (bit pattern)
// scan. They drive the engine session only through Read/Results, walking the
// process regions themselves where needed.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hquip/capx/internal/memscan"
	"github.com/hquip/capx/internal/model"
)

// firstSnapshotCap bounds how many hit addresses the compare-to-first baseline
// captures; narrow the result set with normal next scans first if exceeded.
const firstSnapshotCap = 400_000

// maxUndoDepth limits the number of undo-able scan steps kept in memory.
const maxUndoDepth = 64

// scanSnapshot captures the Go-layer hit list state at one point in time,
// enabling undo (CE's "Undo last scan").
type scanSnapshot struct {
	hits []uint64
	prev map[uint64][]byte
	vt   memscan.ValueType
}

// memExt holds per-session Go-layer scan state.
type memExt struct {
	mu  sync.Mutex
	pid uint32

	// compare-to-first baseline: address -> value bytes at first-scan save time.
	firstVals map[uint64][]byte
	firstType memscan.ValueType

	// When goHits != nil the Go layer owns the hit list (after a
	// compare-to-first filter) and Results / next scans operate on it.
	goHits []uint64
	goPrev map[uint64][]byte
	goType memscan.ValueType

	// undoStack holds previous (goHits, goPrev, goType) states so the user
	// can revert to the prior scan round (CE's "Undo last scan").
	undoStack []scanSnapshot

	// history records each scan step (most recent last) for the scan log.
	history []scanHistEntry

	watch memWatcher
}

// maxHistory bounds the per-session scan log.
const maxHistory = 200

// scanHistEntry is one recorded scan operation for the history log.
type scanHistEntry struct {
	Time   string `json:"time"`
	Action string `json:"action"`
	Type   string `json:"type"`
	Op     string `json:"op,omitempty"`
	Value  string `json:"value,omitempty"`
	Hits   int    `json:"hits"`
}

// recordHist appends a scan-log entry for a session.
func (s *Server) recordHist(sid string, e scanHistEntry) {
	e.Time = time.Now().UTC().Format("15:04:05")
	ext := s.extFor(sid)
	ext.mu.Lock()
	ext.history = append(ext.history, e)
	if len(ext.history) > maxHistory {
		ext.history = ext.history[len(ext.history)-maxHistory:]
	}
	ext.mu.Unlock()
}

const memHitPublishCap = 64

// publishScanHits records a bounded sample of current scan hits into the
// store so /api/correlate can join them with hook events (by pid) and HTTP
// history (when a window at the address matches a captured request/response).
func (s *Server) publishScanHits(sid string, sess memscan.Session, kind, value string) {
	if s.st == nil {
		return
	}
	e := s.extFor(sid)
	e.mu.Lock()
	pid := e.pid
	e.mu.Unlock()
	if pid == 0 {
		return
	}
	addrs, err := s.currentHits(sid, sess, memHitPublishCap)
	if err != nil || len(addrs) == 0 {
		return
	}
	now := time.Now().UTC()
	for _, addr := range addrs {
		val := value
		if val == "" {
			buf := make([]byte, 64)
			if n, _ := sess.Read(addr, buf); n > 0 {
				val = asciiPreview(buf[:n], 48)
			}
		}
		h := &model.MemHit{PID: pid, Addr: addr, Type: kind, Value: val, TS: now}
		if tx, score := s.matchHTTPAt(sess, addr, 256); tx != nil && score > 0 {
			h.HTTPID = tx.ID
			h.Host = tx.Host
			if h.Value == "" {
				h.Value = tx.URL
			}
		}
		s.st.AddMemHit(h)
	}
}

// memHistory returns the scan log for a session (most recent last).
func (s *Server) memHistory(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	ext := s.extFor(sid)
	ext.mu.Lock()
	out := make([]scanHistEntry, len(ext.history))
	copy(out, ext.history)
	ext.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "history": out})
}

func decodeBody(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func jsonNumber(s string) json.Number { return json.Number(strings.TrimSpace(s)) }

func (s *Server) extFor(sid string) *memExt {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.ext[sid]
	if !ok {
		e = &memExt{}
		s.ext[sid] = e
	}
	return e
}

// resetGo drops the Go-side hit list so the engine's own results are
// authoritative again (called when a fresh engine scan starts).
func (e *memExt) resetGo() {
	e.mu.Lock()
	e.goHits = nil
	e.goPrev = nil
	e.undoStack = nil
	e.mu.Unlock()
}

// pushUndo saves the current Go-layer state onto the undo stack before a new
// scan modifies it. Must be called with e.mu held.
func (e *memExt) pushUndo() {
	snap := scanSnapshot{vt: e.goType}
	if e.goHits != nil {
		snap.hits = make([]uint64, len(e.goHits))
		copy(snap.hits, e.goHits)
	}
	if e.goPrev != nil {
		snap.prev = make(map[uint64][]byte, len(e.goPrev))
		for k, v := range e.goPrev {
			snap.prev[k] = v
		}
	}
	e.undoStack = append(e.undoStack, snap)
	if len(e.undoStack) > maxUndoDepth {
		e.undoStack = e.undoStack[len(e.undoStack)-maxUndoDepth:]
	}
}

// popUndo reverts the Go-layer hit list to the previous state. Returns false
// if the stack is empty.
func (e *memExt) popUndo() bool {
	if len(e.undoStack) == 0 {
		return false
	}
	snap := e.undoStack[len(e.undoStack)-1]
	e.undoStack = e.undoStack[:len(e.undoStack)-1]
	e.goHits = snap.hits
	e.goPrev = snap.prev
	e.goType = snap.vt
	return true
}

// readBatch reads the values (width w) of sorted addrs, batching neighbouring
// addresses into single chunk reads to limit FFI round-trips. Missing /
// unreadable addresses are omitted from the result map.
func readBatch(sess memscan.Session, addrs []uint64, w int) map[uint64][]byte {
	const chunk = 64 * 1024
	out := make(map[uint64][]byte, len(addrs))
	buf := make([]byte, chunk)
	for i := 0; i < len(addrs); {
		start := addrs[i]
		j := i
		for j < len(addrs) && addrs[j]+uint64(w) <= start+chunk {
			j++
		}
		span := int(addrs[j-1] + uint64(w) - start)
		n, err := sess.Read(start, buf[:span])
		if err == nil {
			for k := i; k < j; k++ {
				off := int(addrs[k] - start)
				if off+w <= n {
					v := make([]byte, w)
					copy(v, buf[off:off+w])
					out[addrs[k]] = v
				}
			}
		} else {
			// Chunk spans an unreadable hole: fall back to per-address reads.
			for k := i; k < j; k++ {
				v := make([]byte, w)
				if n, err := sess.Read(addrs[k], v); err == nil && n == w {
					out[addrs[k]] = v
				}
			}
		}
		i = j
	}
	return out
}

// currentHits returns the live hit list: the Go-side list when present,
// otherwise the engine's results (up to cap).
func (s *Server) currentHits(sid string, sess memscan.Session, cap int) ([]uint64, error) {
	e := s.extFor(sid)
	e.mu.Lock()
	if e.goHits != nil {
		out := make([]uint64, len(e.goHits))
		copy(out, e.goHits)
		e.mu.Unlock()
		if len(out) > cap {
			out = out[:cap]
		}
		return out, nil
	}
	e.mu.Unlock()
	return sess.Results(cap)
}

// ----------------------- compare to first scan -----------------------------

// memSaveFirst captures the current hit set's values as the "first scan"
// baseline, enabling later compare-to-first filtering (CE's 与首次扫描相比).
func (s *Server) memSaveFirst(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req scanReq
	_ = decodeBody(r, &req)
	width := req.Type.Width()
	if width == 0 {
		writeErr(w, http.StatusBadRequest, "bad value type")
		return
	}
	addrs, err := s.currentHits(sid, sess, firstSnapshotCap+1)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(addrs) > firstSnapshotCap {
		writeErr(w, http.StatusBadRequest,
			fmt.Sprintf("too many hits (> %d); narrow with next scans first", firstSnapshotCap))
		return
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	vals := readBatch(sess, addrs, width)
	e := s.extFor(sid)
	e.mu.Lock()
	e.firstVals = vals
	e.firstType = req.Type
	e.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"saved": len(vals), "type": uint32(req.Type)})
}

// goNextScan filters hits in the Go layer comparing the current value against
// either the saved first-scan value (toFirst) or the previous Go-scan value.
func (s *Server) goNextScan(sid string, sess memscan.Session, req scanReq, toFirst bool) (int, error) {
	e := s.extFor(sid)
	e.mu.Lock()
	first := e.firstVals
	firstType := e.firstType
	prev := e.goPrev
	e.mu.Unlock()
	if toFirst && first == nil {
		return 0, fmt.Errorf("no first-scan snapshot saved (call savefirst after the first scan)")
	}
	vt := req.Type
	if toFirst {
		vt = firstType
	}
	width := vt.Width()
	if width == 0 {
		return 0, fmt.Errorf("bad value type")
	}

	addrs, err := s.currentHits(sid, sess, firstSnapshotCap+1)
	if err != nil {
		return 0, err
	}
	if len(addrs) > firstSnapshotCap {
		return 0, fmt.Errorf("too many hits (> %d); narrow with next scans first", firstSnapshotCap)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	cur := readBatch(sess, addrs, width)

	var val, val2 []byte
	if req.Value != "" {
		if val, err = encodeValue(vt, req.Value); err != nil {
			return 0, err
		}
	}
	if req.Op == memscan.OpBetween {
		if req.Value == "" || req.Value2 == "" {
			return 0, fmt.Errorf("between requires value and value2")
		}
		if val2, err = encodeValue(vt, req.Value2); err != nil {
			return 0, err
		}
	}

	keep := make([]uint64, 0, len(addrs))
	newPrev := make(map[uint64][]byte, len(addrs))
	for _, a := range addrs {
		c, ok := cur[a]
		if !ok {
			continue
		}
		ref := first[a]
		if !toFirst {
			if p, ok := prev[a]; ok {
				ref = p
			}
		}
		if matchOp(vt, req.Op, c, ref, val, val2) {
			keep = append(keep, a)
			newPrev[a] = c
		}
	}
	e.mu.Lock()
	e.pushUndo()
	e.goHits = keep
	e.goPrev = newPrev
	e.goType = vt
	e.mu.Unlock()
	return len(keep), nil
}

// matchOp applies a next-scan comparison: cur vs ref (previous/first value)
// for delta ops, cur vs val/val2 for absolute ops.
func matchOp(vt memscan.ValueType, op memscan.Op, cur, ref, val, val2 []byte) bool {
	switch op {
	case memscan.OpEq:
		return val != nil && cmpValue(vt, cur, val) == 0
	case memscan.OpGt:
		return val != nil && cmpValue(vt, cur, val) > 0
	case memscan.OpLt:
		return val != nil && cmpValue(vt, cur, val) < 0
	case memscan.OpBetween:
		return val != nil && val2 != nil && cmpValue(vt, cur, val) >= 0 && cmpValue(vt, cur, val2) <= 0
	case memscan.OpChanged:
		return ref != nil && cmpValue(vt, cur, ref) != 0
	case memscan.OpUnchanged:
		return ref != nil && cmpValue(vt, cur, ref) == 0
	case memscan.OpIncreased:
		return ref != nil && cmpValue(vt, cur, ref) > 0
	case memscan.OpDecreased:
		return ref != nil && cmpValue(vt, cur, ref) < 0
	case memscan.OpIncBy:
		return ref != nil && val != nil && deltaEq(vt, cur, ref, val, 1)
	case memscan.OpDecBy:
		return ref != nil && val != nil && deltaEq(vt, cur, ref, val, -1)
	}
	return false
}

// deltaEq reports whether cur == ref + sign*delta for the value type.
func deltaEq(vt memscan.ValueType, cur, ref, delta []byte, sign int) bool {
	switch vt {
	case memscan.F32, memscan.F64:
		c, r, d := toFloat(vt, cur), toFloat(vt, ref), toFloat(vt, delta)
		return c == r+float64(sign)*d
	default:
		c, r, d := toInt(vt, cur), toInt(vt, ref), toInt(vt, delta)
		return c == r+int64(sign)*d
	}
}

func toInt(vt memscan.ValueType, b []byte) int64 {
	switch vt {
	case memscan.U8:
		return int64(b[0])
	case memscan.I8:
		return int64(int8(b[0]))
	case memscan.U16:
		return int64(binary.LittleEndian.Uint16(b))
	case memscan.I16:
		return int64(int16(binary.LittleEndian.Uint16(b)))
	case memscan.U32:
		return int64(binary.LittleEndian.Uint32(b))
	case memscan.I32:
		return int64(int32(binary.LittleEndian.Uint32(b)))
	default: // U64 / I64
		return int64(binary.LittleEndian.Uint64(b))
	}
}

func toFloat(vt memscan.ValueType, b []byte) float64 {
	if vt == memscan.F32 {
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(b)))
	}
	return math.Float64frombits(binary.LittleEndian.Uint64(b))
}

// --------------------------- all-types scan --------------------------------

// memAllFirst scans the value as every numeric type at once (CE's "所有类型"),
// returning per-type hit counts and a sample of addresses for each.
func (s *Server) memAllFirst(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(sid)
	var req struct {
		Value        string `json:"value"`
		WritableOnly bool   `json:"writable_only"`
		Max          int    `json:"max"`
	}
	if err := decodeBody(r, &req); err != nil || req.Value == "" {
		writeErr(w, http.StatusBadRequest, "value required")
		return
	}
	maxPer := req.Max
	if maxPer <= 0 || maxPer > 5000 {
		maxPer = 500
	}
	types := []memscan.ValueType{
		memscan.U8, memscan.I8, memscan.U16, memscan.I16,
		memscan.I32, memscan.U32, memscan.I64, memscan.U64,
		memscan.F32, memscan.F64,
	}
	var out []map[string]any
	total := 0
	for _, vt := range types {
		val, err := encodeValue(vt, jsonNumber(req.Value))
		if err != nil {
			continue // value doesn't fit this type (e.g. float text for ints)
		}
		sub, err := s.scanner.Open(e.pid)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = sub.SetOpts(0, 0, 0, req.WritableOnly)
		n, err := sub.FirstScan(vt, val)
		if err != nil {
			_ = sub.Close()
			continue
		}
		addrs, _ := sub.Results(maxPer)
		_ = sub.Close()
		hexed := make([]string, len(addrs))
		for i, a := range addrs {
			hexed[i] = formatHex(a)
		}
		out = append(out, map[string]any{
			"type": uint32(vt), "type_name": typeName(vt), "hits": n, "addrs": hexed,
		})
		total += n
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "types": out})
}

// opName renders a next-scan op as a short label for the history log.
func opName(op memscan.Op) string {
	switch op {
	case memscan.OpEq:
		return "eq"
	case memscan.OpChanged:
		return "changed"
	case memscan.OpUnchanged:
		return "unchanged"
	case memscan.OpIncreased:
		return "increased"
	case memscan.OpDecreased:
		return "decreased"
	case memscan.OpGt:
		return "gt"
	case memscan.OpLt:
		return "lt"
	case memscan.OpBetween:
		return "between"
	case memscan.OpIncBy:
		return "inc_by"
	case memscan.OpDecBy:
		return "dec_by"
	}
	return "?"
}

func typeName(vt memscan.ValueType) string {
	names := map[memscan.ValueType]string{
		memscan.I32: "I32", memscan.I64: "I64", memscan.F32: "F32", memscan.F64: "F64",
		memscan.U32: "U32", memscan.U64: "U64", memscan.U8: "U8", memscan.I8: "I8",
		memscan.U16: "U16", memscan.I16: "I16", memscan.Bin: "BIN", memscan.All: "ALL",
	}
	return names[vt]
}

// ----------------------------- group scan ----------------------------------

// memGroupScan finds CE-style group matches: the given values laid out
// consecutively in memory (in order), each aligned to the group alignment.
// An item with any=true is a wildcard that only consumes its type's width.
func (s *Server) memGroupScan(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(sid)
	var req struct {
		Items []struct {
			Type  memscan.ValueType `json:"type"`
			Value string            `json:"value"`
			Any   bool              `json:"any"`
		} `json:"items"`
		Alignment    uint64 `json:"alignment"`
		WritableOnly bool   `json:"writable_only"`
		Kind         string `json:"kind"`
		Max          int    `json:"max"`
	}
	if err := decodeBody(r, &req); err != nil || len(req.Items) == 0 {
		writeErr(w, http.StatusBadRequest, "items required")
		return
	}
	type elem struct {
		width int
		val   []byte // nil for wildcard
		vt    memscan.ValueType
	}
	elems := make([]elem, 0, len(req.Items))
	total := 0
	for _, it := range req.Items {
		wd := it.Type.Width()
		if wd == 0 {
			writeErr(w, http.StatusBadRequest, "bad value type in items")
			return
		}
		el := elem{width: wd, vt: it.Type}
		if !it.Any {
			v, err := encodeValue(it.Type, jsonNumber(it.Value))
			if err != nil {
				writeErr(w, http.StatusBadRequest, "bad value: "+it.Value)
				return
			}
			el.val = v
		}
		elems = append(elems, el)
		total += wd
	}
	align := req.Alignment
	if align == 0 {
		align = 4
	}
	maxHits := req.Max
	if maxHits <= 0 || maxHits > 20000 {
		maxHits = 5000
	}

	match := func(buf []byte) bool {
		off := 0
		for _, el := range elems {
			if el.val != nil {
				if cmpEqBytes(el.vt, buf[off:off+el.width], el.val) {
					off += el.width
					continue
				}
				return false
			}
			off += el.width
		}
		return true
	}

	var hits []uint64
	err := s.walkMemoryKind(e.pid, sess, req.WritableOnly, req.Kind, total, func(base uint64, buf []byte, starts int) bool {
		// First absolutely-aligned offset within this chunk.
		off := int((align - base%align) % align)
		for ; off < starts && off+total <= len(buf); off += int(align) {
			if match(buf[off : off+total]) {
				hits = append(hits, base+uint64(off))
				if len(hits) >= maxHits {
					return false
				}
			}
		}
		return true
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	hexed := make([]string, len(hits))
	for i, a := range hits {
		hexed[i] = formatHex(a)
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(hits), "addrs": hexed, "block": total})
}

// cmpEqBytes compares two raw values of type vt for equality (float-aware so
// -0.0 == 0.0 etc.).
func cmpEqBytes(vt memscan.ValueType, a, b []byte) bool {
	switch vt {
	case memscan.F32, memscan.F64:
		return toFloat(vt, a) == toFloat(vt, b)
	default:
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
}

// ----------------------------- binary scan ---------------------------------

// memBinScan scans for a bit pattern (e.g. "1011?01", ? = wildcard bit), the
// CE "二进制" scan type. Bits are matched LSB-first within each byte at every
// bit offset; hits report the byte address and starting bit.
func (s *Server) memBinScan(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(sid)
	var req struct {
		Pattern      string `json:"pattern"`
		WritableOnly bool   `json:"writable_only"`
		ByteAligned  bool   `json:"byte_aligned"`
		Kind         string `json:"kind"`
		Max          int    `json:"max"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	pat := strings.ReplaceAll(strings.TrimSpace(req.Pattern), " ", "")
	if pat == "" {
		writeErr(w, http.StatusBadRequest, "pattern required (e.g. 1011?01)")
		return
	}
	// Pattern is written MSB-first (human order); reverse into LSB-first match
	// order so bit i of the pattern lines up with bit (start+i) of memory.
	bits := make([]int8, len(pat)) // 0, 1 or -1 (wildcard)
	for i := 0; i < len(pat); i++ {
		switch pat[len(pat)-1-i] {
		case '0':
			bits[i] = 0
		case '1':
			bits[i] = 1
		case '?', '*':
			bits[i] = -1
		default:
			writeErr(w, http.StatusBadRequest, "pattern may only contain 0, 1 and ?")
			return
		}
	}
	maxHits := req.Max
	if maxHits <= 0 || maxHits > 20000 {
		maxHits = 5000
	}
	nbytes := (len(bits) + 7) / 8

	type binHit struct {
		Addr string `json:"addr"`
		Bit  int    `json:"bit"`
	}
	var hits []binHit
	bitAt := func(buf []byte, idx int) int8 { return int8((buf[idx>>3] >> (idx & 7)) & 1) }
	err := s.walkMemoryKind(e.pid, sess, req.WritableOnly, req.Kind, nbytes+1, func(base uint64, buf []byte, starts int) bool {
		totalBits := starts * 8
		if lim := len(buf)*8 - len(bits); totalBits > lim {
			totalBits = lim
		}
		step := 1
		if req.ByteAligned {
			step = 8
		}
		for sb := 0; sb < totalBits; sb += step {
			ok := true
			for i, want := range bits {
				if want >= 0 && bitAt(buf, sb+i) != want {
					ok = false
					break
				}
			}
			if ok {
				hits = append(hits, binHit{Addr: formatHex(base + uint64(sb>>3)), Bit: sb & 7})
				if len(hits) >= maxHits {
					return false
				}
			}
		}
		return true
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(hits), "hits": hits})
}

// walkMemory streams the readable (optionally writable-only) regions of the
// process in overlapping chunks through fn. overlap is the match window size
// so hits spanning chunk borders aren't lost; starts is the number of valid
// match start offsets within buf (offsets beyond it belong to the next
// chunk). fn returns false to stop early.
func (s *Server) walkMemory(pid uint32, sess memscan.Session, writableOnly bool,
	overlap int, fn func(base uint64, buf []byte, starts int) bool) error {
	return s.walkMemoryKind(pid, sess, writableOnly, "", overlap, fn)
}

func (s *Server) walkMemoryKind(pid uint32, sess memscan.Session, writableOnly bool, kind string,
	overlap int, fn func(base uint64, buf []byte, starts int) bool) error {
	regions, err := listRegions(pid)
	if err != nil {
		return err
	}
	const chunk = 256 * 1024
	buf := make([]byte, chunk+overlap)
	for _, rg := range regions {
		if !rg.readable() || (writableOnly && !rg.writable()) {
			continue
		}
		if !regionKindOK(rg.kind(), kind) {
			continue
		}
		for at := rg.Start; at < rg.End; at += chunk {
			want := int(rg.End - at)
			if want > chunk+overlap {
				want = chunk + overlap
			}
			n, err := sess.Read(at, buf[:want])
			if err != nil || n <= 0 {
				continue
			}
			starts := n
			if at+uint64(chunk) < rg.End && starts > chunk {
				starts = chunk
			}
			if !fn(at, buf[:n], starts) {
				return nil
			}
		}
	}
	return nil
}

// ----------------------------- undo scan -----------------------------------

// memUndo reverts the Go-layer hit list to the previous scan state (CE's
// "Undo last scan"). Returns the restored hit count or an error when the
// undo stack is empty.
func (s *Server) memUndo(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(sid)
	e.mu.Lock()
	ok := e.popUndo()
	count := len(e.goHits)
	depth := len(e.undoStack)
	e.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusBadRequest, "nothing to undo (stack empty)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hits": count, "undo_depth": depth})
}
