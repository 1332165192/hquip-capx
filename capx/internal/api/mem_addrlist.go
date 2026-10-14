package api

// Persistent address list (CE's cheat table bottom pane): saved addresses with
// a description and value type, stored as JSON on disk so they survive
// restarts. Live values are read through an open scan session.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hquip/capx/internal/memscan"
)

// addrEntry is one saved address-list row. Either a fixed Addr ("0x..." hex)
// or, CE-style, a pointer/module Expr ("game.exe+0x1234", "[[base]+0x10]+8")
// that is resolved live against the target so the entry survives ASLR. When
// Expr is set it takes precedence over Addr.
type addrEntry struct {
	ID   int64             `json:"id"`
	Addr string            `json:"addr"`           // "0x..." hex (static)
	Expr string            `json:"expr,omitempty"` // CE-style pointer/module expression
	Type memscan.ValueType `json:"type"`
	Desc string            `json:"desc"`
}

// addrList is the on-disk persistent address list.
type addrList struct {
	mu      sync.Mutex
	path    string
	entries map[int64]*addrEntry
}

func addrListPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		p := filepath.Join(dir, "capx")
		if os.MkdirAll(p, 0o755) == nil {
			return filepath.Join(p, "addrlist.json")
		}
	}
	return "capx-addrlist.json"
}

func newAddrList() *addrList {
	l := &addrList{path: addrListPath(), entries: make(map[int64]*addrEntry)}
	if b, err := os.ReadFile(l.path); err == nil {
		var items []*addrEntry
		if json.Unmarshal(b, &items) == nil {
			for _, it := range items {
				l.entries[it.ID] = it
			}
		}
	}
	return l
}

// save writes the list to disk; callers hold l.mu.
func (l *addrList) save() {
	items := l.sorted()
	if b, err := json.MarshalIndent(items, "", "  "); err == nil {
		_ = os.WriteFile(l.path, b, 0o644)
	}
}

// sorted returns entries ordered by id; callers hold l.mu.
func (l *addrList) sorted() []*addrEntry {
	items := make([]*addrEntry, 0, len(l.entries))
	for _, e := range l.entries {
		items = append(items, e)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	return items
}

// ----------------------------- HTTP handlers -------------------------------

// memAddrList returns saved entries; when an open session id is supplied via
// ?sid=, each entry also carries its live value read from the target and the
// freeze state (frozen/mode) for that session.
func (s *Server) memAddrList(w http.ResponseWriter, r *http.Request) {
	var sess memscan.Session
	sid := r.URL.Query().Get("sid")
	if sid != "" {
		sess, _ = s.session(sid)
	}
	// Get the freezer for the session (if any) to show freeze status.
	var freezer *memFreezer
	if sid != "" {
		s.mu.Lock()
		freezer = s.freezes[sid]
		s.mu.Unlock()
	}

	s.addrs.mu.Lock()
	items := s.addrs.sorted()
	s.addrs.mu.Unlock()

	var pid uint32
	var mods []memModule
	var firstVals map[uint64][]byte
	var firstType memscan.ValueType
	if sid != "" {
		ext := s.extFor(sid)
		ext.mu.Lock()
		pid = ext.pid
		firstType = ext.firstType
		if ext.firstVals != nil {
			firstVals = make(map[uint64][]byte, len(ext.firstVals))
			for k, v := range ext.firstVals {
				cp := make([]byte, len(v))
				copy(cp, v)
				firstVals[k] = cp
			}
		}
		ext.mu.Unlock()
		if pid != 0 {
			mods, _ = listModules(pid)
		}
	}

	out := make([]map[string]any, 0, len(items))
	for _, e := range items {
		item := map[string]any{
			"id": e.ID, "addr": e.Addr, "type": uint32(e.Type),
			"type_name": typeName(e.Type), "desc": e.Desc,
		}
		if e.Expr != "" {
			item["expr"] = e.Expr
		}
		// Resolve the live address (pointer/module expr or static hex).
		a, resolved := s.entryAddr(e, sess, pid)
		if resolved {
			item["resolved"] = formatHex(a)
			if label := moduleLabelFromMods(mods, a); label != "" {
				item["module_label"] = label
			}
			if firstVals != nil && firstType.Width() > 0 {
				if b, ok := firstVals[a]; ok {
					item["first_value"] = decodeValue(firstType, b)
					item["first_type"] = uint32(firstType)
				}
			}
			if sess != nil {
				buf := make([]byte, e.Type.Width())
				if n, err := sess.Read(a, buf); err == nil && n == len(buf) {
					item["value"] = decodeValue(e.Type, buf)
				}
			}
		}
		// Annotate freeze status if an active freezer exists for this session.
		if freezer != nil && resolved {
			freezer.mu.Lock()
			if fe, ok := freezer.entries[a]; ok {
				item["frozen"] = true
				item["freeze_mode"] = string(fe.mode)
				item["freeze_value"] = decodeValue(fe.vt, fe.val)
			} else {
				item["frozen"] = false
			}
			freezer.mu.Unlock()
		}
		out = append(out, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "entries": out})
}

// memAddrAdd adds or updates (when id is set) an address-list entry. Provide
// either addr (static hex) or expr (CE-style pointer/module expression).
func (s *Server) memAddrAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   int64             `json:"id"`
		Addr string            `json:"addr"`
		Expr string            `json:"expr"`
		Type memscan.ValueType `json:"type"`
		Desc string            `json:"desc"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Type.Width() == 0 {
		writeErr(w, http.StatusBadRequest, "bad value type")
		return
	}
	entry := &addrEntry{Type: req.Type, Desc: req.Desc, Expr: strings.TrimSpace(req.Expr)}
	if entry.Expr == "" {
		a, err := parseAddr(req.Addr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "provide addr (0x.../decimal) or expr")
			return
		}
		entry.Addr = formatHex(a)
	}
	s.addrs.mu.Lock()
	id := req.ID
	if id == 0 || s.addrs.entries[id] == nil {
		id = time.Now().UnixNano()
	}
	entry.ID = id
	s.addrs.entries[id] = entry
	s.addrs.save()
	s.addrs.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
}

// entryAddr resolves an address-list entry to a concrete address: via its
// pointer/module expression (needs a session + pid) when set, else its static
// hex. ok is false when it cannot be resolved.
func (s *Server) entryAddr(e *addrEntry, sess memscan.Session, pid uint32) (uint64, bool) {
	if e.Expr != "" {
		if sess == nil {
			return 0, false
		}
		a, err := resolveExpr(e.Expr, moduleMap(pid), sessionPtrReader(sess))
		if err != nil {
			return 0, false
		}
		return a, true
	}
	a, err := parseAddr(e.Addr)
	if err != nil {
		return 0, false
	}
	return a, true
}

// memAddrDel removes an entry by id.
func (s *Server) memAddrDel(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	s.addrs.mu.Lock()
	_, ok := s.addrs.entries[id]
	delete(s.addrs.entries, id)
	s.addrs.save()
	s.addrs.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"deleted": ok})
}

// memAddrFreeze freezes the address-list entry identified by id using the
// supplied session. This integrates the address list with the freeze system so
// users can one-click freeze from the cheat table without manually calling the
// lower-level freeze endpoint.
func (s *Server) memAddrFreeze(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var req struct {
		SID   string      `json:"sid"`
		Value json.Number `json:"value"`
		Mode  freezeMode  `json:"mode"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.SID == "" {
		writeErr(w, http.StatusBadRequest, "sid required")
		return
	}
	sess, ok := s.session(req.SID)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	s.addrs.mu.Lock()
	entry, ok := s.addrs.entries[id]
	s.addrs.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "address-list entry not found")
		return
	}
	addr, ok := s.entryAddr(entry, sess, s.extFor(req.SID).pid)
	if !ok {
		writeErr(w, http.StatusBadRequest, "cannot resolve entry address (bad addr/expr)")
		return
	}
	// Determine the value to freeze: use the request value if supplied,
	// otherwise read the current value from the target.
	var val []byte
	if req.Value != "" {
		val, err = encodeValue(entry.Type, req.Value)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad value: "+err.Error())
			return
		}
	} else {
		buf := make([]byte, entry.Type.Width())
		n, err := sess.Read(addr, buf)
		if err != nil || n < len(buf) {
			writeErr(w, http.StatusInternalServerError, "cannot read current value")
			return
		}
		val = buf
	}
	mode := req.Mode
	if mode == "" {
		mode = freezeSet
	}
	s.freezerFor(req.SID, sess).set(addr, entry.Type, mode, val)
	writeJSON(w, http.StatusOK, map[string]any{
		"frozen": formatHex(addr), "mode": string(mode),
		"value": decodeValue(entry.Type, val),
	})
}

// memAddrUnfreeze removes the freeze on the address-list entry identified by id.
func (s *Server) memAddrUnfreeze(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	var req struct {
		SID string `json:"sid"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.SID == "" {
		writeErr(w, http.StatusBadRequest, "sid required")
		return
	}
	sess, ok := s.session(req.SID)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	s.addrs.mu.Lock()
	entry, ok := s.addrs.entries[id]
	s.addrs.mu.Unlock()
	if !ok {
		writeErr(w, http.StatusNotFound, "address-list entry not found")
		return
	}
	addr, ok := s.entryAddr(entry, sess, s.extFor(req.SID).pid)
	if !ok {
		writeErr(w, http.StatusBadRequest, "cannot resolve entry address (bad addr/expr)")
		return
	}
	s.mu.Lock()
	f := s.freezes[req.SID]
	s.mu.Unlock()
	cleared := false
	if f != nil {
		cleared = f.clear(addr)
	}
	writeJSON(w, http.StatusOK, map[string]any{"unfrozen": formatHex(addr), "was_locked": cleared})
}
