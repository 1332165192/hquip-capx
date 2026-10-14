package api

// Cheat Table import/export (CE's .CT): serialise the persistent address list
// (plus, when a live session is supplied, the current freeze state) into a
// shareable JSON file, and restore it on import. The format is capx-native
// JSON rather than CE's XML, but captures the same essentials: address, type,
// description and freeze/value so a table survives across machines.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/hquip/capx/internal/memscan"
)

// cheatTableVersion tags exported files so importers can detect the format.
const cheatTableVersion = 1

// ctEntry is one row of an exported cheat table.
type ctEntry struct {
	Addr        string `json:"addr"`
	Expr        string `json:"expr,omitempty"`
	Type        uint32 `json:"type"`
	TypeName    string `json:"type_name"`
	Desc        string `json:"desc"`
	Frozen      bool   `json:"frozen,omitempty"`
	FreezeMode  string `json:"freeze_mode,omitempty"`
	FreezeValue any    `json:"freeze_value,omitempty"`
}

type cheatTable struct {
	Format   string    `json:"format"`
	Version  int       `json:"version"`
	Exported time.Time `json:"exported"`
	Entries  []ctEntry `json:"entries"`
}

// memTableExport returns the address list (and freeze state for ?sid=) as a
// downloadable cheat-table JSON file.
func (s *Server) memTableExport(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	var freezer *memFreezer
	if sid != "" {
		s.mu.Lock()
		freezer = s.freezes[sid]
		s.mu.Unlock()
	}

	s.addrs.mu.Lock()
	items := s.addrs.sorted()
	s.addrs.mu.Unlock()

	tbl := cheatTable{Format: "capx-cheat-table", Version: cheatTableVersion, Exported: time.Now().UTC()}
	for _, e := range items {
		row := ctEntry{Addr: e.Addr, Expr: e.Expr, Type: uint32(e.Type), TypeName: typeName(e.Type), Desc: e.Desc}
		if freezer != nil {
			if a, err := parseAddr(e.Addr); err == nil {
				freezer.mu.Lock()
				if fe, ok := freezer.entries[a]; ok {
					row.Frozen = true
					row.FreezeMode = string(fe.mode)
					row.FreezeValue = decodeValue(fe.vt, fe.val)
				}
				freezer.mu.Unlock()
			}
		}
		tbl.Entries = append(tbl.Entries, row)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="capx-table-%s.json"`, time.Now().Format("20060102-150405")))
	_ = json.NewEncoder(w).Encode(tbl)
}

// memTableImport restores entries from a cheat-table JSON body. When replace is
// true the existing address list is cleared first. When a sid is supplied,
// rowsked frozen are re-frozen on that session.
func (s *Server) memTableImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SID     string    `json:"sid"`
		Replace bool      `json:"replace"`
		Entries []ctEntry `json:"entries"`
		// Allow posting a whole exported file directly.
		Table *cheatTable `json:"table"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	entries := req.Entries
	if req.Table != nil && len(req.Table.Entries) > 0 {
		entries = req.Table.Entries
	}
	if len(entries) == 0 {
		writeErr(w, http.StatusBadRequest, "no entries to import")
		return
	}

	s.addrs.mu.Lock()
	if req.Replace {
		s.addrs.entries = make(map[int64]*addrEntry)
	}
	imported := 0
	now := time.Now().UnixNano()
	type pendingFreeze struct {
		addr uint64
		vt   memscan.ValueType
		mode freezeMode
		val  json.Number
	}
	var freezes []pendingFreeze
	for i, row := range entries {
		vt := memscan.ValueType(row.Type)
		if vt.Width() == 0 {
			continue
		}
		id := now + int64(i)
		entry := &addrEntry{ID: id, Type: vt, Desc: row.Desc, Expr: row.Expr}
		var a uint64
		if entry.Expr == "" {
			var err error
			a, err = parseAddr(row.Addr)
			if err != nil {
				continue
			}
			entry.Addr = formatHex(a)
		}
		s.addrs.entries[id] = entry
		imported++
		if row.Frozen && req.SID != "" && row.FreezeValue != nil && entry.Expr == "" {
			mode := freezeMode(row.FreezeMode)
			if mode == "" {
				mode = freezeSet
			}
			freezes = append(freezes, pendingFreeze{
				addr: a, vt: vt, mode: mode,
				val: json.Number(fmt.Sprintf("%v", row.FreezeValue)),
			})
		}
	}
	s.addrs.save()
	s.addrs.mu.Unlock()

	// Re-apply freezes outside the addrlist lock.
	reFrozen := 0
	if req.SID != "" && len(freezes) > 0 {
		if sess, ok := s.session(req.SID); ok {
			f := s.freezerFor(req.SID, sess)
			for _, pf := range freezes {
				val, err := encodeValue(pf.vt, pf.val)
				if err != nil {
					continue
				}
				f.set(pf.addr, pf.vt, pf.mode, val)
				reFrozen++
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"imported": imported, "refrozen": reFrozen})
}
