package api

// Pointer-map operations on top of the engine's pointer scan (CE's pointer
// scan "rescan" + save/load): filter the last scan's paths to those that still
// resolve to a (possibly moved) target, export the paths as a portable map, and
// re-check an imported map against the live target so a saved pointer map can
// keep being narrowed across runs.

import (
	"net/http"
)

// ptrPathOut is one exported/returned pointer path.
type ptrPathOut struct {
	Base     string   `json:"base"`
	Offsets  []string `json:"offsets"`
	Resolved string   `json:"resolved,omitempty"`
}

func hexOffsets(offs []uint64) []string {
	out := make([]string, len(offs))
	for i, o := range offs {
		out[i] = formatHex(o)
	}
	return out
}

// memPtrFilter keeps only the last scan's pointer paths that currently resolve
// to target (CE's pointer "rescan" after the value moved to a new address).
func (s *Server) memPtrFilter(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Target string `json:"target"`
		Max    int    `json:"max"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	target, err := parseAddr(req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad target (use 0x... or decimal)")
		return
	}
	max := req.Max
	if max <= 0 || max > 100000 {
		max = 100000
	}
	paths, err := sess.PointerPaths(max)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	kept := make([]ptrPathOut, 0, len(paths))
	for i, p := range paths {
		if addr, ok, _ := sess.PointerResolve(i); ok && addr == target {
			kept = append(kept, ptrPathOut{Base: formatHex(p.Base), Offsets: hexOffsets(p.Offsets), Resolved: formatHex(addr)})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target": formatHex(target), "before": len(paths), "kept": len(kept), "paths": kept,
	})
}

// memPtrMapExport returns the current pointer paths as a portable map that can
// be saved to disk and re-checked later with /ptrmap/check.
func (s *Server) memPtrMapExport(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	max := 100000
	paths, err := sess.PointerPaths(max)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]ptrPathOut, 0, len(paths))
	for _, p := range paths {
		out = append(out, ptrPathOut{Base: formatHex(p.Base), Offsets: hexOffsets(p.Offsets)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "paths": out})
}

// memPtrMapCheck resolves an imported pointer map against live memory and
// returns the paths that currently resolve to target. Unlike /ptrfilter it does
// not rely on the engine's last-scan state, so a saved map (from a previous
// run) can be reloaded and narrowed.
func (s *Server) memPtrMapCheck(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.session(r.PathValue("sid"))
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	var req struct {
		Target string `json:"target"`
		Paths  []struct {
			Base    string   `json:"base"`
			Offsets []string `json:"offsets"`
		} `json:"paths"`
	}
	if err := decodeBody(r, &req); err != nil || len(req.Paths) == 0 {
		writeErr(w, http.StatusBadRequest, "paths required")
		return
	}
	target, err := parseAddr(req.Target)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad target")
		return
	}
	read := sessionPtrReader(sess)
	kept := make([]ptrPathOut, 0, len(req.Paths))
	for _, p := range req.Paths {
		base, err := parseAddr(p.Base)
		if err != nil {
			continue
		}
		offs := make([]uint64, 0, len(p.Offsets))
		bad := false
		for _, o := range p.Offsets {
			v, err := parseAddr(o)
			if err != nil {
				bad = true
				break
			}
			offs = append(offs, v)
		}
		if bad {
			continue
		}
		if addr, ok := resolvePath(base, offs, read); ok && addr == target {
			kept = append(kept, ptrPathOut{Base: formatHex(base), Offsets: hexOffsets(offs), Resolved: formatHex(addr)})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"target": formatHex(target), "checked": len(req.Paths), "kept": len(kept), "paths": kept,
	})
}
