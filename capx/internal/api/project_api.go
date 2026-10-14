package api

// Project bundle: export/import the whole working state (proxy scope + rules +
// session macros, inline packet rules, Lua scripts with source, and the
// memory address list) as one JSON file so an engagement can be saved and
// restored — or shared with a teammate.

import (
	"net/http"

	"github.com/hquip/capx/internal/inline"
	"github.com/hquip/capx/internal/proxy"
	"github.com/hquip/capx/internal/script"
)

const projectBundleVersion = 1

// projectBundle is the serialized working state.
type projectBundle struct {
	Version  int                    `json:"version"`
	Proxy    *proxy.PersistedConfig `json:"proxy,omitempty"`
	Inline   []*inline.PacketRule   `json:"inline_rules,omitempty"`
	Scripts  []script.ScriptDef     `json:"scripts,omitempty"`
	AddrList []*addrEntry           `json:"addr_list,omitempty"`
}

// exportProject gathers the working state into a downloadable bundle.
func (s *Server) exportProject(w http.ResponseWriter, r *http.Request) {
	b := projectBundle{Version: projectBundleVersion}
	if s.proxy != nil {
		cfg := s.proxy.ExportConfig()
		b.Proxy = &cfg
	}
	if s.inline != nil {
		b.Inline = s.inline.Engine().List()
	}
	if s.script != nil {
		b.Scripts = s.script.Export()
	}
	s.addrs.mu.Lock()
	b.AddrList = s.addrs.sorted()
	s.addrs.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="capx-project.json"`)
	writeJSON(w, http.StatusOK, b)
}

// importProject loads a bundle into the live engines, replacing the current
// proxy config, inline rules, scripts, and address list.
func (s *Server) importProject(w http.ResponseWriter, r *http.Request) {
	var b projectBundle
	if err := decodeBody(r, &b); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if b.Version != projectBundleVersion {
		writeErr(w, http.StatusBadRequest, "unsupported bundle version")
		return
	}
	applied := map[string]int{}

	if b.Proxy != nil && s.proxy != nil {
		s.proxy.ImportConfig(*b.Proxy)
		applied["proxy"] = 1
	}
	if s.inline != nil {
		eng := s.inline.Engine()
		for _, r := range eng.List() { // clear existing
			eng.Delete(r.ID)
		}
		for _, pr := range b.Inline {
			cp := *pr
			cp.ID = ""
			if _, err := eng.Add(&cp); err == nil {
				applied["inline"]++
			}
		}
	}
	if s.script != nil {
		for _, sc := range s.script.List() { // unload existing
			s.script.Delete(sc.ID)
		}
		for _, def := range b.Scripts {
			if _, err := s.script.Add(def.Name, def.Source); err == nil {
				applied["scripts"]++
			}
		}
	}
	// Replace the address list.
	s.addrs.mu.Lock()
	s.addrs.entries = make(map[int64]*addrEntry, len(b.AddrList))
	for _, e := range b.AddrList {
		if e.ID == 0 {
			continue
		}
		cp := *e
		s.addrs.entries[e.ID] = &cp
	}
	s.addrs.save()
	count := len(s.addrs.entries)
	s.addrs.mu.Unlock()
	applied["addr_list"] = count

	writeJSON(w, http.StatusOK, map[string]any{"imported": applied})
}
