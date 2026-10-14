package api

// Module list (CE's "Enumerate modules" / the base for module+offset cheat
// table entries). Loaded module images are stable anchors across runs even
// under ASLR, so addresses are usefully expressed as "module.dll+0x1234".

import "net/http"

// memModule is one loaded module image in the target process.
type memModule struct {
	Name string `json:"name"` // base file name, e.g. "game.exe"
	Base uint64 `json:"base"`
	Size uint64 `json:"size"`
	Path string `json:"path,omitempty"`
}

// memModules returns the loaded modules of the attached process, used by the
// UI to show module+offset and by the address-expression resolver.
func (s *Server) memModules(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.session(sid); !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(sid)
	mods, err := listModules(e.pid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(mods))
	for _, m := range mods {
		out = append(out, map[string]any{
			"name": m.Name, "base": formatHex(m.Base), "size": m.Size, "path": m.Path,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(out), "modules": out})
}

// moduleMap returns a name->base lookup (lower-cased names, plus the name
// without extension) for the address-expression resolver.
func moduleMap(pid uint32) map[string]uint64 {
	mods, err := listModules(pid)
	if err != nil {
		return nil
	}
	m := make(map[string]uint64, len(mods)*2)
	for _, mod := range mods {
		name := lowerASCII(mod.Name)
		m[name] = mod.Base
		if i := lastDot(name); i > 0 {
			m[name[:i]] = mod.Base // also index without extension
		}
	}
	return m
}

// moduleLabel formats addr as "module+0xOFFSET" when it falls inside a loaded
// module. This mirrors Cheat Engine's module-offset display and makes ASLR
// affected addresses easier to recognize across runs.
func moduleLabel(pid uint32, addr uint64) string {
	mods, err := listModules(pid)
	if err != nil {
		return ""
	}
	return moduleLabelFromMods(mods, addr)
}

func moduleLabelFromMods(mods []memModule, addr uint64) string {
	var best *memModule
	for i := range mods {
		m := &mods[i]
		if m.Size == 0 || addr < m.Base || addr >= m.Base+m.Size {
			continue
		}
		if best == nil || m.Base > best.Base {
			best = m
		}
	}
	if best == nil {
		return ""
	}
	return best.Name + "+" + formatHex(addr-best.Base)
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}
