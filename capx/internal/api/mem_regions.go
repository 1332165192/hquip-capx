package api

import "strings"

// memRegion describes one mapped memory region of an attached process, used
// by the hex viewer / region browser and the Go-side scans (group / binary).
type memRegion struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
	Perms string `json:"perms"` // "rwx"-style permission string
	Path  string `json:"path"`  // backing file / [heap] / [stack] / ""
}

func (r memRegion) readable() bool { return len(r.Perms) > 0 && r.Perms[0] == 'r' }
func (r memRegion) writable() bool { return len(r.Perms) > 1 && r.Perms[1] == 'w' }

func (r memRegion) kind() string {
	p := strings.ToLower(r.Path)
	switch {
	case p == "[heap]" || strings.Contains(p, "[heap]"):
		return "heap"
	case strings.Contains(p, "[stack]") || strings.HasPrefix(p, "[stack"):
		return "stack"
	case p == "" || strings.HasPrefix(p, "[anon") || p == "[anonymous]":
		return "anon"
	case strings.Contains(p, ".so") || strings.Contains(p, ".dll") || strings.Contains(p, ".dylib") ||
		strings.HasSuffix(p, ".exe") || strings.Contains(p, "/usr/") || strings.Contains(p, `\Windows\`):
		if r.writable() {
			return "module_data"
		}
		return "module"
	default:
		if r.writable() && r.readable() {
			return "data"
		}
		return "other"
	}
}

func regionKindOK(kind, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" || want == "all" {
		return true
	}
	switch want {
	case "heap":
		return kind == "heap"
	case "stack":
		return kind == "stack"
	case "data", "module_data":
		return kind == "data" || kind == "module_data" || kind == "heap"
	case "module":
		return kind == "module" || kind == "module_data"
	case "writable", "write":
		return true
	default:
		return kind == want
	}
}
