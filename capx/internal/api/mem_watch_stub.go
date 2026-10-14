//go:build ((!linux && !windows) || !amd64) && !(darwin && cgo && machwatch && amd64)

package api

import "errors"

// startWatcher: hardware watchpoints are implemented on linux/amd64 (ptrace
// debug registers), windows/amd64 (DebugActiveProcess + SetThreadContext) and
// macOS/amd64 with cgo when built with -tags machwatch (Mach exception ports).
// Other platforms fall back to this stub.
func startWatcher(pid uint32, specs []watchSpec) (memWatcher, error) {
	return nil, errors.New("hardware watchpoints supported on linux/amd64, windows/amd64, and macOS/amd64 (build -tags machwatch)")
}
