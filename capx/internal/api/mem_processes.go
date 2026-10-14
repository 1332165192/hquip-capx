package api

// Process enumeration for the memory-scan layer (CE's "Process List" window).
// Unlike the hook layer's ListProcesses (which only needs pid+name for Frida),
// this endpoint returns richer metadata (user, cmdline) so the CE-style UI can
// present a meaningful process picker. The platform-specific enumeration lives
// in mem_processes_{linux,windows,darwin}.go; this file holds the shared HTTP
// handler and data model.

import (
	"errors"
	"net/http"
)

type procInfo struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"`
	User string `json:"user"`
	Cmd  string `json:"cmd"`
}

// errProcEnumUnsupported is returned by listProcesses on platforms without an
// implementation, so the handler can answer 501 (rather than 500).
var errProcEnumUnsupported = errors.New("process enumeration not supported on this platform")

// memProcesses lists running processes with pid/name/user/cmdline for the
// frontend process picker (replaces manually entering a PID).
func (s *Server) memProcesses(w http.ResponseWriter, r *http.Request) {
	procs, err := listProcesses()
	if err != nil {
		if errors.Is(err, errProcEnumUnsupported) {
			writeErr(w, http.StatusNotImplemented, err.Error())
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(procs), "processes": procs})
}
