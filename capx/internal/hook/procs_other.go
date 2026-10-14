//go:build !windows && !darwin

package hook

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ListProcesses enumerates processes via /proc (Linux). On platforms without
// /proc it returns an empty list with no error.
func (m *Manager) ListProcesses() ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return []Process{}, nil //nolint:nilerr // no /proc => no enumeration, not an error
	}
	procs := make([]Process, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		name := readProcName(e.Name())
		procs = append(procs, Process{PID: uint32(pid), Name: name})
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, nil
}

func readProcName(pid string) string {
	if b, err := os.ReadFile(filepath.Join("/proc", pid, "comm")); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}
