//go:build windows

package hook

import (
	"encoding/csv"
	"sort"
	"strconv"
	"strings"

	"github.com/hquip/capx/internal/backgroundprocess"
)

// ListProcesses enumerates processes via tasklist (no extra deps, no frida).
func (m *Manager) ListProcesses() ([]Process, error) {
	out, err := backgroundprocess.Command("tasklist", "/fo", "csv", "/nh").Output()
	if err != nil {
		return nil, err
	}
	r := csv.NewReader(strings.NewReader(string(out)))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	procs := make([]Process, 0, len(rows))
	for _, row := range rows {
		if len(row) < 2 {
			continue
		}
		pid, err := strconv.ParseUint(strings.TrimSpace(row[1]), 10, 32)
		if err != nil {
			continue
		}
		procs = append(procs, Process{PID: uint32(pid), Name: strings.TrimSpace(row[0])})
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, nil
}
