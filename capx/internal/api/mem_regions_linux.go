//go:build linux

package api

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// listRegions enumerates the mapped regions of a process from
// /proc/<pid>/maps.
func listRegions(pid uint32) ([]memRegion, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []memRegion
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		// e.g. "5651a000-5651b000 rw-p 00002000 08:01 1234  /usr/bin/x"
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		var lo, hi uint64
		if _, err := fmt.Sscanf(fields[0], "%x-%x", &lo, &hi); err != nil {
			continue
		}
		perms := fields[1]
		path := ""
		if len(fields) >= 6 {
			path = strings.Join(fields[5:], " ")
		}
		out = append(out, memRegion{Start: lo, End: hi, Perms: perms, Path: path})
	}
	return out, sc.Err()
}
