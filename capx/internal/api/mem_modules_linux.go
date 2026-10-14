//go:build linux

package api

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// listModules derives modules from file-backed mappings in /proc/<pid>/maps,
// collapsing the multiple segments of one image into a single base..end span.
func listModules(pid uint32) ([]memModule, error) {
	f, err := os.Open("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/maps")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type span struct {
		lo, hi uint64
	}
	byPath := map[string]*span{}
	var order []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		path := strings.Join(fields[5:], " ")
		if !strings.HasPrefix(path, "/") {
			continue // anonymous / [heap] / [stack] etc.
		}
		rng := strings.SplitN(fields[0], "-", 2)
		if len(rng) != 2 {
			continue
		}
		lo, err1 := strconv.ParseUint(rng[0], 16, 64)
		hi, err2 := strconv.ParseUint(rng[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		s := byPath[path]
		if s == nil {
			byPath[path] = &span{lo: lo, hi: hi}
			order = append(order, path)
			continue
		}
		if lo < s.lo {
			s.lo = lo
		}
		if hi > s.hi {
			s.hi = hi
		}
	}
	out := make([]memModule, 0, len(order))
	for _, path := range order {
		s := byPath[path]
		out = append(out, memModule{
			Name: filepath.Base(path),
			Base: s.lo,
			Size: s.hi - s.lo,
			Path: path,
		})
	}
	return out, nil
}
