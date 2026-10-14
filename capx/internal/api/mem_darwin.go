//go:build darwin

package api

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
)

func listRegions(pid uint32) ([]memRegion, error) {
	out, err := exec.Command("vmmap", "-interleaved", strconv.FormatUint(uint64(pid), 10)).Output()
	if err != nil {
		return nil, err
	}
	var regions []memRegion
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.Contains(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		rng := ""
		for _, f := range fields {
			if strings.Contains(f, "-") && strings.ContainsAny(f, "0123456789abcdefABCDEF") {
				rng = f
				break
			}
		}
		if rng == "" {
			continue
		}
		parts := strings.SplitN(rng, "-", 2)
		if len(parts) != 2 {
			continue
		}
		lo, err1 := strconv.ParseUint(strings.TrimPrefix(parts[0], "0x"), 16, 64)
		hi, err2 := strconv.ParseUint(strings.TrimPrefix(parts[1], "0x"), 16, 64)
		if err1 != nil || err2 != nil || hi <= lo {
			continue
		}
		perms := "r--"
		low := strings.ToLower(line)
		if strings.Contains(low, "rw") || strings.Contains(low, "write") {
			perms = "rw-"
		}
		if strings.Contains(low, "x") || strings.Contains(low, "exec") {
			if perms == "rw-" {
				perms = "rwx"
			} else {
				perms = "r-x"
			}
		}
		path := ""
		if i := strings.Index(line, "/"); i >= 0 {
			path = strings.TrimSpace(line[i:])
		}
		regions = append(regions, memRegion{Start: lo, End: hi, Perms: perms, Path: path})
	}
	return regions, nil
}

func listModules(pid uint32) ([]memModule, error) {
	regs, err := listRegions(pid)
	if err != nil {
		return nil, err
	}
	type span struct{ lo, hi uint64 }
	byPath := map[string]*span{}
	var order []string
	for _, r := range regs {
		if r.Path == "" || !strings.HasPrefix(r.Path, "/") {
			continue
		}
		s := byPath[r.Path]
		if s == nil {
			byPath[r.Path] = &span{lo: r.Start, hi: r.End}
			order = append(order, r.Path)
			continue
		}
		if r.Start < s.lo {
			s.lo = r.Start
		}
		if r.End > s.hi {
			s.hi = r.End
		}
	}
	out := make([]memModule, 0, len(order))
	for _, path := range order {
		s := byPath[path]
		name := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			name = path[i+1:]
		}
		out = append(out, memModule{Name: name, Base: s.lo, Size: s.hi - s.lo, Path: path})
	}
	return out, nil
}
