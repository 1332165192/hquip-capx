//go:build linux && !memscan_ffi

package memscan

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type region struct {
	base     uint64
	size     uint64
	writable bool
	image    bool
}

type unixScanner struct{}

func newScanner() Scanner { return unixScanner{} }

func (unixScanner) Available() bool { return true }

func (unixScanner) Open(pid uint32) (Session, error) {
	path := fmt.Sprintf("/proc/%d/mem", pid)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		f, err = os.OpenFile(path, os.O_RDONLY, 0)
		if err != nil {
			return nil, fmt.Errorf("memscan: cannot open %s: %w", path, err)
		}
	}
	return &unixSession{f: f, pid: pid, round: RoundExact, ptrWidth: 8}, nil
}

type unixSession struct {
	f            *os.File
	pid          uint32
	ptrWidth     int
	round        RoundMode
	align        uint64
	rangeLo      uint64
	rangeHi      uint64
	writableOnly bool
	vt           ValueType
	hits         []uint64
	prev         map[uint64][]byte
	ptrPaths     []PointerPath
}

func (s *unixSession) PtrWidth() int {
	if s.ptrWidth == 4 {
		return 4
	}
	return 8
}

func (s *unixSession) Read(addr uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n, err := s.f.ReadAt(buf, int64(addr))
	if n > 0 {
		return n, nil
	}
	return 0, err
}

func (s *unixSession) Write(addr uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n, err := s.f.WriteAt(buf, int64(addr))
	if n > 0 {
		return n, nil
	}
	if err != nil {
		return 0, err
	}
	return 0, syscall.EPERM
}

func (s *unixSession) maps() ([]region, error) {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", s.pid))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []region
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		rng := strings.SplitN(fields[0], "-", 2)
		if len(rng) != 2 {
			continue
		}
		lo, err1 := strconv.ParseUint(rng[0], 16, 64)
		hi, err2 := strconv.ParseUint(rng[1], 16, 64)
		if err1 != nil || err2 != nil || hi <= lo {
			continue
		}
		perms := fields[1]
		if !strings.Contains(perms, "r") {
			continue
		}
		writable := strings.Contains(perms, "w")
		if s.writableOnly && !writable {
			continue
		}
		if s.rangeLo != 0 && lo < s.rangeLo {
			lo = s.rangeLo
		}
		if s.rangeHi != 0 && hi > s.rangeHi {
			hi = s.rangeHi
		}
		if hi <= lo {
			continue
		}
		path := ""
		if len(fields) >= 6 {
			path = strings.Join(fields[5:], " ")
		}
		static := strings.HasPrefix(path, "/")
		out = append(out, region{base: lo, size: hi - lo, writable: writable, image: static})
	}
	return out, sc.Err()
}

func (s *unixSession) walkChunks(overlap int, fn func(base uint64, buf []byte)) error {
	regs, err := s.maps()
	if err != nil {
		return err
	}
	const chunkSize = 2 * 1024 * 1024
	if overlap < 1 {
		overlap = 1
	}
	for _, r := range regs {
		for pos := uint64(0); pos < r.size; {
			want := uint64(chunkSize)
			if left := r.size - pos; left < want {
				want = left
			}
			buf := make([]byte, want)
			n, err := s.Read(r.base+pos, buf)
			if err == nil && n >= overlap {
				fn(r.base+pos, buf[:n])
			}
			if want == 0 {
				break
			}
			pos += uint64(chunkSize)
		}
	}
	return nil
}

func (s *unixSession) step(width uint64) uint64 {
	if s.align > 0 {
		return s.align
	}
	if width == 0 {
		return 1
	}
	return width
}

func (s *unixSession) FirstScan(vt ValueType, value []byte) (int, error) {
	wd := vt.Width()
	if wd == 0 || len(value) < wd {
		return 0, fmt.Errorf("memscan: bad value")
	}
	hits := make([]uint64, 0)
	prev := make(map[uint64][]byte)
	step := s.step(uint64(wd))
	needle := value[:wd]
	err := s.walkChunks(wd, func(base uint64, buf []byte) {
		limit := len(buf) - wd
		for off := 0; off <= limit; off += int(step) {
			if bytes.Equal(buf[off:off+wd], needle) {
				addr := base + uint64(off)
				hits = append(hits, addr)
				prev[addr] = append([]byte(nil), needle...)
			}
		}
	})
	if err != nil {
		return 0, err
	}
	s.vt, s.hits, s.prev = vt, hits, prev
	return len(hits), nil
}

func (s *unixSession) Snapshot(vt ValueType) (int, error) {
	wd := vt.Width()
	if wd == 0 {
		return 0, fmt.Errorf("memscan: bad value type")
	}
	step := s.step(uint64(wd))
	hits := make([]uint64, 0)
	prev := make(map[uint64][]byte)
	stopped := false
	err := s.walkChunks(wd, func(base uint64, buf []byte) {
		if stopped {
			return
		}
		limit := len(buf) - wd
		for off := 0; off <= limit; off += int(step) {
			addr := base + uint64(off)
			hits = append(hits, addr)
			prev[addr] = append([]byte(nil), buf[off:off+wd]...)
			if len(hits) >= DefaultMaxSnapHits {
				stopped = true
				return
			}
		}
	})
	if err != nil {
		return 0, err
	}
	s.vt, s.hits, s.prev = vt, hits, prev
	return len(hits) * wd, nil
}

func (s *unixSession) NextScan(op Op, value []byte) (int, error) {
	wd := s.vt.Width()
	if wd == 0 {
		return 0, fmt.Errorf("memscan: no previous scan")
	}
	nextHits := make([]uint64, 0, len(s.hits))
	nextPrev := make(map[uint64][]byte)
	buf := make([]byte, wd)
	for _, addr := range s.hits {
		n, err := s.Read(addr, buf)
		if err != nil || n != wd {
			continue
		}
		cur := append([]byte(nil), buf...)
		ref := s.prev[addr]
		ok := false
		switch op {
		case OpEq:
			ok = len(value) >= wd && bytes.Equal(cur, value[:wd])
		case OpChanged:
			ok = ref != nil && !bytes.Equal(cur, ref)
		case OpUnchanged:
			ok = ref != nil && bytes.Equal(cur, ref)
		default:
			ok = bytes.Equal(cur, ref)
		}
		if ok {
			nextHits = append(nextHits, addr)
			nextPrev[addr] = cur
		}
	}
	s.hits, s.prev = nextHits, nextPrev
	return len(nextHits), nil
}

func (s *unixSession) AOBScan(pattern string) (int, error) {
	return 0, fmt.Errorf("memscan: AOB on linux Go backend not wired; rebuild with -tags memscan_ffi")
}

func (s *unixSession) StringScan(text string, utf16 bool) (int, error) {
	if text == "" {
		return 0, fmt.Errorf("memscan: empty string")
	}
	needle := []byte(text)
	hits := make([]uint64, 0)
	prev := make(map[uint64][]byte)
	err := s.walkChunks(len(needle), func(base uint64, buf []byte) {
		start := 0
		for {
			idx := bytes.Index(buf[start:], needle)
			if idx < 0 {
				break
			}
			off := start + idx
			addr := base + uint64(off)
			hits = append(hits, addr)
			prev[addr] = append([]byte(nil), needle...)
			start = off + 1
		}
	})
	if err != nil {
		return 0, err
	}
	s.vt, s.hits, s.prev = U8, hits, prev
	return len(hits), nil
}

func (s *unixSession) SetRound(mode RoundMode) error { s.round = mode; return nil }

func (s *unixSession) SetOpts(align, rangeLo, rangeHi uint64, writableOnly bool) error {
	s.align, s.rangeLo, s.rangeHi, s.writableOnly = align, rangeLo, rangeHi, writableOnly
	return nil
}

func (s *unixSession) Results(max int) ([]uint64, error) {
	if max <= 0 || max > len(s.hits) {
		max = len(s.hits)
	}
	out := make([]uint64, max)
	copy(out, s.hits[:max])
	return out, nil
}

func (s *unixSession) PointerScan(target, maxOffset uint64, maxLevel uint32) (int, error) {
	regs, err := s.maps()
	if err != nil {
		return 0, err
	}
	pregs := make([]ptrRegion, 0, len(regs))
	for _, r := range regs {
		pregs = append(pregs, ptrRegion{base: r.base, size: r.size, static: r.image})
	}
	paths, err := runPointerScan(s, pregs, target, maxOffset, maxLevel)
	if err != nil {
		return 0, err
	}
	s.ptrPaths = paths
	return len(paths), nil
}

func (s *unixSession) PointerPaths(max int) ([]PointerPath, error) {
	if max <= 0 || max > len(s.ptrPaths) {
		max = len(s.ptrPaths)
	}
	out := make([]PointerPath, max)
	copy(out, s.ptrPaths[:max])
	return out, nil
}

func (s *unixSession) PointerResolve(idx int) (uint64, bool, error) {
	if idx < 0 || idx >= len(s.ptrPaths) {
		return 0, false, nil
	}
	path := s.ptrPaths[idx]
	addr := path.Base
	wd := s.PtrWidth()
	for _, off := range path.Offsets {
		b := make([]byte, wd)
		n, err := s.Read(addr, b)
		if err != nil || n != wd {
			return 0, false, nil
		}
		if wd == 4 {
			addr = uint64(binary.LittleEndian.Uint32(b)) + off
		} else {
			addr = binary.LittleEndian.Uint64(b) + off
		}
	}
	return addr, true, nil
}

func (s *unixSession) Close() error {
	if s.f != nil {
		return s.f.Close()
	}
	return nil
}
