//go:build windows && !memscan_ffi

package memscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	processQueryInformation = 0x0400
	processVMOperation      = 0x0008
	processVMRead           = 0x0010
	processVMWrite          = 0x0020

	memCommit = 0x1000
	memImage  = 0x1000000

	pageNoAccess         = 0x01
	pageReadonly         = 0x02
	pageReadwrite        = 0x04
	pageWritecopy        = 0x08
	pageExecuteRead      = 0x20
	pageExecuteReadwrite = 0x40
	pageExecuteWritecopy = 0x80
	pageGuard            = 0x100
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess       = kernel32.NewProc("OpenProcess")
	procCloseHandle       = kernel32.NewProc("CloseHandle")
	procReadProcessMemory = kernel32.NewProc("ReadProcessMemory")
	procWriteProcessMem   = kernel32.NewProc("WriteProcessMemory")
	procVirtualQueryEx    = kernel32.NewProc("VirtualQueryEx")
	procIsWow64Process    = kernel32.NewProc("IsWow64Process")
)

type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type region struct {
	base     uint64
	size     uint64
	writable bool
	image    bool
}

type winScanner struct{}

func newScanner() Scanner { return winScanner{} }

func (winScanner) Available() bool { return true }

func (winScanner) Open(pid uint32) (Session, error) {
	access := uintptr(processQueryInformation | processVMRead | processVMWrite | processVMOperation)
	h, _, err := procOpenProcess.Call(access, 0, uintptr(pid))
	if h == 0 {
		if err != syscall.Errno(0) {
			return nil, fmt.Errorf("memscan: cannot open pid %d: %w", pid, err)
		}
		return nil, fmt.Errorf("memscan: cannot open pid %d", pid)
	}
	return &winSession{
		h:        syscall.Handle(h),
		pid:      pid,
		round:    RoundExact,
		ptrWidth: detectPtrWidth(syscall.Handle(h)),
	}, nil
}

type winSession struct {
	h syscall.Handle

	pid          uint32
	ptrWidth     int
	round        RoundMode
	align        uint64
	rangeLo      uint64
	rangeHi      uint64
	writableOnly bool

	vt       ValueType
	hits     []uint64
	prev     map[uint64][]byte
	first    map[uint64][]byte
	ptrPaths []PointerPath
}

func detectPtrWidth(h syscall.Handle) int {
	var wow uint32
	r1, _, _ := procIsWow64Process.Call(uintptr(h), uintptr(unsafe.Pointer(&wow)))
	if r1 != 0 && wow != 0 {
		return 4
	}
	return 8
}

func (s *winSession) PtrWidth() int {
	if s.ptrWidth == 4 {
		return 4
	}
	return 8
}

func (s *winSession) Read(addr uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var n uintptr
	r1, _, err := procReadProcessMemory.Call(
		uintptr(s.h),
		uintptr(addr),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)),
	)
	if r1 == 0 {
		if n > 0 {
			return int(n), nil
		}
		if err != syscall.Errno(0) {
			return 0, err
		}
		return 0, syscall.EINVAL
	}
	return int(n), nil
}

func (s *winSession) Write(addr uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var n uintptr
	r1, _, err := procWriteProcessMem.Call(
		uintptr(s.h),
		uintptr(addr),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)),
	)
	if r1 == 0 {
		if n > 0 {
			return int(n), nil
		}
		if err != syscall.Errno(0) {
			return 0, err
		}
		return 0, syscall.EINVAL
	}
	return int(n), nil
}

func (s *winSession) FirstScan(vt ValueType, value []byte) (int, error) {
	wd := vt.Width()
	if wd == 0 || len(value) < wd {
		return 0, fmt.Errorf("memscan: bad value type or empty value")
	}
	hits, prev, err := s.scanNeedle(vt, value[:wd], uint64(wd))
	if err != nil {
		return 0, err
	}
	s.vt = vt
	s.hits = hits
	s.prev = prev
	s.first = cloneMap(prev)
	return len(hits), nil
}

func (s *winSession) Snapshot(vt ValueType) (int, error) {
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
			v := append([]byte(nil), buf[off:off+wd]...)
			hits = append(hits, addr)
			prev[addr] = v
			if len(hits) >= DefaultMaxSnapHits {
				stopped = true
				return
			}
		}
	})
	if err != nil {
		return 0, err
	}
	s.vt = vt
	s.hits = hits
	s.prev = prev
	s.first = cloneMap(prev)
	return len(hits) * wd, nil
}

func (s *winSession) NextScan(op Op, value []byte) (int, error) {
	wd := s.vt.Width()
	if wd == 0 {
		return 0, fmt.Errorf("memscan: no previous scan")
	}
	var lo, hi []byte
	if len(value) >= wd {
		lo = value[:wd]
	}
	if op == OpBetween {
		if len(value) < wd*2 {
			return 0, fmt.Errorf("memscan: between requires two values")
		}
		hi = value[wd : wd*2]
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
		if winMatchOp(s.vt, s.round, op, cur, ref, lo, hi) {
			nextHits = append(nextHits, addr)
			nextPrev[addr] = cur
		}
	}
	s.hits = nextHits
	s.prev = nextPrev
	return len(nextHits), nil
}

func (s *winSession) AOBScan(pattern string) (int, error) {
	needle, mask, err := parseAOB(pattern)
	if err != nil {
		return 0, err
	}
	hits := make([]uint64, 0)
	prev := make(map[uint64][]byte)
	err = s.walkChunks(len(needle), func(base uint64, buf []byte) {
		limit := len(buf) - len(needle)
		for off := 0; off <= limit; off++ {
			if matchMasked(buf[off:off+len(needle)], needle, mask) {
				addr := base + uint64(off)
				hits = append(hits, addr)
				prev[addr] = append([]byte(nil), buf[off:off+len(needle)]...)
			}
		}
	})
	if err != nil {
		return 0, err
	}
	s.vt = U8
	s.hits = hits
	s.prev = prev
	s.first = cloneMap(prev)
	return len(hits), nil
}

func (s *winSession) StringScan(text string, wide bool) (int, error) {
	var needle []byte
	if wide {
		for _, r := range utf16.Encode([]rune(text)) {
			var b [2]byte
			binary.LittleEndian.PutUint16(b[:], r)
			needle = append(needle, b[:]...)
		}
	} else {
		needle = []byte(text)
	}
	if len(needle) == 0 {
		return 0, fmt.Errorf("memscan: empty string")
	}
	hits, prev, err := s.scanBytes(needle)
	if err != nil {
		return 0, err
	}
	s.vt = U8
	s.hits = hits
	s.prev = prev
	s.first = cloneMap(prev)
	return len(hits), nil
}

func (s *winSession) SetRound(mode RoundMode) error {
	s.round = mode
	return nil
}

func (s *winSession) SetOpts(align, rangeLo, rangeHi uint64, writableOnly bool) error {
	s.align = align
	s.rangeLo = rangeLo
	s.rangeHi = rangeHi
	s.writableOnly = writableOnly
	return nil
}

func (s *winSession) Results(max int) ([]uint64, error) {
	if max <= 0 || max > len(s.hits) {
		max = len(s.hits)
	}
	out := make([]uint64, max)
	copy(out, s.hits[:max])
	return out, nil
}

func (s *winSession) PointerScan(target, maxOffset uint64, maxLevel uint32) (int, error) {
	regs, err := s.regions()
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

func (s *winSession) PointerPaths(max int) ([]PointerPath, error) {
	if max <= 0 || max > len(s.ptrPaths) {
		max = len(s.ptrPaths)
	}
	out := make([]PointerPath, max)
	copy(out, s.ptrPaths[:max])
	return out, nil
}

func (s *winSession) PointerResolve(idx int) (uint64, bool, error) {
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

func (s *winSession) Close() error {
	if s.h != 0 {
		procCloseHandle.Call(uintptr(s.h))
		s.h = 0
	}
	return nil
}

func (s *winSession) regions() ([]region, error) {
	var out []region
	var addr uintptr
	mbiSize := unsafe.Sizeof(memoryBasicInformation{})
	for {
		var mbi memoryBasicInformation
		r1, _, _ := procVirtualQueryEx.Call(
			uintptr(s.h),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			mbiSize,
		)
		if r1 == 0 {
			break
		}
		base := uint64(mbi.BaseAddress)
		size := uint64(mbi.RegionSize)
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
		if mbi.State != memCommit || size == 0 || !readableProtect(mbi.Protect) {
			continue
		}
		writable := writableProtect(mbi.Protect)
		if s.writableOnly && !writable {
			continue
		}
		lo, hi := base, base+size
		if s.rangeLo != 0 && lo < s.rangeLo {
			lo = s.rangeLo
		}
		if s.rangeHi != 0 && hi > s.rangeHi {
			hi = s.rangeHi
		}
		if hi <= lo {
			continue
		}
		out = append(out, region{base: lo, size: hi - lo, writable: writable, image: mbi.Type == memImage})
	}
	return out, nil
}

func (s *winSession) walkChunks(overlap int, fn func(base uint64, buf []byte)) error {
	regs, err := s.regions()
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
			if pos+want < r.size {
				want += uint64(overlap - 1)
				if want > r.size-pos {
					want = r.size - pos
				}
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

func (s *winSession) scanNeedle(vt ValueType, needle []byte, width uint64) ([]uint64, map[uint64][]byte, error) {
	hits := make([]uint64, 0)
	prev := make(map[uint64][]byte)
	step := s.step(width)
	err := s.walkChunks(len(needle), func(base uint64, buf []byte) {
		limit := len(buf) - len(needle)
		for off := 0; off <= limit; off += int(step) {
			cur := buf[off : off+len(needle)]
			if winValueEq(vt, s.round, cur, needle) {
				addr := base + uint64(off)
				hits = append(hits, addr)
				prev[addr] = append([]byte(nil), cur...)
			}
		}
	})
	return hits, prev, err
}

func (s *winSession) scanBytes(needle []byte) ([]uint64, map[uint64][]byte, error) {
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
			prev[addr] = append([]byte(nil), buf[off:off+len(needle)]...)
			start = off + 1
		}
	})
	return hits, prev, err
}

func (s *winSession) step(width uint64) uint64 {
	if s.align > 0 {
		return s.align
	}
	if width == 0 {
		return 1
	}
	return width
}

func readableProtect(p uint32) bool {
	if p&pageGuard != 0 || p&pageNoAccess != 0 {
		return false
	}
	switch p & 0xff {
	case pageReadonly, pageReadwrite, pageWritecopy, pageExecuteRead, pageExecuteReadwrite, pageExecuteWritecopy:
		return true
	default:
		return false
	}
}

func writableProtect(p uint32) bool {
	if p&pageGuard != 0 || p&pageNoAccess != 0 {
		return false
	}
	switch p & 0xff {
	case pageReadwrite, pageWritecopy, pageExecuteReadwrite, pageExecuteWritecopy:
		return true
	default:
		return false
	}
}

func cloneMap(in map[uint64][]byte) map[uint64][]byte {
	out := make(map[uint64][]byte, len(in))
	for k, v := range in {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func parseAOB(pattern string) ([]byte, []bool, error) {
	fields := strings.Fields(strings.TrimSpace(pattern))
	if len(fields) == 0 {
		return nil, nil, fmt.Errorf("memscan: empty AOB pattern")
	}
	needle := make([]byte, len(fields))
	mask := make([]bool, len(fields))
	for i, f := range fields {
		f = strings.TrimSpace(f)
		if f == "?" || f == "??" || strings.Contains(f, "?") {
			mask[i] = false
			continue
		}
		v, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, nil, fmt.Errorf("memscan: bad AOB token %q", f)
		}
		needle[i] = byte(v)
		mask[i] = true
	}
	return needle, mask, nil
}

func matchMasked(cur, needle []byte, mask []bool) bool {
	for i := range needle {
		if mask[i] && cur[i] != needle[i] {
			return false
		}
	}
	return true
}

func winMatchOp(vt ValueType, round RoundMode, op Op, cur, ref, val, val2 []byte) bool {
	switch op {
	case OpEq:
		return val != nil && winValueEq(vt, round, cur, val)
	case OpGt:
		return val != nil && winCmp(vt, cur, val) > 0
	case OpLt:
		return val != nil && winCmp(vt, cur, val) < 0
	case OpBetween:
		return val != nil && val2 != nil && winCmp(vt, cur, val) >= 0 && winCmp(vt, cur, val2) <= 0
	case OpChanged:
		return ref != nil && winCmp(vt, cur, ref) != 0
	case OpUnchanged:
		return ref != nil && winCmp(vt, cur, ref) == 0
	case OpIncreased:
		return ref != nil && winCmp(vt, cur, ref) > 0
	case OpDecreased:
		return ref != nil && winCmp(vt, cur, ref) < 0
	case OpIncBy:
		return ref != nil && val != nil && winDeltaEq(vt, cur, ref, val, 1)
	case OpDecBy:
		return ref != nil && val != nil && winDeltaEq(vt, cur, ref, val, -1)
	default:
		return false
	}
}

func winValueEq(vt ValueType, round RoundMode, a, b []byte) bool {
	switch vt {
	case F32:
		av := float64(math.Float32frombits(binary.LittleEndian.Uint32(a)))
		bv := float64(math.Float32frombits(binary.LittleEndian.Uint32(b)))
		return floatEq(round, av, bv)
	case F64:
		av := math.Float64frombits(binary.LittleEndian.Uint64(a))
		bv := math.Float64frombits(binary.LittleEndian.Uint64(b))
		return floatEq(round, av, bv)
	default:
		return bytes.Equal(a, b)
	}
}

func floatEq(round RoundMode, a, b float64) bool {
	switch round {
	case RoundRounded:
		return math.Round(a) == math.Round(b)
	case RoundTruncated:
		return math.Trunc(a) == math.Trunc(b)
	default:
		return a == b
	}
}

func winCmp(vt ValueType, a, b []byte) int {
	switch vt {
	case I8:
		return cmpInt(int64(int8(a[0])), int64(int8(b[0])))
	case U8:
		return cmpUint(uint64(a[0]), uint64(b[0]))
	case I16:
		return cmpInt(int64(int16(binary.LittleEndian.Uint16(a))), int64(int16(binary.LittleEndian.Uint16(b))))
	case U16:
		return cmpUint(uint64(binary.LittleEndian.Uint16(a)), uint64(binary.LittleEndian.Uint16(b)))
	case I32:
		return cmpInt(int64(int32(binary.LittleEndian.Uint32(a))), int64(int32(binary.LittleEndian.Uint32(b))))
	case U32:
		return cmpUint(uint64(binary.LittleEndian.Uint32(a)), uint64(binary.LittleEndian.Uint32(b)))
	case I64:
		return cmpInt(int64(binary.LittleEndian.Uint64(a)), int64(binary.LittleEndian.Uint64(b)))
	case U64:
		return cmpUint(binary.LittleEndian.Uint64(a), binary.LittleEndian.Uint64(b))
	case F32:
		return cmpFloat(float64(math.Float32frombits(binary.LittleEndian.Uint32(a))), float64(math.Float32frombits(binary.LittleEndian.Uint32(b))))
	case F64:
		return cmpFloat(math.Float64frombits(binary.LittleEndian.Uint64(a)), math.Float64frombits(binary.LittleEndian.Uint64(b)))
	default:
		return bytes.Compare(a, b)
	}
}

func winDeltaEq(vt ValueType, cur, ref, delta []byte, sign int) bool {
	c := winToFloat(vt, cur)
	r := winToFloat(vt, ref)
	d := winToFloat(vt, delta)
	if sign < 0 {
		d = -d
	}
	return c == r+d
}

func winToFloat(vt ValueType, b []byte) float64 {
	switch vt {
	case I8:
		return float64(int8(b[0]))
	case U8:
		return float64(b[0])
	case I16:
		return float64(int16(binary.LittleEndian.Uint16(b)))
	case U16:
		return float64(binary.LittleEndian.Uint16(b))
	case I32:
		return float64(int32(binary.LittleEndian.Uint32(b)))
	case U32:
		return float64(binary.LittleEndian.Uint32(b))
	case I64:
		return float64(int64(binary.LittleEndian.Uint64(b)))
	case U64:
		return float64(binary.LittleEndian.Uint64(b))
	case F32:
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(b)))
	case F64:
		return math.Float64frombits(binary.LittleEndian.Uint64(b))
	default:
		return 0
	}
}

func cmpInt(a, b int64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func cmpUint(a, b uint64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func cmpFloat(a, b float64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
