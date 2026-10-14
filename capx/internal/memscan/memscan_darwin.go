//go:build darwin && cgo && !memscan_ffi

package memscan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"
)

/*
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_init.h>
#include <mach/task.h>
#include <mach/vm_region.h>
#include <stdlib.h>

static int capx_task(int pid, mach_port_t *out) {
    return task_for_pid(mach_task_self(), (pid_t)pid, out);
}

static int capx_read(mach_port_t task, unsigned long long addr, void *buf, unsigned long long len, unsigned long long *got) {
    mach_vm_size_t out = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)addr, (mach_vm_size_t)len, (mach_vm_address_t)buf, &out);
    if (kr != KERN_SUCCESS) {
        return (int)kr;
    }
    *got = (unsigned long long)out;
    return 0;
}

static int capx_write(mach_port_t task, unsigned long long addr, const void *buf, unsigned int len) {
    return mach_vm_write(task, (mach_vm_address_t)addr, (vm_offset_t)buf, (mach_msg_type_number_t)len);
}

static int capx_region(mach_port_t task, unsigned long long *addr, unsigned long long *size, int *prot) {
    mach_vm_address_t a = (mach_vm_address_t)*addr;
    mach_vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(task, &a, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &obj);
    if (kr != KERN_SUCCESS) {
        return (int)kr;
    }
    *addr = (unsigned long long)a;
    *size = (unsigned long long)sz;
    *prot = (int)info.protection;
    return 0;
}
*/
import "C"

type region struct {
	base     uint64
	size     uint64
	writable bool
	image    bool
}

type darwinScanner struct{}

func newScanner() Scanner { return darwinScanner{} }

func (darwinScanner) Available() bool { return true }

func (darwinScanner) Open(pid uint32) (Session, error) {
	var task C.mach_port_t
	if kr := C.capx_task(C.int(pid), &task); kr != 0 || task == 0 {
		return nil, fmt.Errorf("memscan: task_for_pid(%d) failed (need root or task-port entitlement, kr=%d)", pid, int(kr))
	}
	return &darwinSession{task: task, pid: pid, round: RoundExact, ptrWidth: 8}, nil
}

type darwinSession struct {
	task         C.mach_port_t
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

func (s *darwinSession) PtrWidth() int {
	if s.ptrWidth == 4 {
		return 4
	}
	return 8
}

func (s *darwinSession) Read(addr uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var got C.ulonglong
	kr := C.capx_read(s.task, C.ulonglong(addr), unsafe.Pointer(&buf[0]), C.ulonglong(len(buf)), &got)
	if kr != 0 {
		if got > 0 {
			return int(got), nil
		}
		return 0, fmt.Errorf("mach_vm_read_overwrite kr=%d", int(kr))
	}
	return int(got), nil
}

func (s *darwinSession) Write(addr uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	kr := C.capx_write(s.task, C.ulonglong(addr), unsafe.Pointer(&buf[0]), C.uint(len(buf)))
	if kr != 0 {
		return 0, fmt.Errorf("mach_vm_write kr=%d", int(kr))
	}
	return len(buf), nil
}

func (s *darwinSession) maps() ([]region, error) {
	var out []region
	var addr uint64
	for i := 0; i < 100000; i++ {
		start := addr
		var size uint64
		var prot C.int
		a := C.ulonglong(addr)
		sz := C.ulonglong(0)
		if kr := C.capx_region(s.task, &a, &sz, &prot); kr != 0 {
			break
		}
		start = uint64(a)
		size = uint64(sz)
		if size == 0 {
			break
		}
		writable := prot&0x2 != 0
		readable := prot&0x1 != 0
		next := start + size
		if readable && !(s.writableOnly && !writable) {
			lo, hi := start, next
			if s.rangeLo != 0 && lo < s.rangeLo {
				lo = s.rangeLo
			}
			if s.rangeHi != 0 && hi > s.rangeHi {
				hi = s.rangeHi
			}
			if hi > lo {
				out = append(out, region{base: lo, size: hi - lo, writable: writable, image: prot&0x2 == 0})
			}
		}
		if next <= addr {
			break
		}
		addr = next
	}
	return out, nil
}

func (s *darwinSession) walkChunks(overlap int, fn func(base uint64, buf []byte)) error {
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

func (s *darwinSession) step(width uint64) uint64 {
	if s.align > 0 {
		return s.align
	}
	if width == 0 {
		return 1
	}
	return width
}

func (s *darwinSession) FirstScan(vt ValueType, value []byte) (int, error) {
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

func (s *darwinSession) Snapshot(vt ValueType) (int, error) {
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

func (s *darwinSession) NextScan(op Op, value []byte) (int, error) {
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

func (s *darwinSession) AOBScan(pattern string) (int, error) {
	return 0, fmt.Errorf("memscan: AOB on darwin Go backend not wired; rebuild with -tags memscan_ffi")
}

func (s *darwinSession) StringScan(text string, utf16 bool) (int, error) {
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

func (s *darwinSession) SetRound(mode RoundMode) error { s.round = mode; return nil }

func (s *darwinSession) SetOpts(align, rangeLo, rangeHi uint64, writableOnly bool) error {
	s.align, s.rangeLo, s.rangeHi, s.writableOnly = align, rangeLo, rangeHi, writableOnly
	return nil
}

func (s *darwinSession) Results(max int) ([]uint64, error) {
	if max <= 0 || max > len(s.hits) {
		max = len(s.hits)
	}
	out := make([]uint64, max)
	copy(out, s.hits[:max])
	return out, nil
}

func (s *darwinSession) PointerScan(target, maxOffset uint64, maxLevel uint32) (int, error) {
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

func (s *darwinSession) PointerPaths(max int) ([]PointerPath, error) {
	if max <= 0 || max > len(s.ptrPaths) {
		max = len(s.ptrPaths)
	}
	out := make([]PointerPath, max)
	copy(out, s.ptrPaths[:max])
	return out, nil
}

func (s *darwinSession) PointerResolve(idx int) (uint64, bool, error) {
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

func (s *darwinSession) Close() error { return nil }
