//go:build memscan_ffi

// cgo backend linking the Rust memory-scan engine (native/memscan-rs).
//
// Build steps (see packet-capture/capx/scripts/build-memscan.sh):
//  1. cargo build --release in native/memscan-rs (produces libmemscan.a)
//  2. copy the static lib to native/memscan-rs/lib/
//  3. go build -tags memscan_ffi ./...  (from packet-capture/capx, CGO_ENABLED=1)
package memscan

/*
#cgo CFLAGS: -I${SRCDIR}/../../native/memscan-rs/include
#cgo LDFLAGS: -L${SRCDIR}/../../native/memscan-rs/lib -lmemscan
#cgo windows LDFLAGS: -lws2_32 -lbcrypt -luserenv -lntdll -ladvapi32 -lkernel32
#cgo linux LDFLAGS: -ldl -lpthread -lm
#include <stdlib.h>
#include "memscan.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

type ffiScanner struct{}

func newScanner() Scanner { return ffiScanner{} }

func (ffiScanner) Available() bool { return true }

func (ffiScanner) Open(pid uint32) (Session, error) {
	sid := C.msx_open(C.uint32_t(pid))
	if sid == 0 {
		return nil, fmt.Errorf("memscan: cannot open pid %d (need debug privilege / valid pid)", pid)
	}
	return &ffiSession{sid: uint64(sid)}, nil
}

type ffiSession struct{ sid uint64 }

func (s *ffiSession) Read(addr uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := C.msx_read(C.uint64_t(s.sid), C.uint64_t(addr),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.uint64_t(len(buf)))
	if n < 0 {
		return 0, fmt.Errorf("memscan: read failed (bad session)")
	}
	return int(n), nil
}

func (s *ffiSession) Write(addr uint64, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := C.msx_write(C.uint64_t(s.sid), C.uint64_t(addr),
		(*C.uint8_t)(unsafe.Pointer(&buf[0])), C.uint64_t(len(buf)))
	if n < 0 {
		return 0, fmt.Errorf("memscan: write failed (bad session)")
	}
	if n == 0 {
		return 0, fmt.Errorf("memscan: write rejected at 0x%x (no write access / protected page)", addr)
	}
	return int(n), nil
}

func (s *ffiSession) FirstScan(vt ValueType, value []byte) (int, error) {
	if len(value) == 0 {
		return 0, fmt.Errorf("memscan: empty value")
	}
	n := C.msx_scan_first(C.uint64_t(s.sid), C.uint32_t(vt),
		(*C.uint8_t)(unsafe.Pointer(&value[0])), C.uint64_t(len(value)))
	if n < 0 {
		return 0, fmt.Errorf("memscan: first scan failed")
	}
	return int(n), nil
}

func (s *ffiSession) Snapshot(vt ValueType) (int, error) {
	n := C.msx_snapshot(C.uint64_t(s.sid), C.uint32_t(vt))
	if n < 0 {
		return 0, fmt.Errorf("memscan: snapshot failed (bad value type)")
	}
	return int(n), nil
}

func (s *ffiSession) NextScan(op Op, value []byte) (int, error) {
	var ptr *C.uint8_t
	var ln C.uint64_t
	if len(value) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&value[0]))
		ln = C.uint64_t(len(value))
	}
	n := C.msx_scan_next(C.uint64_t(s.sid), C.uint32_t(op), ptr, ln)
	if n < 0 {
		return 0, fmt.Errorf("memscan: next scan failed")
	}
	return int(n), nil
}

func (s *ffiSession) AOBScan(pattern string) (int, error) {
	cs := C.CString(pattern)
	defer C.free(unsafe.Pointer(cs))
	n := C.msx_scan_aob(C.uint64_t(s.sid), cs)
	if n < 0 {
		return 0, fmt.Errorf("memscan: aob scan failed (bad pattern?)")
	}
	return int(n), nil
}

func (s *ffiSession) StringScan(text string, utf16 bool) (int, error) {
	cs := C.CString(text)
	defer C.free(unsafe.Pointer(cs))
	var w C.uint32_t
	if utf16 {
		w = 1
	}
	n := C.msx_scan_string(C.uint64_t(s.sid), cs, w)
	if n < 0 {
		return 0, fmt.Errorf("memscan: string scan failed (empty text?)")
	}
	return int(n), nil
}

func (s *ffiSession) SetRound(mode RoundMode) error {
	if C.msx_set_round(C.uint64_t(s.sid), C.uint32_t(mode)) < 0 {
		return fmt.Errorf("memscan: set round failed (bad session)")
	}
	return nil
}

func (s *ffiSession) SetOpts(align, rangeLo, rangeHi uint64, writableOnly bool) error {
	var wo C.uint32_t
	if writableOnly {
		wo = 1
	}
	rc := C.msx_set_opts(C.uint64_t(s.sid), C.uint64_t(align),
		C.uint64_t(rangeLo), C.uint64_t(rangeHi), wo)
	if rc < 0 {
		return fmt.Errorf("memscan: set opts failed (bad session)")
	}
	return nil
}

func (s *ffiSession) Results(max int) ([]uint64, error) {
	if max <= 0 {
		max = int(C.msx_result_count(C.uint64_t(s.sid)))
	}
	if max == 0 {
		return nil, nil
	}
	out := make([]uint64, max)
	n := C.msx_results(C.uint64_t(s.sid),
		(*C.uint64_t)(unsafe.Pointer(&out[0])), C.uint64_t(max))
	return out[:n], nil
}

func (s *ffiSession) PointerScan(target, maxOffset uint64, maxLevel uint32) (int, error) {
	n := C.msx_pointer_scan(C.uint64_t(s.sid), C.uint64_t(target),
		C.uint64_t(maxOffset), C.uint32_t(maxLevel))
	if n < 0 {
		return 0, fmt.Errorf("memscan: pointer scan failed (bad session / zero target)")
	}
	return int(n), nil
}

func (s *ffiSession) PointerPaths(max int) ([]PointerPath, error) {
	total := int(C.msx_pointer_count(C.uint64_t(s.sid)))
	if max <= 0 || max > total {
		max = total
	}
	if max == 0 {
		return nil, nil
	}
	// A path is [base, off0, off1, ...]; CE caps depth well under this buffer.
	const cap = 64
	buf := make([]uint64, cap)
	paths := make([]PointerPath, 0, max)
	for i := 0; i < max; i++ {
		n := int(C.msx_pointer_path(C.uint64_t(s.sid), C.uint64_t(i),
			(*C.uint64_t)(unsafe.Pointer(&buf[0])), C.uint64_t(cap)))
		if n < 1 {
			continue
		}
		offs := make([]uint64, n-1)
		copy(offs, buf[1:n])
		paths = append(paths, PointerPath{Base: buf[0], Offsets: offs})
	}
	return paths, nil
}

func (s *ffiSession) PointerResolve(idx int) (uint64, bool, error) {
	a := C.msx_pointer_resolve(C.uint64_t(s.sid), C.uint64_t(idx))
	if a < 0 {
		return 0, false, nil
	}
	return uint64(a), true, nil
}

func (s *ffiSession) Close() error {
	C.msx_close(C.uint64_t(s.sid))
	return nil
}

func (s *ffiSession) PtrWidth() int { return 8 }
