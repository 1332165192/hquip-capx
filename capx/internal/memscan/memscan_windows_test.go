//go:build windows && !memscan_ffi

package memscan

import (
	"encoding/binary"
	"os"
	"testing"
	"unsafe"
)

var testNeedleU32 uint32 = 0x78563412

func TestWindowsScannerFindsOwnProcessValue(t *testing.T) {
	sc := New()
	if !sc.Available() {
		t.Fatal("scanner is not available")
	}
	sess, err := sc.Open(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("open self: %v", err)
	}
	defer sess.Close()

	addr := uint64(uintptr(unsafe.Pointer(&testNeedleU32)))
	page := addr &^ 0xfff
	if err := sess.SetOpts(1, page, page+0x1000, true); err != nil {
		t.Fatalf("set opts: %v", err)
	}
	var value [4]byte
	binary.LittleEndian.PutUint32(value[:], testNeedleU32)
	n, err := sess.FirstScan(U32, value[:])
	if err != nil {
		t.Fatalf("first scan: %v", err)
	}
	if n == 0 {
		t.Fatal("first scan returned no hits")
	}
	addrs, err := sess.Results(32)
	if err != nil {
		t.Fatalf("results: %v", err)
	}
	for _, got := range addrs {
		if got == addr {
			return
		}
	}
	t.Fatalf("target address 0x%x not in first %d hits: %v", addr, len(addrs), addrs)
}
