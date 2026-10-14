//go:build windows

package api

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	modkernel32         = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess     = modkernel32.NewProc("OpenProcess")
	procCloseHandle     = modkernel32.NewProc("CloseHandle")
	procVirtualQueryEx  = modkernel32.NewProc("VirtualQueryEx")
	procGetMappedFileNW = modkernel32.NewProc("GetMappedFileNameW")
)

const (
	winProcessQueryInformation = 0x0400
	winProcessVMRead           = 0x0010

	winMemCommit = 0x1000

	winPageNoAccess         = 0x01
	winPageReadonly         = 0x02
	winPageReadWrite        = 0x04
	winPageWriteCopy        = 0x08
	winPageExecute          = 0x10
	winPageExecuteRead      = 0x20
	winPageExecuteReadWrite = 0x40
	winPageExecuteWriteCopy = 0x80
	winPageGuard            = 0x100
)

type winMemoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionID       uint16
	_                 uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

func winPermString(protect uint32) string {
	if protect&winPageGuard != 0 {
		return "---"
	}
	r, w, x := "-", "-", "-"
	switch protect & 0xFF {
	case winPageReadonly:
		r = "r"
	case winPageReadWrite, winPageWriteCopy:
		r, w = "r", "w"
	case winPageExecute:
		x = "x"
	case winPageExecuteRead:
		r, x = "r", "x"
	case winPageExecuteReadWrite, winPageExecuteWriteCopy:
		r, w, x = "r", "w", "x"
	}
	return r + w + x
}

// listRegions enumerates committed regions of a process via VirtualQueryEx.
func listRegions(pid uint32) ([]memRegion, error) {
	h, _, _ := procOpenProcess.Call(winProcessQueryInformation|winProcessVMRead, 0, uintptr(pid))
	if h == 0 {
		return nil, fmt.Errorf("OpenProcess(%d) failed", pid)
	}
	defer procCloseHandle.Call(h)

	var out []memRegion
	var addr uintptr
	nameBuf := make([]uint16, 1024)
	for {
		var mbi winMemoryBasicInformation
		n, _, _ := procVirtualQueryEx.Call(h, addr, uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi))
		if n == 0 {
			break
		}
		if mbi.State == winMemCommit && mbi.Protect&0xFF != winPageNoAccess {
			path := ""
			if ln, _, _ := procGetMappedFileNW.Call(h, mbi.BaseAddress,
				uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(len(nameBuf))); ln > 0 {
				path = syscall.UTF16ToString(nameBuf[:ln])
			}
			out = append(out, memRegion{
				Start: uint64(mbi.BaseAddress),
				End:   uint64(mbi.BaseAddress) + uint64(mbi.RegionSize),
				Perms: winPermString(mbi.Protect),
				Path:  path,
			})
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
	return out, nil
}
