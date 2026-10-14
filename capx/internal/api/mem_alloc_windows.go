//go:build windows

package api

import "fmt"

var (
	procVirtualAllocEx = modkernel32.NewProc("VirtualAllocEx")
)

const (
	winProcessVMOperation = 0x0008
	winMemReserveCommit   = 0x3000 // MEM_COMMIT | MEM_RESERVE
	winPageReadWriteC     = 0x04   // PAGE_READWRITE
	winPageExecReadWriteC = 0x40   // PAGE_EXECUTE_READWRITE
)

// allocInProcess reserves+commits memory in the target via VirtualAllocEx.
func allocInProcess(pid uint32, size uint64, exec bool, near uint64) (uint64, error) {
	access := uintptr(winProcessVMOperation | winProcessVMRead | 0x0020) // +PROCESS_VM_WRITE
	h, _, _ := procOpenProcess.Call(access, 0, uintptr(pid))
	if h == 0 {
		return 0, fmt.Errorf("OpenProcess(%d) failed (need debug rights)", pid)
	}
	defer procCloseHandle.Call(h)

	prot := uintptr(winPageReadWriteC)
	if exec {
		prot = winPageExecReadWriteC
	}
	addr, _, _ := procVirtualAllocEx.Call(h, uintptr(near), uintptr(size), winMemReserveCommit, prot)
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed")
	}
	return uint64(addr), nil
}
