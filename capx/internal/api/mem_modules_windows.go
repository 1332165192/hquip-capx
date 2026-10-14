//go:build windows

package api

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procModule32FirstW           = modkernel32.NewProc("Module32FirstW")
	procModule32NextW            = modkernel32.NewProc("Module32NextW")
)

const (
	th32csSnapModule   = 0x00000008
	th32csSnapModule32 = 0x00000010
)

// moduleEntry32W mirrors the Win32 MODULEENTRY32W structure.
type moduleEntry32W struct {
	dwSize        uint32
	th32ModuleID  uint32
	th32ProcessID uint32
	GlblcntUsage  uint32
	ProccntUsage  uint32
	modBaseAddr   uintptr
	modBaseSize   uint32
	hModule       uintptr
	szModule      [256]uint16
	szExePath     [260]uint16
}

// listModules enumerates loaded modules via the Toolhelp32 snapshot API.
func listModules(pid uint32) ([]memModule, error) {
	snap, _, _ := procCreateToolhelp32Snapshot.Call(uintptr(th32csSnapModule|th32csSnapModule32), uintptr(pid))
	if snap == 0 || snap == uintptr(^uintptr(0)) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot(%d) failed", pid)
	}
	defer procCloseHandle.Call(snap)

	var me moduleEntry32W
	me.dwSize = uint32(unsafe.Sizeof(me))
	r, _, _ := procModule32FirstW.Call(snap, uintptr(unsafe.Pointer(&me)))
	if r == 0 {
		return nil, fmt.Errorf("Module32First failed (pid %d)", pid)
	}
	var out []memModule
	for {
		path := syscall.UTF16ToString(me.szExePath[:])
		name := syscall.UTF16ToString(me.szModule[:])
		if name == "" {
			name = filepath.Base(path)
		}
		out = append(out, memModule{
			Name: name,
			Base: uint64(me.modBaseAddr),
			Size: uint64(me.modBaseSize),
			Path: path,
		})
		me.dwSize = uint32(unsafe.Sizeof(me))
		if r, _, _ := procModule32NextW.Call(snap, uintptr(unsafe.Pointer(&me))); r == 0 {
			break
		}
	}
	return out, nil
}
