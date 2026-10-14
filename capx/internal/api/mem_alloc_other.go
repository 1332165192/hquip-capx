//go:build !windows && (!linux || !amd64) && (!darwin || !cgo)

package api

import "errors"

// allocInProcess: in-process allocation is implemented on Windows
// (VirtualAllocEx), Linux/amd64 (ptrace-driven mmap injection) and macOS with
// cgo (mach_vm_allocate). Other platforms (or macOS built with CGO_ENABLED=0,
// or non-amd64 Linux) fall back to this stub.
func allocInProcess(pid uint32, size uint64, exec bool, near uint64) (uint64, error) {
	return 0, errors.New("in-process allocation supported on windows, linux/amd64, and macOS (cgo) only")
}
