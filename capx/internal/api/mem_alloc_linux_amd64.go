//go:build linux && amd64

package api

// In-process memory allocation on Linux/amd64 via ptrace-driven syscall
// injection. There is no Linux equivalent of VirtualAllocEx, so capx attaches
// to the target with ptrace, saves its register state, writes a tiny "syscall;
// int3" stub over a few bytes of the current instruction pointer, points the
// registers at an mmap(2) call (anonymous, private, RWX when exec is requested)
// and runs it. The returned address is read from RAX; the original bytes and
// registers are then restored and we detach, leaving the target running with a
// fresh region — the code cave used by the assembler/patch features.
//
// This needs CAP_SYS_PTRACE / the same UID (yama ptrace_scope permitting), the
// same privilege the rest of the active memory layer already requires.

import (
	"fmt"
	"runtime"
	"syscall"
)

const (
	sysMmap            = 9
	protRead           = 0x1
	protWrite          = 0x2
	protExec           = 0x4
	mapPrivate         = 0x02
	mapAnonymous       = 0x20
	allocStubScratch   = 16
	defaultAllocLength = 0x1000
)

func allocInProcess(pid uint32, size uint64, exec bool, near uint64) (uint64, error) {
	if size == 0 {
		size = defaultAllocLength
	}
	prot := uintptr(protRead | protWrite)
	if exec {
		prot |= protExec
	}

	// ptrace must run on a single OS thread for the duration: all ptrace
	// requests for a tracee must come from the thread that attached.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tpid := int(pid)
	if err := syscall.PtraceAttach(tpid); err != nil {
		return 0, fmt.Errorf("ptrace attach %d: %w", pid, err)
	}
	detached := false
	defer func() {
		if !detached {
			_ = syscall.PtraceDetach(tpid)
		}
	}()
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(tpid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("wait after attach: %w", err)
	}

	var saved syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(tpid, &saved); err != nil {
		return 0, fmt.Errorf("getregs: %w", err)
	}

	// Stub at the current RIP: 0f 05 (syscall), cc (int3 trap to stop us). Save
	// and later restore the bytes we overwrite.
	stubAddr := uintptr(saved.Rip)
	orig := make([]byte, allocStubScratch)
	if n, err := syscall.PtracePeekText(tpid, stubAddr, orig); err != nil || n < len(orig) {
		return 0, fmt.Errorf("peek text @%x: %w", stubAddr, err)
	}
	stub := []byte{0x0f, 0x05, 0xcc}
	patched := make([]byte, len(orig))
	copy(patched, orig)
	copy(patched, stub)
	if _, err := syscall.PtracePokeText(tpid, stubAddr, patched); err != nil {
		return 0, fmt.Errorf("poke stub: %w", err)
	}

	regs := saved
	regs.Rip = uint64(stubAddr)
	regs.Rax = sysMmap
	regs.Rdi = uint64(near) // addr hint (0 = kernel chooses)
	regs.Rsi = size
	regs.Rdx = uint64(prot)
	regs.R10 = mapPrivate | mapAnonymous
	regs.R8 = ^uint64(0) // fd = -1
	regs.R9 = 0          // offset
	if err := syscall.PtraceSetRegs(tpid, &regs); err != nil {
		return 0, fmt.Errorf("setregs: %w", err)
	}

	// Run until the int3 (the syscall has returned by then).
	if err := syscall.PtraceCont(tpid, 0); err != nil {
		return 0, fmt.Errorf("cont: %w", err)
	}
	if _, err := syscall.Wait4(tpid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("wait after syscall: %w", err)
	}

	var result syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(tpid, &result); err != nil {
		return 0, fmt.Errorf("getregs result: %w", err)
	}
	ret := result.Rax

	// Restore original bytes and registers regardless of outcome.
	if _, err := syscall.PtracePokeText(tpid, stubAddr, orig); err != nil {
		return 0, fmt.Errorf("restore text: %w", err)
	}
	if err := syscall.PtraceSetRegs(tpid, &saved); err != nil {
		return 0, fmt.Errorf("restore regs: %w", err)
	}

	// mmap returns -errno (a small negative value) on failure.
	if int64(ret) < 0 && int64(ret) > -4096 {
		return 0, fmt.Errorf("remote mmap failed: errno %d", -int64(ret))
	}

	_ = syscall.PtraceDetach(tpid)
	detached = true
	return ret, nil
}
