//go:build windows && amd64

package api

// Windows/amd64 hardware watchpoints — CE's "find out what writes/accesses this
// address". We attach as a debugger (DebugActiveProcess), arm DR0–DR3/DR7 on
// every thread via Set/GetThreadContext, then run a debug loop: each hardware
// breakpoint surfaces as an EXCEPTION_SINGLE_STEP whose thread context gives the
// faulting RIP, the DR6 slot, and the full register set. We read a few bytes at
// RIP and disassemble the offending instruction. DebugSetProcessKillOnExit(0)
// ensures detaching leaves the target running.

import (
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"
	"unsafe"
)

var (
	procDebugActiveProcess        = modkernel32.NewProc("DebugActiveProcess")
	procDebugActiveProcessStop    = modkernel32.NewProc("DebugActiveProcessStop")
	procDebugSetProcessKillOnExit = modkernel32.NewProc("DebugSetProcessKillOnExit")
	procWaitForDebugEvent         = modkernel32.NewProc("WaitForDebugEvent")
	procContinueDebugEvent        = modkernel32.NewProc("ContinueDebugEvent")
	procOpenThread                = modkernel32.NewProc("OpenThread")
	procGetThreadContext          = modkernel32.NewProc("GetThreadContext")
	procSetThreadContext          = modkernel32.NewProc("SetThreadContext")
	procReadProcessMemory         = modkernel32.NewProc("ReadProcessMemory")
)

const (
	dbgContinue             = 0x00010002
	dbgExceptionNotHandled  = 0x80010001
	exceptionSingleStep     = 0x80000004
	exceptionBreakpoint     = 0x80000003
	createProcessDebugEvent = 3
	createThreadDebugEvent  = 2
	exitProcessDebugEvent   = 5
	exceptionDebugEvent     = 1
	waitTimeoutMs           = 100
	errSemTimeout           = 121

	threadGetContext       = 0x0008
	threadSetContext       = 0x0010
	threadQueryInformation = 0x0040
	processVMReadW         = 0x0010

	// CONTEXT (amd64) field offsets and flags.
	ctxSize       = 1232
	ctxFlagsOff   = 0x30
	ctxDr0Off     = 0x48
	ctxDr6Off     = 0x68
	ctxDr7Off     = 0x70
	ctxRipOff     = 0xF8
	contextFull   = 0x10000B // AMD64 | CONTROL | INTEGER | FLOATING_POINT
	contextDebug  = 0x100010 // AMD64 | DEBUG_REGISTERS
	contextWanted = contextFull | contextDebug
)

// gpReg lists the integer registers we surface, with their CONTEXT offsets.
var gpRegs = []struct {
	name string
	off  uintptr
}{
	{"rax", 0x78}, {"rcx", 0x80}, {"rdx", 0x88}, {"rbx", 0x90},
	{"rsp", 0x98}, {"rbp", 0xA0}, {"rsi", 0xA8}, {"rdi", 0xB0},
	{"r8", 0xB8}, {"r9", 0xC0}, {"r10", 0xC8}, {"r11", 0xD0},
	{"r12", 0xD8}, {"r13", 0xE0}, {"r14", 0xE8}, {"r15", 0xF0},
	{"rip", 0xF8},
}

type winHit struct {
	count uint64
	slot  int
	insn  string
	regs  map[string]string
}

type windowsWatcher struct {
	mu     sync.Mutex
	hits   map[uint64]*winHit
	err    error
	last   map[string]string
	stopCh chan struct{}
	doneCh chan struct{}
}

func startWatcher(pid uint32, specs []watchSpec) (memWatcher, error) {
	if len(specs) == 0 || len(specs) > 4 {
		return nil, fmt.Errorf("need 1..4 watch slots")
	}
	w := &windowsWatcher{
		hits:   make(map[uint64]*winHit),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	startErr := make(chan error, 1)
	go w.run(pid, specs, startErr)
	if err := <-startErr; err != nil {
		return nil, err
	}
	return w, nil
}

func (w *windowsWatcher) Hits() []watchHit {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]watchHit, 0, len(w.hits))
	for rip, h := range w.hits {
		out = append(out, watchHit{RIP: formatHex(rip), Count: h.count, Slot: h.slot, Insn: h.insn, Regs: h.regs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func (w *windowsWatcher) Context() map[string]string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.last == nil {
		return nil
	}
	out := make(map[string]string, len(w.last))
	for k, v := range w.last {
		out[k] = v
	}
	return out
}

func (w *windowsWatcher) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *windowsWatcher) setErr(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
}

func (w *windowsWatcher) Stop() {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
	select {
	case <-w.doneCh:
	case <-time.After(3 * time.Second):
	}
}

// alignedContext returns a 16-byte-aligned CONTEXT buffer plus a pointer to its
// aligned start. The []byte must be kept alive (runtime.KeepAlive) while the
// pointer is in use.
func alignedContext() ([]byte, unsafe.Pointer) {
	raw := make([]byte, ctxSize+16)
	p0 := unsafe.Pointer(&raw[0])
	off := (16 - uintptr(p0)%16) % 16
	return raw, unsafe.Add(p0, int(off))
}

func ctxU64(p unsafe.Pointer, off uintptr) uint64       { return *(*uint64)(unsafe.Add(p, off)) }
func setCtxU64(p unsafe.Pointer, off uintptr, v uint64) { *(*uint64)(unsafe.Add(p, off)) = v }
func setCtxU32(p unsafe.Pointer, off uintptr, v uint32) { *(*uint32)(unsafe.Add(p, off)) = v }

func winDR7(specs []watchSpec) uint64 {
	dr7 := uint64(0x100) // LE
	for n, sp := range specs {
		dr7 |= 1 << uint(n*2) // local enable Ln
		rw := uint64(0b01)    // write
		switch sp.Mode {
		case "rw":
			rw = 0b11
		case "x":
			rw = 0b00
		}
		var ln uint64
		if sp.Mode == "x" {
			ln = 0b00
		} else {
			switch sp.Size {
			case 1:
				ln = 0b00
			case 2:
				ln = 0b01
			case 8:
				ln = 0b10
			default:
				ln = 0b11
			}
		}
		dr7 |= (rw | ln<<2) << uint(16+n*4)
	}
	return dr7
}

// armThread programs DR0..DR3 + DR7 on one thread id.
func (w *windowsWatcher) armThread(tid uint32, specs []watchSpec) {
	h, _, _ := procOpenThread.Call(uintptr(threadGetContext|threadSetContext|threadQueryInformation), 0, uintptr(tid))
	if h == 0 {
		return
	}
	defer procCloseHandle.Call(h)
	raw, base := alignedContext()
	defer runtime.KeepAlive(raw)
	setCtxU32(base, ctxFlagsOff, contextWanted)
	if r, _, _ := procGetThreadContext.Call(h, uintptr(base)); r == 0 {
		return
	}
	for n, sp := range specs {
		setCtxU64(base, ctxDr0Off+uintptr(n)*8, sp.Addr)
	}
	setCtxU64(base, ctxDr7Off, winDR7(specs))
	setCtxU32(base, ctxFlagsOff, contextWanted)
	procSetThreadContext.Call(h, uintptr(base))
}

func (w *windowsWatcher) run(pid uint32, specs []watchSpec, startErr chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(w.doneCh)

	if r, _, e := procDebugActiveProcess.Call(uintptr(pid)); r == 0 {
		startErr <- fmt.Errorf("DebugActiveProcess(%d) failed: %v (need same-user/admin and no other debugger attached)", pid, e)
		return
	}
	// Don't kill the target when we detach.
	procDebugSetProcessKillOnExit.Call(0)

	// Process handle for reading code at the faulting RIP (disasm).
	hProc, _, _ := procOpenProcess.Call(uintptr(processVMReadW|winProcessQueryInformation), 0, uintptr(pid))
	if hProc != 0 {
		defer procCloseHandle.Call(hProc)
	}

	startErr <- nil

	ev := make([]byte, 4096) // DEBUG_EVENT + union
	evPtr := uintptr(unsafe.Pointer(&ev[0]))
	for {
		select {
		case <-w.stopCh:
			procDebugActiveProcessStop.Call(uintptr(pid))
			return
		default:
		}
		r, _, _ := procWaitForDebugEvent.Call(evPtr, uintptr(waitTimeoutMs))
		if r == 0 {
			continue // timeout: poll stopCh again
		}
		code := *(*uint32)(unsafe.Pointer(&ev[0]))
		tid := *(*uint32)(unsafe.Pointer(&ev[8]))
		cont := uintptr(dbgContinue)

		switch code {
		case createProcessDebugEvent, createThreadDebugEvent:
			// Arm the (existing or new) thread's debug registers.
			w.armThread(tid, specs)
		case exitProcessDebugEvent:
			w.setErr(fmt.Errorf("target exited"))
			procContinueDebugEvent.Call(uintptr(pid), uintptr(tid), uintptr(dbgContinue))
			return
		case exceptionDebugEvent:
			exCode := *(*uint32)(unsafe.Pointer(&ev[16]))
			switch exCode {
			case exceptionSingleStep:
				w.recordHit(tid, hProc, specs)
			case exceptionBreakpoint:
				// initial/loader breakpoint: consume it
			default:
				cont = dbgExceptionNotHandled // pass real exceptions through
			}
		}
		procContinueDebugEvent.Call(uintptr(pid), uintptr(tid), cont)
	}
}

// recordHit reads the faulting thread's context, attributes the hit to a DR
// slot, captures registers + the disassembled instruction, and clears DR6.
func (w *windowsWatcher) recordHit(tid uint32, hProc uintptr, specs []watchSpec) {
	h, _, _ := procOpenThread.Call(uintptr(threadGetContext|threadSetContext|threadQueryInformation), 0, uintptr(tid))
	if h == 0 {
		return
	}
	defer procCloseHandle.Call(h)
	raw, base := alignedContext()
	defer runtime.KeepAlive(raw)
	setCtxU32(base, ctxFlagsOff, contextWanted)
	if r, _, _ := procGetThreadContext.Call(h, uintptr(base)); r == 0 {
		return
	}
	rip := ctxU64(base, ctxRipOff)
	dr6 := ctxU64(base, ctxDr6Off)
	slot := 0
	for n := 0; n < 4; n++ {
		if dr6&(1<<uint(n)) != 0 {
			slot = n
			break
		}
	}
	regs := make(map[string]string, len(gpRegs))
	for _, g := range gpRegs {
		regs[g.name] = formatHex(ctxU64(base, g.off))
	}
	insn := ""
	if hProc != 0 {
		code := make([]byte, 16)
		var read uintptr
		if r, _, _ := procReadProcessMemory.Call(hProc, uintptr(rip),
			uintptr(unsafe.Pointer(&code[0])), uintptr(len(code)), uintptr(unsafe.Pointer(&read))); r != 0 && read > 0 {
			insn = disasmOne(code[:read], rip)
		}
	}

	w.mu.Lock()
	hh := w.hits[rip]
	if hh == nil {
		hh = &winHit{slot: slot}
		w.hits[rip] = hh
	}
	hh.count++
	hh.insn = insn
	hh.regs = regs
	w.last = regs
	w.mu.Unlock()

	// Clear DR6 so the next hit is reported.
	setCtxU64(base, ctxDr6Off, 0)
	setCtxU32(base, ctxFlagsOff, contextWanted)
	procSetThreadContext.Call(h, uintptr(base))
}
