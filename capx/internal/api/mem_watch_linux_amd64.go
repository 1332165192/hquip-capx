//go:build linux && amd64

package api

// Linux/amd64 hardware watchpoints via ptrace debug registers: every thread of
// the target is seized, DR0–DR3 / DR7 are programmed through PTRACE_POKEUSER,
// and a dedicated locked OS thread (ptrace requirement) collects the RIP of
// each SIGTRAP the watchpoints raise. Up to 4 slots can be armed at once and
// each slot can break on write ("w"), access ("rw") or execute ("x").

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	ptraceSeize     = 0x4206
	ptraceInterrupt = 0x4207

	// offsetof(struct user, u_debugreg) on x86_64.
	userDebugRegOffset = 848
	// offsetof(struct user_regs_struct, rip).
	userRegsRIPOffset = 16 * 8
)

type ripStat struct {
	count uint64
	slot  int
	insn  string
	regs  map[string]string
}

// user_regs_struct (amd64) field indices, in units of uint64.
var linuxGPRegs = []struct {
	name string
	idx  int
}{
	{"r15", 0}, {"r14", 1}, {"r13", 2}, {"r12", 3}, {"rbp", 4}, {"rbx", 5},
	{"r11", 6}, {"r10", 7}, {"r9", 8}, {"r8", 9}, {"rax", 10}, {"rcx", 11},
	{"rdx", 12}, {"rsi", 13}, {"rdi", 14}, {"rip", 16}, {"eflags", 18}, {"rsp", 19},
}

type linuxWatcher struct {
	mu     sync.Mutex
	hits   map[uint64]*ripStat
	err    error
	last   map[string]string
	stopCh chan struct{}
	doneCh chan struct{}
}

// startWatcher installs the given DR slots on every thread of pid (max 4).
func startWatcher(pid uint32, specs []watchSpec) (memWatcher, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("no watch slots provided")
	}
	if len(specs) > 4 {
		return nil, fmt.Errorf("at most 4 hardware breakpoints (DR0–DR3)")
	}
	w := &linuxWatcher{
		hits:   make(map[uint64]*ripStat),
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

func (w *linuxWatcher) Hits() []watchHit {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]watchHit, 0, len(w.hits))
	for rip, st := range w.hits {
		out = append(out, watchHit{RIP: formatHex(rip), Count: st.count, Slot: st.slot, Insn: st.insn, Regs: st.regs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// regsAndInsn reads the full integer register set (PTRACE_GETREGS) and the
// bytes at RIP (via /proc/<pid>/mem) to disassemble the faulting instruction.
func regsAndInsn(tid int, pid uint32, rip uint64) (map[string]string, string) {
	var regs [27]uint64
	if err := ptraceRaw(syscall.PTRACE_GETREGS, tid, 0, uintptr(unsafe.Pointer(&regs[0]))); err != nil {
		return nil, ""
	}
	m := make(map[string]string, len(linuxGPRegs))
	for _, g := range linuxGPRegs {
		m[g.name] = formatHex(regs[g.idx])
	}
	insn := ""
	if f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid)); err == nil {
		code := make([]byte, 16)
		if n, err := f.ReadAt(code, int64(rip)); (err == nil || n > 0) && n > 0 {
			insn = disasmOne(code[:n], rip)
		}
		f.Close()
	}
	return m, insn
}

func (w *linuxWatcher) Context() map[string]string {
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

func (w *linuxWatcher) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func (w *linuxWatcher) Stop() {
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

func (w *linuxWatcher) setErr(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
}

func ptraceRaw(req int, tid int, addr, data uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_PTRACE,
		uintptr(req), uintptr(tid), addr, data, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func pokeUser(tid int, off uintptr, val uintptr) error {
	return ptraceRaw(syscall.PTRACE_POKEUSR, tid, off, val)
}

func peekUser(tid int, off uintptr) (uintptr, error) {
	var out uintptr
	err := ptraceRaw(syscall.PTRACE_PEEKUSR, tid, off, uintptr(unsafe.Pointer(&out)))
	return out, err
}

// dr7ForSlots builds the DR7 control word enabling the given slots locally.
// Each slot n contributes the local-enable bit (L0..L3) plus a 4-bit RW/LEN
// field at bit 16+n*4.
func dr7ForSlots(specs []watchSpec) uintptr {
	dr7 := uintptr(0x100) // LE (local exact breakpoint enable)
	for n, sp := range specs {
		dr7 |= 1 << uint(n*2) // Ln local enable
		rw := uintptr(0b01)   // break on data writes
		switch sp.Mode {
		case "rw":
			rw = 0b11 // break on reads and writes
		case "x":
			rw = 0b00 // break on instruction execution
		}
		var ln uintptr
		if sp.Mode == "x" {
			ln = 0b00 // execute breakpoints require LEN=00
		} else {
			switch sp.Size {
			case 1:
				ln = 0b00
			case 2:
				ln = 0b01
			case 8:
				ln = 0b10
			default: // 4
				ln = 0b11
			}
		}
		dr7 |= (rw | ln<<2) << uint(16+n*4)
	}
	return dr7
}

func listTIDs(pid uint32) ([]int, error) {
	ents, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return nil, err
	}
	var tids []int
	for _, e := range ents {
		if tid, err := strconv.Atoi(e.Name()); err == nil {
			tids = append(tids, tid)
		}
	}
	return tids, nil
}

// run is the tracer loop. All ptrace calls for a tracee must come from the
// same OS thread, so the whole lifecycle lives on this locked thread.
func (w *linuxWatcher) run(pid uint32, specs []watchSpec, startErr chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(w.doneCh)

	dr7 := dr7ForSlots(specs)
	tids, err := listTIDs(pid)
	if err != nil {
		startErr <- err
		return
	}
	attached := map[int]bool{}
	detachAll := func() {
		for tid := range attached {
			_ = ptraceRaw(ptraceInterrupt, tid, 0, 0)
			var st syscall.WaitStatus
			_, _ = syscall.Wait4(tid, &st, 0, nil)
			_ = pokeUser(tid, userDebugRegOffset+7*8, 0) // clear DR7
			_ = ptraceRaw(syscall.PTRACE_DETACH, tid, 0, 0)
		}
	}
	arm := func(tid int) error {
		if err := ptraceRaw(ptraceSeize, tid, 0, 0); err != nil {
			return fmt.Errorf("seize tid %d: %w (need same-user or root, check ptrace_scope)", tid, err)
		}
		attached[tid] = true
		if err := ptraceRaw(ptraceInterrupt, tid, 0, 0); err != nil {
			return err
		}
		var st syscall.WaitStatus
		if _, err := syscall.Wait4(tid, &st, 0, nil); err != nil {
			return err
		}
		for n, sp := range specs {
			if err := pokeUser(tid, userDebugRegOffset+uintptr(n)*8, uintptr(sp.Addr)); err != nil {
				return fmt.Errorf("set DR%d: %w", n, err)
			}
		}
		if err := pokeUser(tid, userDebugRegOffset+7*8, dr7); err != nil {
			return fmt.Errorf("set DR7: %w", err)
		}
		return ptraceRaw(syscall.PTRACE_CONT, tid, 0, 0)
	}
	for _, tid := range tids {
		if err := arm(tid); err != nil {
			detachAll()
			startErr <- err
			return
		}
	}
	startErr <- nil

	for {
		select {
		case <-w.stopCh:
			detachAll()
			return
		default:
		}
		var st syscall.WaitStatus
		tid, err := syscall.Wait4(-1, &st, syscall.WNOHANG, nil)
		if err != nil || tid <= 0 {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		if !attached[tid] {
			continue
		}
		if st.Exited() || st.Signaled() {
			delete(attached, tid)
			if len(attached) == 0 {
				w.setErr(fmt.Errorf("target exited"))
				return
			}
			continue
		}
		if !st.Stopped() {
			continue
		}
		sig := st.StopSignal()
		inject := uintptr(0)
		if sig == syscall.SIGTRAP {
			// DR6 bits 0..3 (B0..B3) say which slot fired.
			slot := 0
			if dr6, err := peekUser(tid, userDebugRegOffset+6*8); err == nil {
				for n := 0; n < 4; n++ {
					if dr6&(1<<uint(n)) != 0 {
						slot = n
						break
					}
				}
			}
			if rip, err := peekUser(tid, userRegsRIPOffset); err == nil {
				regs, insn := regsAndInsn(tid, pid, uint64(rip))
				w.mu.Lock()
				rs := w.hits[uint64(rip)]
				if rs == nil {
					rs = &ripStat{slot: slot}
					w.hits[uint64(rip)] = rs
				}
				rs.count++
				if regs != nil {
					rs.regs = regs
				}
				if insn != "" {
					rs.insn = insn
				}
				if regs != nil {
					w.last = regs
				}
				w.mu.Unlock()
			}
			// Clear DR6 so the next hit is reported again.
			_ = pokeUser(tid, userDebugRegOffset+6*8, 0)
		} else if sig != syscall.SIGSTOP {
			inject = uintptr(sig) // forward the real signal
		}
		_ = ptraceRaw(syscall.PTRACE_CONT, tid, 0, inject)
	}
}
