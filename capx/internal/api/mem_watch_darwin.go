//go:build darwin && cgo && machwatch && amd64

package api

// macOS/amd64 hardware watchpoints ("find out what writes this address") via
// Mach: capx obtains the task port (task_for_pid), programs the x86 debug
// registers DR0–DR3/DR7 on every thread (thread_set_state with
// x86_DEBUG_STATE64), installs a Mach exception port for EXC_BREAKPOINT, and a
// locked goroutine drains exception messages — reading the faulting RIP and the
// DR6 status to attribute each hit to a slot, then replies KERN_SUCCESS to
// resume the thread.
//
// This is gated behind the opt-in "machwatch" build tag: it is intricate Mach
// code that must be verified on a macOS host (it needs root or a debugger
// entitlement, and SIP may block task_for_pid on system binaries). Default
// macOS builds keep the portable stub. Build with:
//
//	CGO_ENABLED=1 go build -tags machwatch ./...

/*
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <stdlib.h>
#include <string.h>

// Exception message layouts (EXCEPTION_DEFAULT, no MACH_EXCEPTION_CODES), as
// produced by the MIG exc.defs interface.
typedef struct {
    mach_msg_header_t Head;
    mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t NDR;
    exception_type_t exception;
    mach_msg_type_number_t codeCnt;
    integer_t code[2];
    char pad[512];
} capx_exc_request;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t NDR;
    kern_return_t RetCode;
} capx_exc_reply;

// dr7_for builds the DR7 control word for n local slots (rw: 0=x,1=w,3=rw;
// len: 0=1,1=2,3=4,2=8 byte).
static unsigned long long capx_dr7(int n, int *rw, int *len) {
    unsigned long long dr7 = 0x100ULL; // LE
    for (int i = 0; i < n; i++) {
        dr7 |= (1ULL << (i * 2)); // local enable Li
        dr7 |= (((unsigned long long)(rw[i] & 0x3) | ((unsigned long long)(len[i] & 0x3) << 2)) << (16 + i * 4));
    }
    return dr7;
}

// capx_watch_setup arms the debug registers on every thread and installs the
// exception port. Returns 0 on success (and sets *taskOut/*portOut), else a
// nonzero error code: 1 task_for_pid, 2 task_threads, 3 port alloc, 4 set ports.
static int capx_watch_setup(int pid, unsigned long long *addrs, int *rw, int *len, int n,
                            task_t *taskOut, mach_port_t *portOut) {
    task_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), (pid_t)pid, &task) != KERN_SUCCESS) {
        return 1;
    }
    thread_act_array_t threads;
    mach_msg_type_number_t tcount = 0;
    if (task_threads(task, &threads, &tcount) != KERN_SUCCESS) {
        return 2;
    }
    unsigned long long dr7 = capx_dr7(n, rw, len);
    for (unsigned i = 0; i < tcount; i++) {
        x86_debug_state64_t ds;
        memset(&ds, 0, sizeof(ds));
        if (n > 0) ds.__dr0 = addrs[0];
        if (n > 1) ds.__dr1 = addrs[1];
        if (n > 2) ds.__dr2 = addrs[2];
        if (n > 3) ds.__dr3 = addrs[3];
        ds.__dr7 = dr7;
        thread_set_state(threads[i], x86_DEBUG_STATE64, (thread_state_t)&ds, x86_DEBUG_STATE64_COUNT);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, tcount * sizeof(thread_act_t));

    mach_port_t port = MACH_PORT_NULL;
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) {
        return 3;
    }
    mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (task_set_exception_ports(task, EXC_MASK_BREAKPOINT, port,
                                 EXCEPTION_DEFAULT, THREAD_STATE_NONE) != KERN_SUCCESS) {
        return 4;
    }
    *taskOut = task;
    *portOut = port;
    return 0;
}

// capx_watch_wait blocks up to timeoutMs for one breakpoint exception. On a hit
// it fills *rip and *slot, resumes the thread, and returns 0. Returns 1 on
// timeout, 2 on receive error.
static int capx_watch_wait(mach_port_t port, int timeoutMs, unsigned long long *rip, int *slot) {
    capx_exc_request req;
    memset(&req, 0, sizeof(req));
    mach_msg_return_t r = mach_msg(&req.Head, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                   0, sizeof(req), port, timeoutMs, MACH_PORT_NULL);
    if (r == MACH_RCV_TIMED_OUT) return 1;
    if (r != MACH_MSG_SUCCESS) return 2;

    thread_act_t thread = req.thread.name;

    x86_thread_state64_t ts;
    mach_msg_type_number_t tc = x86_THREAD_STATE64_COUNT;
    if (thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)&ts, &tc) == KERN_SUCCESS) {
        *rip = ts.__rip;
    }
    x86_debug_state64_t ds;
    mach_msg_type_number_t dc = x86_DEBUG_STATE64_COUNT;
    int s = 0;
    if (thread_get_state(thread, x86_DEBUG_STATE64, (thread_state_t)&ds, &dc) == KERN_SUCCESS) {
        for (int i = 0; i < 4; i++) {
            if (ds.__dr6 & (1ULL << i)) { s = i; break; }
        }
        ds.__dr6 = 0; // clear status so the next hit is reported
        thread_set_state(thread, x86_DEBUG_STATE64, (thread_state_t)&ds, x86_DEBUG_STATE64_COUNT);
    }
    *slot = s;

    capx_exc_reply reply;
    memset(&reply, 0, sizeof(reply));
    reply.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(req.Head.msgh_bits), 0);
    reply.Head.msgh_size = sizeof(reply);
    reply.Head.msgh_remote_port = req.Head.msgh_remote_port;
    reply.Head.msgh_local_port = MACH_PORT_NULL;
    reply.Head.msgh_id = req.Head.msgh_id + 100;
    reply.NDR = NDR_record;
    reply.RetCode = KERN_SUCCESS;
    mach_msg(&reply.Head, MACH_SEND_MSG, sizeof(reply), 0, MACH_PORT_NULL,
             MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    return 0;
}

static void capx_watch_clear(task_t task, mach_port_t port) {
    thread_act_array_t threads;
    mach_msg_type_number_t tcount = 0;
    if (task_threads(task, &threads, &tcount) == KERN_SUCCESS) {
        for (unsigned i = 0; i < tcount; i++) {
            x86_debug_state64_t ds;
            memset(&ds, 0, sizeof(ds));
            thread_set_state(threads[i], x86_DEBUG_STATE64, (thread_state_t)&ds, x86_DEBUG_STATE64_COUNT);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)threads, tcount * sizeof(thread_act_t));
    }
    mach_port_deallocate(mach_task_self(), port);
}
*/
import "C"

import (
	"fmt"
	"sort"
	"sync"
	"time"
	"unsafe"
)

type darwinWatcher struct {
	mu     sync.Mutex
	hits   map[uint64]*ripStatMac
	err    error
	task   C.task_t
	port   C.mach_port_t
	stopCh chan struct{}
	doneCh chan struct{}
}

type ripStatMac struct {
	count uint64
	slot  int
}

func startWatcher(pid uint32, specs []watchSpec) (memWatcher, error) {
	if len(specs) == 0 || len(specs) > 4 {
		return nil, fmt.Errorf("between 1 and 4 hardware breakpoints required")
	}
	addrs := make([]C.ulonglong, 4)
	rws := make([]C.int, 4)
	lens := make([]C.int, 4)
	for i, sp := range specs {
		addrs[i] = C.ulonglong(sp.Addr)
		rws[i], lens[i] = macRWLen(sp)
	}
	var task C.task_t
	var port C.mach_port_t
	rc := C.capx_watch_setup(C.int(pid), &addrs[0], &rws[0], &lens[0], C.int(len(specs)), &task, &port)
	switch rc {
	case 1:
		return nil, fmt.Errorf("task_for_pid(%d) failed (need root or a debugger entitlement; SIP may block it)", pid)
	case 2:
		return nil, fmt.Errorf("task_threads failed")
	case 3, 4:
		return nil, fmt.Errorf("could not install Mach exception port")
	}
	w := &darwinWatcher{
		hits:   map[uint64]*ripStatMac{},
		task:   task,
		port:   port,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
	go w.run()
	return w, nil
}

// macRWLen maps a watchSpec to the x86 DR7 RW (0=x,1=w,3=rw) and LEN encodings.
func macRWLen(sp watchSpec) (C.int, C.int) {
	rw := 1
	switch sp.Mode {
	case "rw":
		rw = 3
	case "x":
		rw = 0
	}
	ln := 3 // 4 bytes
	if sp.Mode == "x" {
		ln = 0
	} else {
		switch sp.Size {
		case 1:
			ln = 0
		case 2:
			ln = 1
		case 8:
			ln = 2
		}
	}
	return C.int(rw), C.int(ln)
}

func (w *darwinWatcher) run() {
	defer close(w.doneCh)
	for {
		select {
		case <-w.stopCh:
			C.capx_watch_clear(w.task, w.port)
			return
		default:
		}
		var rip C.ulonglong
		var slot C.int
		switch C.capx_watch_wait(w.port, 200, &rip, &slot) {
		case 0:
			w.mu.Lock()
			rs := w.hits[uint64(rip)]
			if rs == nil {
				rs = &ripStatMac{slot: int(slot)}
				w.hits[uint64(rip)] = rs
			}
			rs.count++
			w.mu.Unlock()
		case 2:
			w.setErr(fmt.Errorf("mach_msg receive failed"))
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func (w *darwinWatcher) Hits() []watchHit {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]watchHit, 0, len(w.hits))
	for rip, st := range w.hits {
		out = append(out, watchHit{RIP: formatHex(rip), Count: st.count, Slot: st.slot})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func (w *darwinWatcher) Context() map[string]string { return nil }

func (w *darwinWatcher) setErr(err error) {
	w.mu.Lock()
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
}

func (w *darwinWatcher) Stop() {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
	select {
	case <-w.doneCh:
	case <-time.After(3 * time.Second):
	}
	_ = unsafe.Pointer(nil)
}
