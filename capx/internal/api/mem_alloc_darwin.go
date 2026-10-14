//go:build darwin && cgo

package api

// macOS in-process allocation via the Mach VM API. There is no VirtualAllocEx
// equivalent; capx obtains the target task port with task_for_pid and reserves
// memory with mach_vm_allocate, then mach_vm_protect makes it RWX when an
// executable code cave is requested. This mirrors the read/write path the Rust
// memscan engine already uses on macOS, and needs the same authorisation
// (root or a task-port entitlement / SIP allowance).

/*
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_init.h>
#include <mach/task.h>

// capx_alloc reserves `size` bytes in the task owning `pid`. exec!=0 maps it
// RWX. The allocated address is returned via *out. Return codes: 0 ok,
// 1 task_for_pid failed, 2 mach_vm_allocate failed.
static int capx_alloc(int pid, unsigned long long size, int exec, unsigned long long *out) {
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), (pid_t)pid, &task);
    if (kr != KERN_SUCCESS) {
        return 1;
    }
    mach_vm_address_t addr = 0;
    kr = mach_vm_allocate(task, &addr, (mach_vm_size_t)size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), task);
        return 2;
    }
    vm_prot_t prot = VM_PROT_READ | VM_PROT_WRITE;
    if (exec) {
        prot |= VM_PROT_EXECUTE;
    }
    // Best-effort protection change: even if this fails the region is usable RW.
    mach_vm_protect(task, addr, (mach_vm_size_t)size, 0, prot);
    mach_port_deallocate(mach_task_self(), task);
    *out = (unsigned long long)addr;
    return 0;
}
*/
import "C"

import "fmt"

// allocInProcess reserves memory inside the target process. near is ignored on
// macOS (mach_vm_allocate chooses the address); the assembler/patch features use
// 32-bit-relative jumps only when the allocation lands in range, otherwise the
// caller falls back to an absolute jump.
func allocInProcess(pid uint32, size uint64, exec bool, near uint64) (uint64, error) {
	if size == 0 {
		size = 0x1000
	}
	var out C.ulonglong
	execFlag := C.int(0)
	if exec {
		execFlag = 1
	}
	switch C.capx_alloc(C.int(pid), C.ulonglong(size), execFlag, &out) {
	case 1:
		return 0, fmt.Errorf("task_for_pid(%d) failed (need root or a task-port entitlement)", pid)
	case 2:
		return 0, fmt.Errorf("mach_vm_allocate failed")
	}
	return uint64(out), nil
}
