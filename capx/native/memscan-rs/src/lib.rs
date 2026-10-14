//! capx memory-scan engine (CE-style).
//!
//! Provides process-memory enumeration, reading, and value/AOB/next scanning
//! behind a small C ABI so the Go core (`capx/internal/memscan`) can
//! drive it over cgo. Platform memory access uses raw OS facilities only
//! (kernel32 on Windows, `/proc/<pid>/{maps,mem}` on Linux) so the crate
//! builds with no third-party dependencies.
//!
//! C ABI (see generated `memscan.h`):
//!   uint64_t msx_open(uint32_t pid);
//!   void     msx_close(uint64_t sid);
//!   int64_t  msx_read(uint64_t sid, uint64_t addr, uint8_t* out, uint64_t len);
//!   int64_t  msx_scan_first(uint64_t sid, uint32_t vtype, const uint8_t* val, uint64_t vlen);
//!   int64_t  msx_scan_next(uint64_t sid, uint32_t op, const uint8_t* val, uint64_t vlen);
//!   int64_t  msx_scan_aob(uint64_t sid, const char* pattern);
//!   uint64_t msx_result_count(uint64_t sid);
//!   uint64_t msx_results(uint64_t sid, uint64_t* out_addrs, uint64_t cap);

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::sync::OnceLock;

// ----------------------------- value types --------------------------------

#[derive(Clone, Copy, PartialEq)]
enum VType {
    I32,
    I64,
    F32,
    F64,
    U32,
    U64,
    U8,
    I8,
    U16,
    I16,
}

impl VType {
    fn from_u32(v: u32) -> Option<VType> {
        match v {
            0 => Some(VType::I32),
            1 => Some(VType::I64),
            2 => Some(VType::F32),
            3 => Some(VType::F64),
            4 => Some(VType::U32),
            5 => Some(VType::U64),
            6 => Some(VType::U8),
            7 => Some(VType::I8),
            8 => Some(VType::U16),
            9 => Some(VType::I16),
            _ => None,
        }
    }
    fn width(self) -> usize {
        match self {
            VType::U8 | VType::I8 => 1,
            VType::U16 | VType::I16 => 2,
            VType::I32 | VType::F32 | VType::U32 => 4,
            VType::I64 | VType::F64 | VType::U64 => 8,
        }
    }
}

/// Float comparison mode for exact/EQ scans. CE's default is "rounded".
mod fround {
    pub const EXACT: u8 = 0; // bit-ish equality within EPSILON
    pub const ROUNDED: u8 = 1; // round-to-nearest-integer equality
    pub const TRUNCATED: u8 = 2; // truncate-toward-zero equality
}

/// Comparison ops for `scan_next`.
mod op {
    pub const EQ: u32 = 0; // current == provided value
    pub const CHANGED: u32 = 1; // current != previous
    pub const UNCHANGED: u32 = 2; // current == previous
    pub const INCREASED: u32 = 3; // current > previous
    pub const DECREASED: u32 = 4; // current < previous
    pub const GT: u32 = 5; // current > provided value
    pub const LT: u32 = 6; // current < provided value
    pub const BETWEEN: u32 = 7; // lo <= current <= hi (value = lo||hi)
    pub const INC_BY: u32 = 8; // current == previous + delta (value = delta)
    pub const DEC_BY: u32 = 9; // current == previous - delta (value = delta)
}

// --------------------------- memory regions -------------------------------

#[derive(Clone, Copy)]
struct Region {
    base: usize,
    size: usize,
    /// Whether the page is writable; used by the writable-only fast-scan filter
    /// and snapshot capture.
    writable: bool,
    /// Whether the region belongs to a loaded module image (MEM_IMAGE on
    /// Windows / a file-backed mapping on Linux). Such addresses are stable
    /// across runs and serve as the "static base" anchor for pointer scans.
    is_static: bool,
}

/// A single surviving scan hit: address + the bytes captured at last scan.
struct Hit {
    addr: usize,
    last: Vec<u8>,
}

/// A resolved pointer path (CE-style "static base + multi-level offsets").
/// Resolution: start at `base` (a static pointer slot), then for each offset
/// `o`: `addr = read_ptr(addr) + o`. The final `addr` is the value address.
struct PtrPath {
    base: usize,
    offsets: Vec<usize>,
}

struct Session {
    mem: Box<dyn MemAccess + Send>,
    vtype: VType,
    hits: Vec<Hit>,
    /// Float comparison mode (see `fround`) applied to F32/F64 equality.
    fround: u8,
    /// Fast-scan step between candidate addresses in `scan_first` (0 => use the
    /// type width, i.e. CE-style aligned fast scan; 1 => unaligned find-all).
    align: usize,
    /// Inclusive lower / exclusive upper address window for every scan
    /// (`range_hi == 0` => unbounded above). Candidate values must fit wholly
    /// inside `[range_lo, range_hi)`.
    range_lo: usize,
    range_hi: usize,
    /// When set, scans skip non-writable regions (CE's "writable only").
    writable_only: bool,
    /// Captured writable-region bytes for an unknown-initial-value scan.
    /// Populated by `snapshot`; consumed (and freed) by the first subsequent
    /// `scan_next`, which compares it against live memory to seed the hits.
    snapshot: Vec<(usize, Vec<u8>)>,
    /// Pointer paths found by the most recent `pointer_scan`.
    ptr_paths: Vec<PtrPath>,
}

trait MemAccess {
    fn regions(&self) -> Vec<Region>;
    /// Reads into `buf`, returns bytes read (0 on failure).
    fn read(&self, addr: usize, buf: &mut [u8]) -> usize;
    /// Writes `buf` at `addr`, returns bytes written (0 on failure).
    fn write(&self, addr: usize, buf: &[u8]) -> usize;
}

// ------------------------------ Windows -----------------------------------

#[cfg(windows)]
mod plat {
    use super::{MemAccess, Region};

    type Handle = isize;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_IMAGE: u32 = 0x100_0000;
    const PAGE_GUARD: u32 = 0x100;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: usize,
        allocation_base: usize,
        allocation_protect: u32,
        _align: u32,
        region_size: usize,
        state: u32,
        protect: u32,
        typ: u32,
    }

    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn CloseHandle(h: Handle) -> i32;
        fn ReadProcessMemory(
            h: Handle,
            addr: usize,
            buf: *mut u8,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn WriteProcessMemory(
            h: Handle,
            addr: usize,
            buf: *const u8,
            size: usize,
            written: *mut usize,
        ) -> i32;
        fn VirtualProtectEx(
            h: Handle,
            addr: usize,
            size: usize,
            new_protect: u32,
            old_protect: *mut u32,
        ) -> i32;
        fn VirtualQueryEx(
            h: Handle,
            addr: usize,
            mbi: *mut MemoryBasicInformation,
            len: usize,
        ) -> usize;
    }

    pub struct WinProc {
        h: Handle,
    }

    impl WinProc {
        pub fn open(pid: u32) -> Option<WinProc> {
            // Prefer read+write+operation so the same handle can modify and
            // freeze values; fall back to read-only if write access is denied.
            const FULL: u32 = PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION;
            let mut h = unsafe { OpenProcess(FULL, 0, pid) };
            if h == 0 {
                h = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
            }
            if h == 0 {
                None
            } else {
                Some(WinProc { h })
            }
        }
    }

    impl Drop for WinProc {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.h);
            }
        }
    }

    fn is_writable(protect: u32) -> bool {
        const PAGE_READWRITE: u32 = 0x04;
        const PAGE_WRITECOPY: u32 = 0x08;
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
        protect
            & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
            != 0
    }

    impl MemAccess for WinProc {
        fn regions(&self) -> Vec<Region> {
            let mut out = Vec::new();
            let mut addr: usize = 0;
            let sz = std::mem::size_of::<MemoryBasicInformation>();
            loop {
                let mut mbi: MemoryBasicInformation = unsafe { std::mem::zeroed() };
                let r = unsafe { VirtualQueryEx(self.h, addr, &mut mbi, sz) };
                if r == 0 {
                    break;
                }
                let readable = mbi.state == MEM_COMMIT
                    && (mbi.protect & PAGE_GUARD) == 0
                    && (mbi.protect & PAGE_NOACCESS) == 0;
                if readable && mbi.region_size > 0 {
                    out.push(Region {
                        base: mbi.base_address,
                        size: mbi.region_size,
                        writable: is_writable(mbi.protect),
                        is_static: mbi.typ == MEM_IMAGE,
                    });
                }
                let next = mbi.base_address.wrapping_add(mbi.region_size);
                if next <= addr {
                    break;
                }
                addr = next;
            }
            out
        }

        fn read(&self, addr: usize, buf: &mut [u8]) -> usize {
            let mut read: usize = 0;
            let ok = unsafe {
                ReadProcessMemory(self.h, addr, buf.as_mut_ptr(), buf.len(), &mut read)
            };
            if ok == 0 {
                0
            } else {
                read
            }
        }

        fn write(&self, addr: usize, buf: &[u8]) -> usize {
            if buf.is_empty() {
                return 0;
            }
            let mut written: usize = 0;
            let ok = unsafe {
                WriteProcessMemory(self.h, addr, buf.as_ptr(), buf.len(), &mut written)
            };
            if ok != 0 {
                return written;
            }
            // Page may be read-only; temporarily make it writable, then restore.
            let mut old: u32 = 0;
            let changed = unsafe {
                VirtualProtectEx(self.h, addr, buf.len(), PAGE_EXECUTE_READWRITE, &mut old)
            };
            if changed == 0 {
                return 0;
            }
            let ok2 = unsafe {
                WriteProcessMemory(self.h, addr, buf.as_ptr(), buf.len(), &mut written)
            };
            let mut tmp: u32 = 0;
            unsafe {
                VirtualProtectEx(self.h, addr, buf.len(), old, &mut tmp);
            }
            if ok2 != 0 {
                written
            } else {
                0
            }
        }
    }

    pub fn open(pid: u32) -> Option<Box<dyn MemAccess + Send>> {
        WinProc::open(pid).map(|p| Box::new(p) as Box<dyn MemAccess + Send>)
    }
}

// ------------------------------- Linux ------------------------------------

#[cfg(all(unix, not(target_os = "macos")))]
mod plat {
    use super::{MemAccess, Region};
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};

    pub struct LinProc {
        pid: u32,
    }

    impl MemAccess for LinProc {
        fn regions(&self) -> Vec<Region> {
            let mut out = Vec::new();
            let maps = match std::fs::read_to_string(format!("/proc/{}/maps", self.pid)) {
                Ok(s) => s,
                Err(_) => return out,
            };
            for line in maps.lines() {
                // format: start-end perms offset dev inode pathname
                let mut it = line.split_whitespace();
                let range = match it.next() {
                    Some(r) => r,
                    None => continue,
                };
                let perms = it.next().unwrap_or("");
                if !perms.starts_with('r') {
                    continue;
                }
                let mut rng = range.split('-');
                let start = rng
                    .next()
                    .and_then(|s| usize::from_str_radix(s, 16).ok());
                let end = rng.next().and_then(|s| usize::from_str_radix(s, 16).ok());
                if let (Some(s), Some(e)) = (start, end) {
                    if e > s {
                        // A file-backed mapping (pathname starting with '/') is a
                        // loaded module image => a stable static-base anchor.
                        let is_static = line
                            .split_whitespace()
                            .nth(5)
                            .map_or(false, |p| p.starts_with('/'));
                        out.push(Region {
                            base: s,
                            size: e - s,
                            writable: perms.as_bytes().get(1) == Some(&b'w'),
                            is_static,
                        });
                    }
                }
            }
            out
        }

        fn read(&self, addr: usize, buf: &mut [u8]) -> usize {
            let mut f = match File::open(format!("/proc/{}/mem", self.pid)) {
                Ok(f) => f,
                Err(_) => return 0,
            };
            if f.seek(SeekFrom::Start(addr as u64)).is_err() {
                return 0;
            }
            f.read(buf).unwrap_or(0)
        }

        fn write(&self, addr: usize, buf: &[u8]) -> usize {
            let mut f = match std::fs::OpenOptions::new()
                .write(true)
                .open(format!("/proc/{}/mem", self.pid))
            {
                Ok(f) => f,
                Err(_) => return 0,
            };
            if f.seek(SeekFrom::Start(addr as u64)).is_err() {
                return 0;
            }
            f.write(buf).unwrap_or(0)
        }
    }

    pub fn open(pid: u32) -> Option<Box<dyn MemAccess + Send>> {
        // Validate the process exists / is accessible.
        if std::fs::metadata(format!("/proc/{}/maps", pid)).is_err() {
            return None;
        }
        Some(Box::new(LinProc { pid }) as Box<dyn MemAccess + Send>)
    }
}

// ------------------------------ macOS -------------------------------------
//
// macOS has no /proc, so memory access goes through the Mach VM API:
// task_for_pid to obtain the target task port, mach_vm_region to enumerate
// regions, and mach_vm_read_overwrite / mach_vm_write to read and write. These
// symbols are exported by libSystem, so no extra crate is needed. task_for_pid
// requires the caller to be root or hold the proper task-port entitlement.

#[cfg(target_os = "macos")]
mod plat {
    #![allow(non_camel_case_types, non_upper_case_globals, dead_code)]
    use super::{MemAccess, Region};
    use std::os::raw::{c_int, c_void};

    type kern_return_t = c_int;
    type mach_port_t = u32;
    type vm_map_t = mach_port_t;
    type mach_vm_address_t = u64;
    type mach_vm_size_t = u64;
    type vm_offset_t = usize;
    type vm_prot_t = c_int;
    type natural_t = u32;

    const KERN_SUCCESS: kern_return_t = 0;
    const VM_PROT_READ: vm_prot_t = 0x1;
    const VM_PROT_WRITE: vm_prot_t = 0x2;
    const VM_REGION_BASIC_INFO_64: c_int = 9;

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct vm_region_basic_info_64 {
        protection: vm_prot_t,
        max_protection: vm_prot_t,
        inheritance: natural_t,
        shared: c_int,
        reserved: c_int,
        offset: u64,
        behavior: c_int,
        user_wired_count: u16,
    }

    extern "C" {
        static mach_task_self_: mach_port_t;
        fn task_for_pid(target_tport: mach_port_t, pid: c_int, t: *mut mach_port_t) -> kern_return_t;
        fn mach_vm_region(
            target_task: vm_map_t,
            address: *mut mach_vm_address_t,
            size: *mut mach_vm_size_t,
            flavor: c_int,
            info: *mut c_void,
            info_cnt: *mut natural_t,
            object_name: *mut mach_port_t,
        ) -> kern_return_t;
        fn mach_vm_read_overwrite(
            target_task: vm_map_t,
            address: mach_vm_address_t,
            size: mach_vm_size_t,
            data: mach_vm_address_t,
            out_size: *mut mach_vm_size_t,
        ) -> kern_return_t;
        fn mach_vm_write(
            target_task: vm_map_t,
            address: mach_vm_address_t,
            data: vm_offset_t,
            data_cnt: natural_t,
        ) -> kern_return_t;
    }

    pub struct MacProc {
        task: mach_port_t,
    }

    impl MemAccess for MacProc {
        fn regions(&self) -> Vec<Region> {
            let mut out = Vec::new();
            let mut addr: mach_vm_address_t = 0;
            loop {
                let mut size: mach_vm_size_t = 0;
                let mut info = vm_region_basic_info_64::default();
                let mut count: natural_t =
                    (std::mem::size_of::<vm_region_basic_info_64>() / std::mem::size_of::<c_int>()) as natural_t;
                let mut object_name: mach_port_t = 0;
                let kr = unsafe {
                    mach_vm_region(
                        self.task,
                        &mut addr,
                        &mut size,
                        VM_REGION_BASIC_INFO_64,
                        &mut info as *mut _ as *mut c_void,
                        &mut count,
                        &mut object_name,
                    )
                };
                if kr != KERN_SUCCESS || size == 0 {
                    break;
                }
                if info.protection & VM_PROT_READ != 0 {
                    out.push(Region {
                        base: addr as usize,
                        size: size as usize,
                        writable: info.protection & VM_PROT_WRITE != 0,
                        // Mach regions don't directly flag file-backed images here;
                        // treat non-writable executable-ish regions as stable anchors.
                        is_static: info.protection & VM_PROT_WRITE == 0,
                    });
                }
                addr = addr.wrapping_add(size);
                if addr == 0 {
                    break;
                }
            }
            out
        }

        fn read(&self, addr: usize, buf: &mut [u8]) -> usize {
            if buf.is_empty() {
                return 0;
            }
            let mut out_size: mach_vm_size_t = 0;
            let kr = unsafe {
                mach_vm_read_overwrite(
                    self.task,
                    addr as mach_vm_address_t,
                    buf.len() as mach_vm_size_t,
                    buf.as_mut_ptr() as mach_vm_address_t,
                    &mut out_size,
                )
            };
            if kr != KERN_SUCCESS {
                return 0;
            }
            out_size as usize
        }

        fn write(&self, addr: usize, buf: &[u8]) -> usize {
            if buf.is_empty() {
                return 0;
            }
            let kr = unsafe {
                mach_vm_write(
                    self.task,
                    addr as mach_vm_address_t,
                    buf.as_ptr() as vm_offset_t,
                    buf.len() as natural_t,
                )
            };
            if kr != KERN_SUCCESS {
                return 0;
            }
            buf.len()
        }
    }

    pub fn open(pid: u32) -> Option<Box<dyn MemAccess + Send>> {
        let mut task: mach_port_t = 0;
        let kr = unsafe { task_for_pid(mach_task_self_, pid as c_int, &mut task) };
        if kr != KERN_SUCCESS || task == 0 {
            // Typically EPERM without root / the task_for_pid-allow entitlement.
            return None;
        }
        Some(Box::new(MacProc { task }) as Box<dyn MemAccess + Send>)
    }
}

// --------------------------- session registry -----------------------------

static REGISTRY: OnceLock<Mutex<HashMap<u64, Session>>> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn registry() -> &'static Mutex<HashMap<u64, Session>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

// ------------------------------ scanning ----------------------------------

/// Maximum bytes read per region chunk while scanning.
const CHUNK: usize = 1 << 20; // 1 MiB

/// Upper bound on total bytes captured by an unknown-value snapshot, so a huge
/// target can't exhaust memory. Writable regions beyond this are skipped.
const MAX_SNAPSHOT: usize = 512 << 20; // 512 MiB

fn f32_eq(a: f32, b: f32, round: u8) -> bool {
    match round {
        fround::ROUNDED => a.round() == b.round(),
        fround::TRUNCATED => a.trunc() == b.trunc(),
        _ => (a - b).abs() < f32::EPSILON,
    }
}

fn f64_eq(a: f64, b: f64, round: u8) -> bool {
    match round {
        fround::ROUNDED => a.round() == b.round(),
        fround::TRUNCATED => a.trunc() == b.trunc(),
        _ => (a - b).abs() < f64::EPSILON,
    }
}

fn cmp_value(buf: &[u8], vtype: VType, target: &[u8], round: u8) -> bool {
    let w = vtype.width();
    if buf.len() < w || target.len() < w {
        return false;
    }
    match vtype {
        VType::U8 | VType::I8 => buf[0] == target[0],
        VType::U16 | VType::I16 => buf[..2] == target[..2],
        VType::I32 | VType::U32 => buf[..4] == target[..4],
        VType::I64 | VType::U64 => buf[..8] == target[..8],
        VType::F32 => {
            let a = f32::from_le_bytes(buf[..4].try_into().unwrap());
            let b = f32::from_le_bytes(target[..4].try_into().unwrap());
            f32_eq(a, b, round)
        }
        VType::F64 => {
            let a = f64::from_le_bytes(buf[..8].try_into().unwrap());
            let b = f64::from_le_bytes(target[..8].try_into().unwrap());
            f64_eq(a, b, round)
        }
    }
}

/// Returns ordering of `a` vs `b` for the given numeric type: -1, 0, 1.
fn order(a: &[u8], b: &[u8], vtype: VType) -> i32 {
    macro_rules! ord {
        ($t:ty, $w:expr) => {{
            let x = <$t>::from_le_bytes(a[..$w].try_into().unwrap());
            let y = <$t>::from_le_bytes(b[..$w].try_into().unwrap());
            if x < y {
                -1
            } else if x > y {
                1
            } else {
                0
            }
        }};
    }
    if a.len() < vtype.width() || b.len() < vtype.width() {
        return 0;
    }
    match vtype {
        VType::U8 => ord!(u8, 1),
        VType::I8 => ord!(i8, 1),
        VType::U16 => ord!(u16, 2),
        VType::I16 => ord!(i16, 2),
        VType::I32 => ord!(i32, 4),
        VType::U32 => ord!(u32, 4),
        VType::I64 => ord!(i64, 8),
        VType::U64 => ord!(u64, 8),
        VType::F32 => {
            let x = f32::from_le_bytes(a[..4].try_into().unwrap());
            let y = f32::from_le_bytes(b[..4].try_into().unwrap());
            if x < y {
                -1
            } else if x > y {
                1
            } else {
                0
            }
        }
        VType::F64 => {
            let x = f64::from_le_bytes(a[..8].try_into().unwrap());
            let y = f64::from_le_bytes(b[..8].try_into().unwrap());
            if x < y {
                -1
            } else if x > y {
                1
            } else {
                0
            }
        }
    }
}

/// True if `cur == prev (+/- delta)` for the type. Integer math wraps; floats
/// use a 0.5 tolerance so single-step counters match despite rounding.
fn delta_eq(prev: &[u8], cur: &[u8], delta: &[u8], vtype: VType, inc: bool) -> bool {
    let w = vtype.width();
    if prev.len() < w || cur.len() < w || delta.len() < w {
        return false;
    }
    macro_rules! di {
        ($t:ty, $w:expr) => {{
            let p = <$t>::from_le_bytes(prev[..$w].try_into().unwrap());
            let c = <$t>::from_le_bytes(cur[..$w].try_into().unwrap());
            let d = <$t>::from_le_bytes(delta[..$w].try_into().unwrap());
            let want = if inc { p.wrapping_add(d) } else { p.wrapping_sub(d) };
            c == want
        }};
    }
    match vtype {
        VType::U8 => di!(u8, 1),
        VType::I8 => di!(i8, 1),
        VType::U16 => di!(u16, 2),
        VType::I16 => di!(i16, 2),
        VType::I32 => di!(i32, 4),
        VType::U32 => di!(u32, 4),
        VType::I64 => di!(i64, 8),
        VType::U64 => di!(u64, 8),
        VType::F32 => {
            let p = f32::from_le_bytes(prev[..4].try_into().unwrap());
            let c = f32::from_le_bytes(cur[..4].try_into().unwrap());
            let d = f32::from_le_bytes(delta[..4].try_into().unwrap());
            let want = if inc { p + d } else { p - d };
            (c - want).abs() < 0.5
        }
        VType::F64 => {
            let p = f64::from_le_bytes(prev[..8].try_into().unwrap());
            let c = f64::from_le_bytes(cur[..8].try_into().unwrap());
            let d = f64::from_le_bytes(delta[..8].try_into().unwrap());
            let want = if inc { p + d } else { p - d };
            (c - want).abs() < 0.5
        }
    }
}

/// Evaluates one scan op against current vs. previous bytes. `target` holds the
/// operand for value ops: EQ/GT/LT take one value, BETWEEN takes lo||hi, and
/// INC_BY/DEC_BY take a delta. `round` is the float comparison mode.
fn keep_op(op: u32, cur: &[u8], prev: &[u8], vtype: VType, target: &[u8], round: u8) -> bool {
    let w = vtype.width();
    match op {
        op::EQ => target.len() >= w && cmp_value(cur, vtype, target, round),
        op::CHANGED => cur != prev,
        op::UNCHANGED => cur == prev,
        op::INCREASED => order(cur, prev, vtype) > 0,
        op::DECREASED => order(cur, prev, vtype) < 0,
        op::GT => target.len() >= w && order(cur, target, vtype) > 0,
        op::LT => target.len() >= w && order(cur, target, vtype) < 0,
        op::BETWEEN => {
            target.len() >= 2 * w
                && order(cur, &target[..w], vtype) >= 0
                && order(cur, &target[w..2 * w], vtype) <= 0
        }
        op::INC_BY => target.len() >= w && delta_eq(prev, cur, target, vtype, true),
        op::DEC_BY => target.len() >= w && delta_eq(prev, cur, target, vtype, false),
        _ => false,
    }
}

/// Computes the `[start, end)` absolute address range of `reg` to scan after
/// applying the session's writable-only filter and address window, or `None`
/// when the region should be skipped entirely. `range_hi == 0` is unbounded.
fn region_window(sess: &Session, reg: &Region) -> Option<(usize, usize)> {
    if sess.writable_only && !reg.writable {
        return None;
    }
    let mut start = reg.base;
    let mut end = reg.base.saturating_add(reg.size);
    if sess.range_lo > start {
        start = sess.range_lo;
    }
    if sess.range_hi != 0 && sess.range_hi < end {
        end = sess.range_hi;
    }
    if start >= end {
        None
    } else {
        Some((start, end))
    }
}

fn scan_first(sess: &mut Session, vtype: VType, target: &[u8]) -> i64 {
    let width = vtype.width();
    if target.len() < width {
        return -1;
    }
    let round = sess.fround;
    let step = if sess.align == 0 { width } else { sess.align };
    sess.vtype = vtype;
    sess.snapshot = Vec::new();
    let mut hits: Vec<Hit> = Vec::new();
    let regions = sess.mem.regions();
    let mut buf = vec![0u8; CHUNK];
    for reg in regions {
        let (start, end) = match region_window(sess, &reg) {
            Some(w) => w,
            None => continue,
        };
        // Align the first candidate up to a `step` multiple relative to the
        // region base so addresses stay congruent across chunk boundaries
        // (CHUNK is a power of two divisible by every step).
        let mut addr = start;
        let rem = (addr - reg.base) % step;
        if rem != 0 {
            addr += step - rem;
        }
        while addr < end {
            let want = std::cmp::min(CHUNK, end - addr);
            let n = sess.mem.read(addr, &mut buf[..want]);
            if n == 0 {
                break;
            }
            let mut i = 0usize;
            while i + width <= n {
                if cmp_value(&buf[i..i + width], vtype, target, round) {
                    hits.push(Hit {
                        addr: addr + i,
                        last: buf[i..i + width].to_vec(),
                    });
                }
                i += step;
            }
            addr += want;
        }
    }
    sess.hits = hits;
    sess.hits.len() as i64
}

fn scan_next(sess: &mut Session, op: u32, target: &[u8]) -> i64 {
    // Unknown-initial-value flow: the first next-scan after a snapshot has no
    // prior hits, so narrow the captured baseline against live memory instead.
    if sess.hits.is_empty() && !sess.snapshot.is_empty() {
        return scan_next_snapshot(sess, op, target);
    }
    let vtype = sess.vtype;
    let round = sess.fround;
    let width = vtype.width();
    let mut buf = vec![0u8; width];
    let prev = std::mem::take(&mut sess.hits);
    let mut kept: Vec<Hit> = Vec::with_capacity(prev.len());
    for hit in prev {
        let n = sess.mem.read(hit.addr, &mut buf);
        if n < width {
            continue;
        }
        let keep = keep_op(op, &buf, &hit.last, vtype, target, round);
        if keep {
            kept.push(Hit {
                addr: hit.addr,
                last: buf.clone(),
            });
        }
    }
    sess.hits = kept;
    sess.hits.len() as i64
}

/// Captures the current bytes of every writable region as a baseline for an
/// unknown-initial-value scan (CE's "unknown initial value"). Clears existing
/// hits. Returns bytes captured (bounded by `MAX_SNAPSHOT`).
fn snapshot(sess: &mut Session, vtype: VType) -> i64 {
    sess.vtype = vtype;
    sess.hits.clear();
    let mut snap: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut captured = 0usize;
    let regions = sess.mem.regions();
    let mut buf = vec![0u8; CHUNK];
    // Snapshot is inherently writable-only; honour the address window too.
    let prev_wo = sess.writable_only;
    sess.writable_only = true;
    'outer: for reg in regions {
        let (start, end) = match region_window(sess, &reg) {
            Some(w) => w,
            None => continue,
        };
        let mut bytes: Vec<u8> = Vec::with_capacity(end - start);
        let mut addr = start;
        while addr < end {
            if captured >= MAX_SNAPSHOT {
                break 'outer;
            }
            let want = std::cmp::min(CHUNK, end - addr);
            let n = sess.mem.read(addr, &mut buf[..want]);
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
            captured += n;
            addr += want;
        }
        if !bytes.is_empty() {
            snap.push((start, bytes));
        }
    }
    sess.writable_only = prev_wo;
    sess.snapshot = snap;
    captured as i64
}

/// First narrowing of an unknown-value snapshot: compares each width-aligned
/// value in the snapshot against live memory and keeps those satisfying `op`
/// (delta ops compare against the snapshot; EQ/GT/LT against `target`). The
/// snapshot is consumed (freed) and the survivors become the hit set.
fn scan_next_snapshot(sess: &mut Session, op: u32, target: &[u8]) -> i64 {
    let vtype = sess.vtype;
    let round = sess.fround;
    let width = vtype.width();
    let snap = std::mem::take(&mut sess.snapshot);
    let mut hits: Vec<Hit> = Vec::new();
    let mut newbuf = vec![0u8; CHUNK];
    for (base, old_bytes) in &snap {
        let mut off = 0usize;
        while off < old_bytes.len() {
            let want = std::cmp::min(CHUNK, old_bytes.len() - off);
            let n = sess.mem.read(base + off, &mut newbuf[..want]);
            if n == 0 {
                break;
            }
            let mut i = 0usize;
            while i + width <= n {
                let old = &old_bytes[off + i..off + i + width];
                let cur = &newbuf[i..i + width];
                let keep = keep_op(op, cur, old, vtype, target, round);
                if keep {
                    hits.push(Hit {
                        addr: base + off + i,
                        last: cur.to_vec(),
                    });
                }
                i += width;
            }
            off += want;
        }
    }
    sess.hits = hits;
    sess.hits.len() as i64
}

/// Parses an AOB pattern like "48 8B ?? C0" into (bytes, mask).
fn parse_aob(pattern: &str) -> Option<(Vec<u8>, Vec<bool>)> {
    let mut bytes = Vec::new();
    let mut mask = Vec::new();
    for tok in pattern.split_whitespace() {
        if tok == "??" || tok == "?" {
            bytes.push(0);
            mask.push(false);
        } else {
            let b = u8::from_str_radix(tok, 16).ok()?;
            bytes.push(b);
            mask.push(true);
        }
    }
    if bytes.is_empty() {
        None
    } else {
        Some((bytes, mask))
    }
}

fn scan_aob(sess: &mut Session, pattern: &str) -> i64 {
    let (pat, mask) = match parse_aob(pattern) {
        Some(p) => p,
        None => return -1,
    };
    let plen = pat.len();
    let mut hits: Vec<Hit> = Vec::new();
    let regions = sess.mem.regions();
    let mut buf = vec![0u8; CHUNK + plen];
    for reg in regions {
        let (start, end) = match region_window(sess, &reg) {
            Some(w) => w,
            None => continue,
        };
        let mut addr = start;
        while addr < end {
            let want = std::cmp::min(CHUNK, end - addr);
            // Read an extra plen bytes to catch matches spanning chunk borders.
            let total = std::cmp::min(want + plen, end - addr);
            let n = sess.mem.read(addr, &mut buf[..total]);
            if n >= plen {
                let mut i = 0usize;
                while i + plen <= n {
                    let mut ok = true;
                    for j in 0..plen {
                        if mask[j] && buf[i + j] != pat[j] {
                            ok = false;
                            break;
                        }
                    }
                    if ok {
                        hits.push(Hit {
                            addr: addr + i,
                            last: buf[i..i + plen].to_vec(),
                        });
                    }
                    i += 1;
                }
            }
            if n == 0 {
                break;
            }
            addr += want;
        }
    }
    sess.hits = hits;
    sess.hits.len() as i64
}

/// Builds the byte needle for a string scan: raw UTF-8, or UTF-16LE when
/// `utf16` is set (matches wide strings used by many Windows apps).
fn string_needle(text: &str, utf16: bool) -> Vec<u8> {
    if utf16 {
        text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    } else {
        text.as_bytes().to_vec()
    }
}

/// Scans for an exact string occurrence (UTF-8 or UTF-16LE). Survivors become
/// the hit set; subsequent CHANGED/UNCHANGED next-scans track the same bytes.
fn scan_string(sess: &mut Session, text: &str, utf16: bool) -> i64 {
    let needle = string_needle(text, utf16);
    let nlen = needle.len();
    if nlen == 0 {
        return -1;
    }
    let mut hits: Vec<Hit> = Vec::new();
    let regions = sess.mem.regions();
    let mut buf = vec![0u8; CHUNK + nlen];
    for reg in regions {
        let (start, end) = match region_window(sess, &reg) {
            Some(w) => w,
            None => continue,
        };
        let mut addr = start;
        while addr < end {
            let want = std::cmp::min(CHUNK, end - addr);
            let total = std::cmp::min(want + nlen, end - addr);
            let n = sess.mem.read(addr, &mut buf[..total]);
            if n >= nlen {
                let mut i = 0usize;
                while i + nlen <= n {
                    if buf[i..i + nlen] == needle[..] {
                        hits.push(Hit {
                            addr: addr + i,
                            last: buf[i..i + nlen].to_vec(),
                        });
                    }
                    i += 1;
                }
            }
            if n == 0 {
                break;
            }
            addr += want;
        }
    }
    sess.hits = hits;
    sess.hits.len() as i64
}

// ----------------------------- pointer scan -------------------------------

/// Cap on collected pointer slots, so a huge target can't exhaust memory.
const PTR_MAX_SLOTS: usize = 6_000_000;
/// Cap on emitted pointer paths.
const PTR_MAX_RESULTS: usize = 512;

/// Reads a little-endian pointer-sized (8-byte) value at `addr`.
fn read_ptr(mem: &dyn MemAccess, addr: usize) -> Option<usize> {
    let mut b = [0u8; 8];
    if mem.read(addr, &mut b) < 8 {
        return None;
    }
    Some(u64::from_le_bytes(b) as usize)
}

/// Re-resolves a pointer path against live memory, returning the value address
/// it currently points at (used by rescan to confirm a path is still stable).
fn resolve_path(mem: &dyn MemAccess, path: &PtrPath) -> Option<usize> {
    let mut addr = path.base;
    for off in &path.offsets {
        let p = read_ptr(mem, addr)?;
        addr = p.checked_add(*off)?;
    }
    Some(addr)
}

/// CE-style pointer scan: finds stable static-base + multi-level-offset paths
/// that currently resolve to `target`. Walks every readable region collecting
/// 8-byte-aligned slots whose value lands in readable memory, then does a
/// bounded reverse DFS (depth `max_level`, slack `max_offset`) anchored on a
/// module-image ("static") slot. Survivors are stored in `sess.ptr_paths`.
fn pointer_scan(sess: &mut Session, target: usize, max_offset: usize, max_level: u32) -> i64 {
    sess.ptr_paths.clear();
    if target == 0 {
        return -1;
    }
    let max_level = max_level.clamp(1, 6) as usize;
    let regions = sess.mem.regions();

    // Sorted readable ranges for a fast "does this value look like a pointer?"
    // membership test.
    let mut ranges: Vec<(usize, usize)> =
        regions.iter().map(|r| (r.base, r.base + r.size)).collect();
    ranges.sort_unstable();
    let in_readable = |p: usize| -> bool {
        match ranges.binary_search_by(|&(s, _)| s.cmp(&p)) {
            Ok(_) => true,
            Err(0) => false,
            Err(i) => {
                let (s, e) = ranges[i - 1];
                p >= s && p < e
            }
        }
    };

    // Collect pointer slots: (pointee, slot_addr, slot_is_static).
    let mut slots: Vec<(usize, usize, bool)> = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    'collect: for reg in &regions {
        let mut addr = reg.base;
        let rem = addr % 8;
        if rem != 0 {
            addr += 8 - rem;
        }
        let end = reg.base + reg.size;
        while addr < end {
            let want = std::cmp::min(CHUNK, end - addr);
            let n = sess.mem.read(addr, &mut buf[..want]);
            if n < 8 {
                break;
            }
            let mut i = 0usize;
            while i + 8 <= n {
                let v = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap()) as usize;
                if v != 0 && in_readable(v) {
                    slots.push((v, addr + i, reg.is_static));
                    if slots.len() >= PTR_MAX_SLOTS {
                        break 'collect;
                    }
                }
                i += 8;
            }
            addr += want;
        }
    }
    slots.sort_unstable_by_key(|&(pointee, _, _)| pointee);
    let pointees: Vec<usize> = slots.iter().map(|&(p, _, _)| p).collect();

    // Reverse DFS. Each frame carries the offsets chosen so far in reverse
    // (outermost / last-applied offset first); they are reversed on emit.
    struct Frame {
        tgt: usize,
        depth: usize,
        offs_rev: Vec<usize>,
    }
    let mut results: Vec<PtrPath> = Vec::new();
    let mut stack = vec![Frame {
        tgt: target,
        depth: 0,
        offs_rev: Vec::new(),
    }];
    while let Some(fr) = stack.pop() {
        if results.len() >= PTR_MAX_RESULTS {
            break;
        }
        let lo = fr.tgt.saturating_sub(max_offset);
        let hi = fr.tgt;
        let mut idx = pointees.partition_point(|&p| p < lo);
        while idx < pointees.len() && pointees[idx] <= hi {
            if results.len() >= PTR_MAX_RESULTS {
                break;
            }
            let (pointee, slot, is_static) = slots[idx];
            idx += 1;
            let off = fr.tgt - pointee;
            let mut offs_rev = fr.offs_rev.clone();
            offs_rev.push(off);
            if is_static {
                let mut offsets = offs_rev.clone();
                offsets.reverse();
                results.push(PtrPath { base: slot, offsets });
            }
            // Recurse, but avoid trivially pointing a slot back at itself.
            if fr.depth + 1 < max_level && slot != fr.tgt {
                stack.push(Frame {
                    tgt: slot,
                    depth: fr.depth + 1,
                    offs_rev,
                });
            }
        }
    }
    sess.ptr_paths = results;
    sess.ptr_paths.len() as i64
}

// ------------------------------- C ABI ------------------------------------

/// Opens a process for scanning. Returns a session id (0 on failure).
#[no_mangle]
pub extern "C" fn msx_open(pid: u32) -> u64 {
    let mem = match plat::open(pid) {
        Some(m) => m,
        None => return 0,
    };
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let sess = Session {
        mem,
        vtype: VType::I32,
        hits: Vec::new(),
        fround: fround::EXACT,
        align: 0,
        range_lo: 0,
        range_hi: 0,
        writable_only: false,
        snapshot: Vec::new(),
        ptr_paths: Vec::new(),
    };
    registry().lock().unwrap().insert(id, sess);
    id
}

/// Closes a session and frees its resources.
#[no_mangle]
pub extern "C" fn msx_close(sid: u64) {
    registry().lock().unwrap().remove(&sid);
}

/// Reads `len` bytes at `addr` into `out`. Returns bytes read, -1 on bad session.
///
/// # Safety
/// `out` must point to at least `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn msx_read(sid: u64, addr: u64, out: *mut u8, len: u64) -> i64 {
    if out.is_null() || len == 0 {
        return 0;
    }
    let reg = registry();
    let map = reg.lock().unwrap();
    let sess = match map.get(&sid) {
        Some(s) => s,
        None => return -1,
    };
    let buf = std::slice::from_raw_parts_mut(out, len as usize);
    sess.mem.read(addr as usize, buf) as i64
}

/// Writes `len` bytes from `val` at `addr`. Returns bytes written, -1 on bad
/// session, 0 if the write was rejected (no write access / protected page).
///
/// # Safety
/// `val` must point to at least `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn msx_write(sid: u64, addr: u64, val: *const u8, len: u64) -> i64 {
    if val.is_null() || len == 0 {
        return 0;
    }
    let reg = registry();
    let map = reg.lock().unwrap();
    let sess = match map.get(&sid) {
        Some(s) => s,
        None => return -1,
    };
    let buf = std::slice::from_raw_parts(val, len as usize);
    sess.mem.write(addr as usize, buf) as i64
}

/// Captures a baseline snapshot of writable memory for an unknown-initial-value
/// scan. Afterwards call `msx_scan_next` with a delta op (CHANGED / UNCHANGED /
/// INCREASED / DECREASED) to narrow without ever knowing the exact value.
/// Returns bytes captured (>= 0), or -1 on bad value type.
#[no_mangle]
pub extern "C" fn msx_snapshot(sid: u64, vtype: u32) -> i64 {
    let vt = match VType::from_u32(vtype) {
        Some(v) => v,
        None => return -1,
    };
    let reg = registry();
    let mut map = reg.lock().unwrap();
    match map.get_mut(&sid) {
        Some(sess) => snapshot(sess, vt),
        None => -1,
    }
}

/// First scan for an exact value. Returns surviving hit count, -1 on error.
///
/// # Safety
/// `val` must point to at least `vlen` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn msx_scan_first(
    sid: u64,
    vtype: u32,
    val: *const u8,
    vlen: u64,
) -> i64 {
    let vt = match VType::from_u32(vtype) {
        Some(v) => v,
        None => return -1,
    };
    if val.is_null() {
        return -1;
    }
    let target = std::slice::from_raw_parts(val, vlen as usize);
    let reg = registry();
    let mut map = reg.lock().unwrap();
    match map.get_mut(&sid) {
        Some(sess) => scan_first(sess, vt, target),
        None => -1,
    }
}

/// Next scan, filtering existing hits by `op`. Returns surviving hit count.
///
/// # Safety
/// `val` must point to at least `vlen` readable bytes (may be null for ops
/// that don't use a provided value, e.g. CHANGED/UNCHANGED/INCREASED).
#[no_mangle]
pub unsafe extern "C" fn msx_scan_next(sid: u64, op: u32, val: *const u8, vlen: u64) -> i64 {
    let target: &[u8] = if val.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(val, vlen as usize)
    };
    let reg = registry();
    let mut map = reg.lock().unwrap();
    match map.get_mut(&sid) {
        Some(sess) => scan_next(sess, op, target),
        None => -1,
    }
}

/// Array-of-bytes scan with wildcards, e.g. "48 8B ?? C0". Returns hit count.
///
/// # Safety
/// `pattern` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn msx_scan_aob(sid: u64, pattern: *const std::os::raw::c_char) -> i64 {
    if pattern.is_null() {
        return -1;
    }
    let cstr = std::ffi::CStr::from_ptr(pattern);
    let s = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let reg = registry();
    let mut map = reg.lock().unwrap();
    match map.get_mut(&sid) {
        Some(sess) => scan_aob(sess, s),
        None => -1,
    }
}

/// Sets the float comparison mode for subsequent EQ scans: 0 exact, 1 rounded
/// (nearest integer), 2 truncated. Returns 0 on success, -1 on bad session.
#[no_mangle]
pub extern "C" fn msx_set_round(sid: u64, mode: u32) -> i64 {
    let reg = registry();
    let mut map = reg.lock().unwrap();
    match map.get_mut(&sid) {
        Some(sess) => {
            sess.fround = mode as u8;
            0
        }
        None => -1,
    }
}

/// Sets fast-scan options for subsequent scans (M3.4):
///   `align`         step between candidate addresses (0 => type width / CE-style
///                   aligned fast scan; 1 => unaligned find-all),
///   `range_lo`/`range_hi` inclusive-lower / exclusive-upper address window
///                   (`range_hi == 0` => unbounded above),
///   `writable_only` when != 0, scans skip non-writable regions.
/// Returns 0 on success, -1 on bad session.
#[no_mangle]
pub extern "C" fn msx_set_opts(
    sid: u64,
    align: u64,
    range_lo: u64,
    range_hi: u64,
    writable_only: u32,
) -> i64 {
    let reg = registry();
    let mut map = reg.lock().unwrap();
    match map.get_mut(&sid) {
        Some(sess) => {
            sess.align = align as usize;
            sess.range_lo = range_lo as usize;
            sess.range_hi = range_hi as usize;
            sess.writable_only = writable_only != 0;
            0
        }
        None => -1,
    }
}

/// Scans for an exact string occurrence. `utf16` != 0 matches UTF-16LE (wide)
/// strings; otherwise UTF-8. Returns hit count, or -1 on error.
///
/// # Safety
/// `text` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn msx_scan_string(
    sid: u64,
    text: *const std::os::raw::c_char,
    utf16: u32,
) -> i64 {
    if text.is_null() {
        return -1;
    }
    let cstr = std::ffi::CStr::from_ptr(text);
    let s = match cstr.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let reg = registry();
    let mut map = reg.lock().unwrap();
    match map.get_mut(&sid) {
        Some(sess) => scan_string(sess, s, utf16 != 0),
        None => -1,
    }
}

/// Number of current hits for a session.
#[no_mangle]
pub extern "C" fn msx_result_count(sid: u64) -> u64 {
    registry()
        .lock()
        .unwrap()
        .get(&sid)
        .map(|s| s.hits.len() as u64)
        .unwrap_or(0)
}

/// Copies up to `cap` hit addresses into `out_addrs`. Returns count copied.
///
/// # Safety
/// `out_addrs` must point to at least `cap` writable u64 slots.
#[no_mangle]
pub unsafe extern "C" fn msx_results(sid: u64, out_addrs: *mut u64, cap: u64) -> u64 {
    if out_addrs.is_null() || cap == 0 {
        return 0;
    }
    let reg = registry();
    let map = reg.lock().unwrap();
    let sess = match map.get(&sid) {
        Some(s) => s,
        None => return 0,
    };
    let n = std::cmp::min(cap as usize, sess.hits.len());
    let out = std::slice::from_raw_parts_mut(out_addrs, n);
    for (i, h) in sess.hits.iter().take(n).enumerate() {
        out[i] = h.addr as u64;
    }
    n as u64
}

/// Runs a pointer scan for `target`, finding stable static-base + multi-level
/// offset paths (`max_offset` = per-level slack, `max_level` = max indirection
/// depth). Stores the paths in the session. Returns the path count, or -1 on
/// bad session / zero target.
#[no_mangle]
pub extern "C" fn msx_pointer_scan(
    sid: u64,
    target: u64,
    max_offset: u64,
    max_level: u32,
) -> i64 {
    let reg = registry();
    let mut map = reg.lock().unwrap();
    match map.get_mut(&sid) {
        Some(sess) => pointer_scan(sess, target as usize, max_offset as usize, max_level),
        None => -1,
    }
}

/// Number of pointer paths from the most recent `msx_pointer_scan`.
#[no_mangle]
pub extern "C" fn msx_pointer_count(sid: u64) -> u64 {
    registry()
        .lock()
        .unwrap()
        .get(&sid)
        .map(|s| s.ptr_paths.len() as u64)
        .unwrap_or(0)
}

/// Copies pointer path `idx` into `out` as `[base, off0, off1, ...]`. Returns
/// the number of u64 slots written (1 + offset count), or 0 if `idx` is out of
/// range or `cap` is too small to hold the whole path.
///
/// # Safety
/// `out` must point to at least `cap` writable u64 slots.
#[no_mangle]
pub unsafe extern "C" fn msx_pointer_path(sid: u64, idx: u64, out: *mut u64, cap: u64) -> u64 {
    if out.is_null() || cap == 0 {
        return 0;
    }
    let reg = registry();
    let map = reg.lock().unwrap();
    let sess = match map.get(&sid) {
        Some(s) => s,
        None => return 0,
    };
    let path = match sess.ptr_paths.get(idx as usize) {
        Some(p) => p,
        None => return 0,
    };
    let need = 1 + path.offsets.len();
    if (cap as usize) < need {
        return 0;
    }
    let dst = std::slice::from_raw_parts_mut(out, need);
    dst[0] = path.base as u64;
    for (i, off) in path.offsets.iter().enumerate() {
        dst[1 + i] = *off as u64;
    }
    need as u64
}

/// Re-resolves pointer path `idx` against live memory (rescan), returning the
/// value address it currently points at, or -1 if the path is broken / `idx`
/// is out of range.
#[no_mangle]
pub extern "C" fn msx_pointer_resolve(sid: u64, idx: u64) -> i64 {
    let reg = registry();
    let map = reg.lock().unwrap();
    let sess = match map.get(&sid) {
        Some(s) => s,
        None => return -1,
    };
    let path = match sess.ptr_paths.get(idx as usize) {
        Some(p) => p,
        None => return -1,
    };
    match resolve_path(sess.mem.as_ref(), path) {
        Some(a) => a as i64,
        None => -1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic process memory for deterministic pointer-scan tests.
    struct FakeMem {
        regions: Vec<(Region, Vec<u8>)>,
    }

    impl MemAccess for FakeMem {
        fn regions(&self) -> Vec<Region> {
            self.regions.iter().map(|(r, _)| *r).collect()
        }
        fn read(&self, addr: usize, buf: &mut [u8]) -> usize {
            for (r, bytes) in &self.regions {
                if addr >= r.base && addr < r.base + r.size {
                    let off = addr - r.base;
                    let n = std::cmp::min(buf.len(), bytes.len() - off);
                    buf[..n].copy_from_slice(&bytes[off..off + n]);
                    return n;
                }
            }
            0
        }
        fn write(&self, _addr: usize, _buf: &[u8]) -> usize {
            0
        }
    }

    fn put_ptr(bytes: &mut [u8], off: usize, val: usize) {
        bytes[off..off + 8].copy_from_slice(&(val as u64).to_le_bytes());
    }

    fn blank_session(mem: Box<dyn MemAccess + Send>) -> Session {
        Session {
            mem,
            vtype: VType::I32,
            hits: Vec::new(),
            fround: fround::EXACT,
            align: 0,
            range_lo: 0,
            range_hi: 0,
            writable_only: false,
            snapshot: Vec::new(),
            ptr_paths: Vec::new(),
        }
    }

    #[test]
    fn pointer_scan_finds_static_chain() {
        // Static module region S and a dynamic (heap) region D. A static slot
        // S+0 -> D+0x100; the dynamic slot D+0x110 -> D+0x38. The target value
        // lives at D+0x40, reachable as: *(*(S) + 0x10) + 0x8.
        const S: usize = 0x10000;
        const D: usize = 0x20000;
        const SZ: usize = 0x1000;
        let target = D + 0x40;

        let mut sbytes = vec![0u8; SZ];
        put_ptr(&mut sbytes, 0x0, D + 0x100);
        let mut dbytes = vec![0u8; SZ];
        put_ptr(&mut dbytes, 0x110, D + 0x38); // *(D+0x110) = D+0x38; +0x8 => target

        let fake = FakeMem {
            regions: vec![
                (
                    Region {
                        base: S,
                        size: SZ,
                        writable: true,
                        is_static: true,
                    },
                    sbytes,
                ),
                (
                    Region {
                        base: D,
                        size: SZ,
                        writable: true,
                        is_static: false,
                    },
                    dbytes,
                ),
            ],
        };

        let mut sess = blank_session(Box::new(fake));
        let n = pointer_scan(&mut sess, target, 0x20, 3);
        assert_eq!(n, 1, "expected exactly one stable static chain");
        let p = &sess.ptr_paths[0];
        assert_eq!(p.base, S, "base must be the static slot");
        assert_eq!(p.offsets, vec![0x10, 0x8], "two-level offset chain");
        assert_eq!(
            resolve_path(sess.mem.as_ref(), p),
            Some(target),
            "path must resolve back to the target"
        );
    }

    #[test]
    fn pointer_scan_direct_static_pointer() {
        // A static slot pointing straight at the target (single-level path).
        const S: usize = 0x40000;
        const D: usize = 0x50000;
        const SZ: usize = 0x1000;
        let target = D + 0x80;
        let mut sbytes = vec![0u8; SZ];
        put_ptr(&mut sbytes, 0x20, target); // *(S+0x20) == target, offset 0
        let dbytes = vec![0u8; SZ];
        let fake = FakeMem {
            regions: vec![
                (
                    Region {
                        base: S,
                        size: SZ,
                        writable: true,
                        is_static: true,
                    },
                    sbytes,
                ),
                (
                    Region {
                        base: D,
                        size: SZ,
                        writable: true,
                        is_static: false,
                    },
                    dbytes,
                ),
            ],
        };
        let mut sess = blank_session(Box::new(fake));
        let n = pointer_scan(&mut sess, target, 0x10, 3);
        assert!(n >= 1, "should find the direct static pointer");
        let p = sess
            .ptr_paths
            .iter()
            .find(|p| p.base == S + 0x20 && p.offsets == vec![0])
            .expect("direct [S+0x20]+0 path");
        assert_eq!(resolve_path(sess.mem.as_ref(), p), Some(target));
    }

    #[test]
    fn aob_parse() {
        let (b, m) = parse_aob("48 8B ?? C0").unwrap();
        assert_eq!(b, vec![0x48, 0x8B, 0x00, 0xC0]);
        assert_eq!(m, vec![true, true, false, true]);
    }

    #[test]
    fn value_compare_i32() {
        let v = 1234i32.to_le_bytes();
        assert!(cmp_value(&v, VType::I32, &1234i32.to_le_bytes(), fround::EXACT));
        assert!(!cmp_value(&v, VType::I32, &1i32.to_le_bytes(), fround::EXACT));
    }

    #[test]
    fn value_compare_byte_and_i16() {
        assert!(cmp_value(&[7u8], VType::U8, &[7u8], fround::EXACT));
        assert!(!cmp_value(&[7u8], VType::U8, &[8u8], fround::EXACT));
        let a = (-3i16).to_le_bytes();
        assert!(cmp_value(&a, VType::I16, &(-3i16).to_le_bytes(), fround::EXACT));
        assert_eq!(order(&a, &(5i16).to_le_bytes(), VType::I16), -1);
    }

    #[test]
    fn float_round_modes() {
        let a = 100.4f32.to_le_bytes();
        let b = 100.0f32.to_le_bytes();
        assert!(!cmp_value(&a, VType::F32, &b, fround::EXACT));
        assert!(cmp_value(&a, VType::F32, &b, fround::ROUNDED));
        assert!(cmp_value(&a, VType::F32, &b, fround::TRUNCATED));
    }

    #[test]
    fn keep_op_between_and_delta() {
        let lo = 10i32.to_le_bytes();
        let hi = 20i32.to_le_bytes();
        let mut operand = lo.to_vec();
        operand.extend_from_slice(&hi);
        let cur = 15i32.to_le_bytes();
        assert!(keep_op(op::BETWEEN, &cur, &cur, VType::I32, &operand, fround::EXACT));
        let out = 25i32.to_le_bytes();
        assert!(!keep_op(op::BETWEEN, &out, &out, VType::I32, &operand, fround::EXACT));
        // inc-by 5: prev=10, cur=15
        let d = 5i32.to_le_bytes();
        assert!(keep_op(op::INC_BY, &cur, &lo, VType::I32, &d, fround::EXACT));
        assert!(!keep_op(op::INC_BY, &out, &lo, VType::I32, &d, fround::EXACT));
        // dec-by 5: prev=20, cur=15
        assert!(keep_op(op::DEC_BY, &cur, &hi, VType::I32, &d, fround::EXACT));
    }

    #[test]
    fn string_needle_utf8_and_utf16() {
        assert_eq!(string_needle("AB", false), vec![0x41, 0x42]);
        assert_eq!(string_needle("AB", true), vec![0x41, 0x00, 0x42, 0x00]);
    }

    #[test]
    fn order_works() {
        assert_eq!(order(&5i32.to_le_bytes(), &3i32.to_le_bytes(), VType::I32), 1);
        assert_eq!(order(&1i32.to_le_bytes(), &9i32.to_le_bytes(), VType::I32), -1);
    }

    // Live end-to-end scan of our own process for a unique heap value.
    #[cfg(windows)]
    #[test]
    fn live_first_scan_finds_known_value() {
        extern "system" {
            fn GetCurrentProcessId() -> u32;
        }
        // Unusual value to minimize accidental matches.
        let needle: Vec<i32> = vec![0x6A5B_4C3Du32 as i32];
        let pid = unsafe { GetCurrentProcessId() };
        let sid = msx_open(pid);
        assert_ne!(sid, 0, "msx_open(self) should succeed");
        let target = needle[0].to_le_bytes();
        let hits = unsafe { msx_scan_first(sid, MSX_VT_I32, target.as_ptr(), 4) };
        // Keep `needle` alive across the scan.
        assert_eq!(needle[0], 0x6A5B_4C3Du32 as i32);
        assert!(hits >= 1, "expected to find the known value, got {hits}");
        msx_close(sid);
    }

    // Surface the value-type/op constants used by the C ABI for the test above.
    const MSX_VT_I32: u32 = 0;

    // Write back into our own process and confirm the change is observable.
    #[cfg(windows)]
    #[test]
    fn live_write_roundtrip() {
        extern "system" {
            fn GetCurrentProcessId() -> u32;
        }
        let cell: Box<i32> = Box::new(0x1111_2222u32 as i32);
        let pid = unsafe { GetCurrentProcessId() };
        let sid = msx_open(pid);
        assert_ne!(sid, 0, "msx_open(self) should succeed");
        let addr = (&*cell as *const i32) as u64;
        let newv = (0x3333_4444u32 as i32).to_le_bytes();
        let n = unsafe { msx_write(sid, addr, newv.as_ptr(), 4) };
        assert_eq!(n, 4, "expected 4 bytes written, got {n}");
        assert_eq!(*cell, 0x3333_4444u32 as i32, "write should be observable");
        msx_close(sid);
    }

    const MSX_VT_U32: u32 = 4;
    const MSX_OP_CHANGED: u32 = 1;

    // Unknown-initial-value flow: snapshot writable memory, mutate a cell, then
    // narrow with CHANGED and confirm the mutated address survives.
    #[cfg(windows)]
    #[test]
    fn live_snapshot_changed_finds_mutation() {
        extern "system" {
            fn GetCurrentProcessId() -> u32;
        }
        // Heap cell (writable region) holding an initial value.
        let mut cell: Box<u32> = Box::new(0xA1B2_C3D4u32);
        let ptr: *mut u32 = &mut *cell;
        let addr = ptr as u64;
        let pid = unsafe { GetCurrentProcessId() };
        let sid = msx_open(pid);
        assert_ne!(sid, 0, "msx_open(self) should succeed");

        let captured = msx_snapshot(sid, MSX_VT_U32);
        assert!(captured > 0, "snapshot should capture writable bytes, got {captured}");

        // Mutate the cell so it differs from the snapshot.
        unsafe {
            ptr.write_volatile(0x0102_0304u32);
        }
        let hits = unsafe { msx_scan_next(sid, MSX_OP_CHANGED, std::ptr::null(), 0) };
        assert!(hits >= 1, "CHANGED should keep at least the mutated cell, got {hits}");

        // Confirm our cell's address is among the survivors.
        let cnt = msx_result_count(sid) as usize;
        let mut addrs = vec![0u64; cnt];
        let got = unsafe { msx_results(sid, addrs.as_mut_ptr(), cnt as u64) };
        assert!(
            addrs[..got as usize].contains(&addr),
            "mutated cell 0x{addr:x} should survive a CHANGED snapshot scan"
        );
        // Keep the cell alive across the scan and confirm the mutation stuck.
        assert_eq!(*cell, 0x0102_0304u32);
        msx_close(sid);
    }

    // Fast-scan options: a tight writable address window around a known cell
    // still finds it, and the windowed/aligned scan yields far fewer hits than
    // a full unaligned scan would.
    #[cfg(windows)]
    #[test]
    fn live_fast_scan_opts_narrow() {
        extern "system" {
            fn GetCurrentProcessId() -> u32;
        }
        let cell: Box<i32> = Box::new(0x5E7A_1C9Du32 as i32);
        let addr = (&*cell as *const i32) as u64;
        let pid = unsafe { GetCurrentProcessId() };
        let sid = msx_open(pid);
        assert_ne!(sid, 0, "msx_open(self) should succeed");

        // align=4 (i32), writable-only, window of +/- 0x400 bytes around the cell.
        let lo = addr - 0x400;
        let hi = addr + 0x400;
        let rc = msx_set_opts(sid, 4, lo, hi, 1);
        assert_eq!(rc, 0, "msx_set_opts should succeed");

        let target = (0x5E7A_1C9Du32 as i32).to_le_bytes();
        let hits = unsafe { msx_scan_first(sid, MSX_VT_I32, target.as_ptr(), 4) };
        assert_eq!(cell.as_ref(), &(0x5E7A_1C9Du32 as i32));
        assert!(hits >= 1, "windowed scan should still find the cell, got {hits}");
        assert!(
            hits < 256,
            "a 2 KiB aligned window should yield a tiny hit set, got {hits}"
        );

        let cnt = msx_result_count(sid) as usize;
        let mut addrs = vec![0u64; cnt];
        let got = unsafe { msx_results(sid, addrs.as_mut_ptr(), cnt as u64) };
        assert!(
            addrs[..got as usize].contains(&addr),
            "cell 0x{addr:x} should be inside the windowed result set"
        );
        // Every surviving address must lie inside the requested window and be
        // 4-byte aligned to the scan step.
        for a in &addrs[..got as usize] {
            assert!(*a >= lo && *a < hi, "hit 0x{a:x} escaped the window");
            assert_eq!(a % 4, 0, "hit 0x{a:x} not 4-byte aligned");
        }
        msx_close(sid);
    }
}
