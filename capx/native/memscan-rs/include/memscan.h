/* capx memory-scan engine — C ABI.
 *
 * Implemented by the Rust crate in this directory (`memscan`). Consumed by the
 * Go core at capx/internal/memscan via cgo. Hand-maintained to mirror
 * the `#[no_mangle] extern "C"` functions in src/lib.rs (kept in sync manually
 * so builds don't require cbindgen).
 */
#ifndef CAPX_MEMSCAN_H
#define CAPX_MEMSCAN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Value types for msx_scan_first (vtype argument). */
#define MSX_VT_I32 0
#define MSX_VT_I64 1
#define MSX_VT_F32 2
#define MSX_VT_F64 3
#define MSX_VT_U32 4
#define MSX_VT_U64 5
#define MSX_VT_U8  6
#define MSX_VT_I8  7
#define MSX_VT_U16 8
#define MSX_VT_I16 9

/* Comparison ops for msx_scan_next (op argument). */
#define MSX_OP_EQ        0
#define MSX_OP_CHANGED   1
#define MSX_OP_UNCHANGED 2
#define MSX_OP_INCREASED 3
#define MSX_OP_DECREASED 4
#define MSX_OP_GT        5
#define MSX_OP_LT        6
#define MSX_OP_BETWEEN   7  /* value = lo||hi (two values concatenated) */
#define MSX_OP_INC_BY    8  /* value = delta; keep if cur == prev + delta */
#define MSX_OP_DEC_BY    9  /* value = delta; keep if cur == prev - delta */

/* Float comparison modes for msx_set_round. */
#define MSX_ROUND_EXACT     0
#define MSX_ROUND_ROUNDED   1
#define MSX_ROUND_TRUNCATED 2

/* Open a process for scanning. Returns a session id, or 0 on failure. */
uint64_t msx_open(uint32_t pid);

/* Close a session and free its resources. */
void msx_close(uint64_t sid);

/* Read len bytes at addr into out. Returns bytes read, or -1 on bad session. */
int64_t msx_read(uint64_t sid, uint64_t addr, uint8_t *out, uint64_t len);

/* Write len bytes from val at addr. Returns bytes written, -1 on bad session,
 * or 0 if the write was rejected (no write access / protected page). */
int64_t msx_write(uint64_t sid, uint64_t addr, const uint8_t *val, uint64_t len);

/* Capture a baseline snapshot of writable memory for an unknown-initial-value
 * scan. Afterwards call msx_scan_next with a delta op (CHANGED / UNCHANGED /
 * INCREASED / DECREASED) to narrow without knowing the exact value. Returns
 * bytes captured (>= 0), or -1 on bad value type. */
int64_t msx_snapshot(uint64_t sid, uint32_t vtype);

/* First scan for an exact value. Returns surviving hit count, or -1 on error. */
int64_t msx_scan_first(uint64_t sid, uint32_t vtype, const uint8_t *val, uint64_t vlen);

/* Next scan, filtering existing hits by op. Returns surviving hit count. */
int64_t msx_scan_next(uint64_t sid, uint32_t op, const uint8_t *val, uint64_t vlen);

/* Array-of-bytes scan with wildcards, e.g. "48 8B ?? C0". Returns hit count. */
int64_t msx_scan_aob(uint64_t sid, const char *pattern);

/* Set the float comparison mode for subsequent EQ scans (see MSX_ROUND_*).
 * Returns 0 on success, -1 on bad session. */
int64_t msx_set_round(uint64_t sid, uint32_t mode);

/* Set fast-scan options for subsequent scans:
 *   align         step between candidate addresses (0 => type width / CE-style
 *                 aligned fast scan; 1 => unaligned find-all),
 *   range_lo/range_hi  inclusive-lower / exclusive-upper address window
 *                 (range_hi == 0 => unbounded above),
 *   writable_only when != 0, scans skip non-writable regions.
 * Returns 0 on success, -1 on bad session. */
int64_t msx_set_opts(uint64_t sid, uint64_t align, uint64_t range_lo,
                     uint64_t range_hi, uint32_t writable_only);

/* Scan for an exact string. utf16 != 0 matches UTF-16LE (wide) strings,
 * otherwise UTF-8. Returns hit count, or -1 on error. */
int64_t msx_scan_string(uint64_t sid, const char *text, uint32_t utf16);

/* Number of current hits for a session. */
uint64_t msx_result_count(uint64_t sid);

/* Copy up to cap hit addresses into out_addrs. Returns count copied. */
uint64_t msx_results(uint64_t sid, uint64_t *out_addrs, uint64_t cap);

/* Pointer scan (CE-style stable address): find static-base + multi-level-offset
 * paths that currently resolve to target. max_offset is the per-level offset
 * slack; max_level is the max indirection depth. Stores the paths in the
 * session. Returns the path count, or -1 on bad session / zero target. */
int64_t msx_pointer_scan(uint64_t sid, uint64_t target, uint64_t max_offset,
                         uint32_t max_level);

/* Number of pointer paths from the most recent msx_pointer_scan. */
uint64_t msx_pointer_count(uint64_t sid);

/* Copy pointer path idx into out as [base, off0, off1, ...]. Returns the number
 * of uint64 slots written (1 + offset count), or 0 if idx is out of range or
 * cap is too small to hold the whole path. */
uint64_t msx_pointer_path(uint64_t sid, uint64_t idx, uint64_t *out, uint64_t cap);

/* Re-resolve pointer path idx against live memory (rescan), returning the value
 * address it currently points at, or -1 if the path is broken / out of range. */
int64_t msx_pointer_resolve(uint64_t sid, uint64_t idx);

#ifdef __cplusplus
}
#endif

#endif /* CAPX_MEMSCAN_H */
