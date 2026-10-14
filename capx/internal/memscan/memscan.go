// Package memscan is the Go front-end for local process memory scanning.
// Windows (ReadProcessMemory) and Linux (/proc/pid/mem) have native backends.
// Darwin uses Mach VM when built with cgo and without memscan_ffi. Other
// platforms use the Rust FFI backend (-tags memscan_ffi) or a stub.
package memscan

import "errors"

// ErrNotBuilt is returned by the stub backend.
var ErrNotBuilt = errors.New("memscan: engine not available in this build/platform")

// ValueType selects how scan values are interpreted. Mirrors MSX_VT_* in the
// C header.
type ValueType uint32

const (
	I32 ValueType = iota
	I64
	F32
	F64
	U32
	U64
	U8
	I8
	U16
	I16
)

// Extended value types implemented in the Go layer (internal/api) on top of
// the engine, mirroring Cheat Engine's extra scan types. They are not part of
// the FFI ABI: Bin matches bit patterns (binary scan) and All runs the value
// through every numeric type at once.
const (
	Bin ValueType = 10
	All ValueType = 11
)

// Op selects the comparison used by NextScan. Mirrors MSX_OP_* in the C header.
type Op uint32

const (
	OpEq Op = iota
	OpChanged
	OpUnchanged
	OpIncreased
	OpDecreased
	OpGt
	OpLt
	OpBetween // value = lo||hi (two values concatenated)
	OpIncBy   // value = delta; keep if cur == prev + delta
	OpDecBy   // value = delta; keep if cur == prev - delta
)

// RoundMode selects float comparison for EQ scans. Mirrors MSX_ROUND_* in C.
type RoundMode uint32

const (
	RoundExact RoundMode = iota
	RoundRounded
	RoundTruncated
)

// PointerPath is a CE-style stable pointer path: a static base slot plus a
// chain of dereference offsets. It resolves to a value address by starting at
// Base and, for each offset o, computing addr = readptr(addr) + o.
type PointerPath struct {
	Base    uint64   `json:"base"`
	Offsets []uint64 `json:"offsets"`
}

// Scanner attaches to a process and runs CE-style scans.
type Scanner interface {
	// Open attaches to a pid, returning a session handle.
	Open(pid uint32) (Session, error)
	// Available reports whether a real engine is linked in.
	Available() bool
}

// Session is an attached process scan session.
type Session interface {
	// Read reads len(buf) bytes at addr; returns bytes read.
	Read(addr uint64, buf []byte) (int, error)
	// Write writes buf at addr; returns bytes written. A return of 0 means the
	// write was rejected (no write access / protected page).
	Write(addr uint64, buf []byte) (int, error)
	// FirstScan scans all readable memory for an exact value.
	FirstScan(vt ValueType, value []byte) (int, error)
	// Snapshot captures writable memory as a baseline for an unknown-initial-
	// value scan; the next NextScan (with a delta op) narrows against it.
	// Returns the number of bytes captured.
	Snapshot(vt ValueType) (int, error)
	// NextScan filters current hits by op (value may be nil for delta ops).
	NextScan(op Op, value []byte) (int, error)
	// AOBScan scans for a wildcard byte pattern like "48 8B ?? C0".
	AOBScan(pattern string) (int, error)
	// StringScan scans for an exact string (UTF-16LE when utf16 is set).
	StringScan(text string, utf16 bool) (int, error)
	// SetRound sets the float comparison mode for subsequent EQ scans.
	SetRound(mode RoundMode) error
	// SetOpts sets fast-scan options for subsequent scans: align is the step
	// between candidate addresses (0 => type width / aligned fast scan, 1 =>
	// unaligned find-all); [rangeLo, rangeHi) bounds the scanned address window
	// (rangeHi == 0 => unbounded above); writableOnly skips non-writable regions.
	SetOpts(align, rangeLo, rangeHi uint64, writableOnly bool) error
	// Results returns up to max current hit addresses.
	Results(max int) ([]uint64, error)
	// PointerScan finds stable static-base + multi-level-offset paths that
	// currently resolve to target. maxOffset is the per-level offset slack;
	// maxLevel is the maximum indirection depth. Returns the path count.
	PointerScan(target, maxOffset uint64, maxLevel uint32) (int, error)
	// PointerPaths returns up to max pointer paths from the last PointerScan.
	PointerPaths(max int) ([]PointerPath, error)
	// PointerResolve re-resolves pointer path idx against live memory,
	// returning the value address it currently points at; ok is false when the
	// path is broken or idx is out of range.
	PointerResolve(idx int) (addr uint64, ok bool, err error)
	// Close releases the session.
	Close() error
	PtrWidth() int
}

const (
	DefaultMaxHits     = 2_000_000
	DefaultMaxSnapHits = 400_000
)

// Width returns the byte width of a value type.
func (vt ValueType) Width() int {
	switch vt {
	case U8, I8:
		return 1
	case U16, I16:
		return 2
	case I32, U32, F32:
		return 4
	case I64, U64, F64:
		return 8
	}
	return 0
}

// New returns the scanner backend compiled into this binary.
func New() Scanner { return newScanner() }
