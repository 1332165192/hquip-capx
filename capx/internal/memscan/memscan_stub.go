//go:build !memscan_ffi && !windows && !linux && (!darwin || !cgo)

package memscan

type stubScanner struct{}

func newScanner() Scanner { return stubScanner{} }

func (stubScanner) Available() bool { return false }

func (stubScanner) Open(pid uint32) (Session, error) { return nil, ErrNotBuilt }
