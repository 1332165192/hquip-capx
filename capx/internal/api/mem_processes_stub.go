//go:build !linux && !windows && !darwin

package api

// listProcesses is unsupported on platforms other than Linux/Windows/macOS.
func listProcesses() ([]procInfo, error) {
	return nil, errProcEnumUnsupported
}
