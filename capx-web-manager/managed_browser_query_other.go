//go:build !windows

package main

// defaultManagedBrowserProcessQuery returns the single-PID process metadata by
// reading /proc/<pid>. This gives the same full command-line identity check the
// Windows path gets from WMI, so managed browser flag verification
// (--capx-instance-id=, --capx-generation=, --remote-debugging-port=) runs on
// Linux instead of degrading to image-name-only.
func defaultManagedBrowserProcessQuery(pid int) ([]procInfo, error) {
	info, err := procInfoFromProc(pid)
	if err != nil {
		return nil, err
	}
	return []procInfo{info}, nil
}
