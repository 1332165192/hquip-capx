//go:build windows

package main

import "fmt"

// defaultManagedBrowserProcessQuery returns the single-PID process metadata via
// WMI/CIM, matching the historical Windows behavior exactly.
func defaultManagedBrowserProcessQuery(pid int) ([]procInfo, error) {
	return getProcessInfosWithin(
		fmt.Sprintf(`Get-CimInstance Win32_Process -Filter "ProcessId=%d"`, pid),
		managedBrowserMetadataTimeout,
	)
}
