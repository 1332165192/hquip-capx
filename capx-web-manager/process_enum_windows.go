//go:build windows

package main

import "errors"

// platformEnumerateAllProcesses is never invoked on Windows (getProcessInfosWithin
// takes the PowerShell/WMI path there). It exists so the shared dispatch in
// getProcessInfosWithin compiles on Windows.
func platformEnumerateAllProcesses() ([]procInfo, error) {
	return nil, errors.New("proc enumeration is only used on non-Windows platforms")
}
