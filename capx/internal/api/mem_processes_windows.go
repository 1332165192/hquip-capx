//go:build windows

package api

// Windows process enumeration via the Toolhelp snapshot API (pid + name), with
// best-effort image path (QueryFullProcessImageName) and owner (process token →
// account name). Best-effort fields stay empty when the process can't be opened
// (e.g. protected/system processes without sufficient privilege) rather than
// failing the whole listing.

import (
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

func listProcesses() ([]procInfo, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, err
	}

	var procs []procInfo
	for {
		pid := entry.ProcessID
		p := procInfo{
			PID:  pid,
			Name: windows.UTF16ToString(entry.ExeFile[:]),
		}
		p.Cmd = processImagePath(pid)
		p.User = processOwner(pid)
		procs = append(procs, p)

		if err := windows.Process32Next(snap, &entry); err != nil {
			break // ERROR_NO_MORE_FILES ends the walk
		}
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, nil
}

// processImagePath returns the full executable path of a pid (best-effort).
func processImagePath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// processOwner returns DOMAIN\user that owns the pid (best-effort).
func processOwner(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err != nil {
		return ""
	}
	defer token.Close()

	tu, err := token.GetTokenUser()
	if err != nil {
		return ""
	}
	account, domain, _, err := tu.User.Sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain != "" {
		return domain + "\\" + account
	}
	return account
}
