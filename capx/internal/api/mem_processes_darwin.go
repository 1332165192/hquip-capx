//go:build darwin

package api

// macOS process enumeration via sysctl(KERN_PROC_ALL): pid, name (p_comm) and
// owner (effective uid → account name). The full argv would require
// KERN_PROCARGS2 (and elevated privilege for other users' processes); the short
// process name is what CE's picker needs, so cmd is left to the image name.

import (
	"os/user"
	"sort"
	"strconv"

	"golang.org/x/sys/unix"
)

func listProcesses() ([]procInfo, error) {
	procsRaw, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, err
	}
	procs := make([]procInfo, 0, len(procsRaw))
	for i := range procsRaw {
		kp := &procsRaw[i]
		pid := uint32(kp.Proc.P_pid)
		if pid == 0 {
			continue
		}
		name := unix.ByteSliceToString(kp.Proc.P_comm[:])
		p := procInfo{PID: pid, Name: name, Cmd: name}
		p.User = uidName(uint32(kp.Eproc.Ucred.Uid))
		procs = append(procs, p)
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, nil
}

func uidName(uid uint32) string {
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		return u.Username
	}
	return strconv.FormatUint(uint64(uid), 10)
}
