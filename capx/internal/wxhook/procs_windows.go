//go:build windows

package wxhook

import (
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// listWeChatAppEx enumerates WeChatAppEx.exe processes, resolves their image
// paths, flags the main WMPF host (the WeChatAppEx pid that is the most common
// parent of the others), and detects the WMPF version from the host path.
func listWeChatAppEx() ([]Process, error) {
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

	var procs []Process
	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, "WeChatAppEx.exe") {
			procs = append(procs, Process{PID: entry.ProcessID, PPID: entry.ParentProcessID, Name: name})
		}
		if err := windows.Process32Next(snap, &entry); err != nil {
			break // ERROR_NO_MORE_FILES ends the walk
		}
	}
	if len(procs) == 0 {
		_ = readProcessRoles(nil) // An empty PID set also invalidates old roles.
		return procs, nil
	}

	for i := range procs {
		procs[i].Path = imagePath(procs[i].PID)
	}
	roles := readProcessRoles(procs)
	for i := range procs {
		procs[i].Role = roles[procs[i].PID]
	}

	// The main WMPF host is the WeChatAppEx pid shared as parent by the most
	// render/gpu children.
	pidIndex := make(map[uint32]int, len(procs))
	for i := range procs {
		pidIndex[procs[i].PID] = i
	}
	childCount := map[uint32]int{}
	for _, p := range procs {
		childCount[p.PPID]++
	}
	var mainPID uint32
	best := -1
	for ppid, c := range childCount {
		if _, ok := pidIndex[ppid]; ok && c > best {
			best = c
			mainPID = ppid
		}
	}
	mainIdx := -1
	if idx, ok := pidIndex[mainPID]; ok && mainPID != 0 {
		mainIdx = idx
	}
	if mainIdx < 0 {
		mainIdx = 0
		for i := range procs {
			if procs[i].PID < procs[mainIdx].PID {
				mainIdx = i
			}
		}
	}
	procs[mainIdx].Main = true

	version := lastNumber(procs[mainIdx].Path)
	for i := range procs {
		if procs[i].Version == 0 {
			procs[i].Version = version
		}
		procs[i].Supported = versionSupported(procs[i].Version)
	}
	return procs, nil
}

// One read-only bulk query, rather than launching a command for every renderer.
// If discovery fails, callers see unknown roles and an explicit legacy hint.
func readProcessRoles(procs []Process) map[uint32]string {
	return sharedProcessRoles.get(procs, queryProcessRoles, time.Now)
}

const processRoleCacheTTL = 10 * time.Second

type processRoleLoad struct {
	done  chan struct{}
	roles map[uint32]string
}
type processRoleCache struct {
	mu      sync.Mutex
	key     string
	roles   map[uint32]string
	expires time.Time
	loading map[string]*processRoleLoad
}

var sharedProcessRoles processRoleCache

func processRoleSetKey(procs []Process) string {
	pids := make([]uint32, 0, len(procs))
	for _, p := range procs {
		pids = append(pids, p.PID)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	var key strings.Builder
	for i, pid := range pids {
		if i > 0 && pid == pids[i-1] {
			continue
		}
		key.WriteString(strconv.FormatUint(uint64(pid), 10))
		key.WriteByte(',')
	}
	return key.String()
}

func copyProcessRoles(roles map[uint32]string) map[uint32]string {
	if roles == nil {
		return nil
	}
	copy := make(map[uint32]string, len(roles))
	for pid, role := range roles {
		copy[pid] = role
	}
	return copy
}

// Share successful read-only role discovery for an unchanged PID set. Same-key
// concurrent callers join one query; a new PID set starts its own query at
// once, and an older in-flight query cannot overwrite that newer cache entry.
func (c *processRoleCache) get(procs []Process, load func() (map[uint32]string, error), now func() time.Time) map[uint32]string {
	key := processRoleSetKey(procs)
	c.mu.Lock()
	if c.key != key {
		c.key = key
		c.roles = nil
		c.expires = time.Time{}
	}
	if key == "" {
		c.mu.Unlock()
		return map[uint32]string{}
	}
	if c.roles != nil && now().Before(c.expires) {
		result := copyProcessRoles(c.roles)
		c.mu.Unlock()
		return result
	}
	if pending := c.loading[key]; pending != nil {
		c.mu.Unlock()
		<-pending.done
		return copyProcessRoles(pending.roles)
	}
	if c.loading == nil {
		c.loading = map[string]*processRoleLoad{}
	}
	pending := &processRoleLoad{done: make(chan struct{})}
	c.loading[key] = pending
	c.mu.Unlock()
	roles, err := load()
	c.mu.Lock()
	if err == nil {
		pending.roles = copyProcessRoles(roles)
		if c.key == key {
			c.roles = copyProcessRoles(roles)
			c.expires = now().Add(processRoleCacheTTL)
		}
	}
	// Errors are delivered to this waiting batch but never cached for ten seconds.
	delete(c.loading, key)
	close(pending.done)
	c.mu.Unlock()
	return copyProcessRoles(pending.roles)
}

func queryProcessRoles() (map[uint32]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", `[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); Get-CimInstance Win32_Process -Filter "Name='WeChatAppEx.exe'" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress`)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(out))
	if strings.HasPrefix(text, "{") {
		text = "[" + text + "]"
	}
	var infos []struct {
		ProcessID   uint32 `json:"ProcessId"`
		CommandLine string `json:"CommandLine"`
	}
	if err := json.Unmarshal([]byte(text), &infos); err != nil {
		return nil, err
	}
	roles := map[uint32]string{}
	for _, info := range infos {
		roles[info.ProcessID] = processRole(info.CommandLine)
	}
	return roles, nil
}

// imagePath returns the full executable path of a pid (best-effort).
func imagePath(pid uint32) string {
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
