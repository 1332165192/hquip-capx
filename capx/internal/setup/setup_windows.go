//go:build windows

package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
	http3ChromePolicyKey          = `SOFTWARE\Policies\Google\Chrome`
	http3EdgePolicyKey            = `SOFTWARE\Policies\Microsoft\Edge`
)

func isAdmin() bool {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0, &sid,
	); err != nil {
		return false
	}
	defer windows.FreeSid(sid)
	ok, err := windows.Token(0).IsMember(sid)
	return err == nil && ok
}

func storeHasCert(args []string, thumbprint string) bool {
	out, _ := run("certutil", args...)
	low := strings.ToLower(out)
	return strings.Contains(low, strings.ToLower(thumbprint)) && !strings.Contains(low, "error")
}

func caInstalled(thumbprint string) bool {
	if thumbprint == "" {
		return false
	}
	return storeHasCert([]string{"-user", "-store", "Root", thumbprint}, thumbprint) ||
		storeHasCert([]string{"-store", "Root", thumbprint}, thumbprint)
}

func installCA(pemBytes []byte) error {
	path, err := writeTempPEM(pemBytes)
	if err != nil {
		return err
	}
	defer os.Remove(path)
	out, err := run("certutil", "-user", "-addstore", "-f", "Root", path)
	userErr, userOut := err, out
	var machineErr error
	var machineOut string
	if isAdmin() {
		machineOut, machineErr = run("certutil", "-addstore", "-f", "Root", path)
	}
	if userErr == nil || machineErr == nil {
		_ = installFirefoxPolicies(pemBytes, "")
		return nil
	}
	if machineErr != nil {
		return fmt.Errorf("certutil -addstore Root: %v\n%s", machineErr, strings.TrimSpace(machineOut))
	}
	return fmt.Errorf("certutil -user -addstore Root: %v\n%s", userErr, strings.TrimSpace(userOut))
}

func uninstallCA(pemBytes []byte) error {
	tp, _, err := certThumbprint(pemBytes)
	if err != nil {
		return err
	}
	var last error
	if out, err := run("certutil", "-user", "-delstore", "Root", tp); err != nil {
		last = fmt.Errorf("certutil -user -delstore Root: %v\n%s", err, strings.TrimSpace(out))
	}
	if isAdmin() {
		if out, err := run("certutil", "-delstore", "Root", tp); err != nil && last != nil {
			return fmt.Errorf("certutil -delstore Root: %v\n%s", err, strings.TrimSpace(out))
		}
	}
	return last
}

func writeTempPEM(pemBytes []byte) (string, error) {
	path := filepath.Join(os.TempDir(), "capx-ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func currentProxy() proxySnapshot {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return proxySnapshot{}
	}
	defer k.Close()
	enable, _, _ := k.GetIntegerValue("ProxyEnable")
	server, _, _ := k.GetStringValue("ProxyServer")
	override, _, _ := k.GetStringValue("ProxyOverride")
	auto, _, _ := k.GetStringValue("AutoConfigURL")
	return proxySnapshot{Enable: uint32(enable), Server: server, Override: override, AutoConfigURL: auto}
}

func proxyState(mitmAddr string) (set, owned bool, server, override string) {
	cur := currentProxy()
	server, override = cur.Server, cur.Override
	set = cur.Enable != 0 && strings.TrimSpace(cur.Server) != ""
	if mitmAddr != "" && set && strings.EqualFold(strings.TrimSpace(cur.Server), strings.TrimSpace(mitmAddr)) {
		owned = true
	}
	if _, ok := readBackup(); ok && owned {
		owned = true
	}
	return set, owned, server, override
}

func readSystemProxy() (proxySnapshot, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
	if err != nil {
		return proxySnapshot{}, err
	}
	defer k.Close()
	enable, _, _ := k.GetIntegerValue("ProxyEnable")
	server, _, _ := k.GetStringValue("ProxyServer")
	override, _, _ := k.GetStringValue("ProxyOverride")
	auto, _, _ := k.GetStringValue("AutoConfigURL")
	return proxySnapshot{Enable: uint32(enable), Server: server, Override: override, AutoConfigURL: auto}, nil
}

func targetSystemProxy(current proxySnapshot, addr string) proxySnapshot {
	current.Enable, current.Server, current.AutoConfigURL = 1, addr, ""
	if !strings.Contains(strings.ToLower(current.Override), "localhost") {
		if current.Override != "" {
			current.Override += ";"
		}
		current.Override += "localhost;127.0.0.1;<local>"
	}
	return current
}

func applySystemProxy(snap proxySnapshot) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	if err := k.SetStringValue("ProxyServer", snap.Server); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyOverride", snap.Override); err != nil {
		return err
	}
	if snap.AutoConfigURL != "" {
		if err := k.SetStringValue("AutoConfigURL", snap.AutoConfigURL); err != nil {
			return err
		}
	} else if err := k.DeleteValue("AutoConfigURL"); err != nil && err != registry.ErrNotExist {
		return err
	}
	if err := k.SetDWordValue("ProxyEnable", snap.Enable); err != nil {
		return err
	}
	notifyProxyChange()
	return nil
}

func notifyProxyChange() {
	mod := windows.NewLazySystemDLL("wininet.dll")
	proc := mod.NewProc("InternetSetOptionW")
	if proc.Find() != nil {
		return
	}
	_, _, _ = proc.Call(0, uintptr(internetOptionSettingsChanged), 0, 0)
	_, _, _ = proc.Call(0, uintptr(internetOptionRefresh), 0, 0)
}

func quicOff(hive registry.Key, path string) bool {
	k, err := registry.OpenKey(hive, path, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("QuicAllowed")
	return err == nil && v == 0
}

func http3Disabled() bool {
	if quicOff(registry.LOCAL_MACHINE, http3ChromePolicyKey) || quicOff(registry.CURRENT_USER, http3ChromePolicyKey) {
		return true
	}
	return quicOff(registry.LOCAL_MACHINE, http3EdgePolicyKey) || quicOff(registry.CURRENT_USER, http3EdgePolicyKey)
}

func disableHTTP3() error {
	var last error
	for _, path := range []string{http3ChromePolicyKey, http3EdgePolicyKey} {
		k, _, err := registry.CreateKey(registry.CURRENT_USER, path, registry.SET_VALUE)
		if err != nil {
			last = err
			continue
		}
		if err := k.SetDWordValue("QuicAllowed", 0); err != nil {
			last = err
		}
		k.Close()
	}
	_ = installFirefoxPolicies(nil, "")
	return last
}

func chromeProfileInfo() (bool, string) {
	exe := findChrome()
	dir := chromeProfileDir()
	return exe != "", dir
}

func findChrome() string {
	candidates := []string{}
	if local := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); local != "" {
		candidates = append(candidates,
			filepath.Join(local, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(local, "Microsoft", "Edge", "Application", "msedge.exe"),
		)
	}
	if pf := strings.TrimSpace(os.Getenv("PROGRAMFILES")); pf != "" {
		candidates = append(candidates,
			filepath.Join(pf, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
		)
	}
	if pf86 := strings.TrimSpace(os.Getenv("PROGRAMFILES(X86)")); pf86 != "" {
		candidates = append(candidates,
			filepath.Join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
		)
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func launchCaptureBrowser(proxyAddr, startURL string, caPEM []byte) (string, error) {
	exe := findChrome()
	if exe == "" {
		return "", fmt.Errorf("未找到 Chrome / Edge")
	}
	dir := chromeProfileDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	args := []string{
		"--user-data-dir=" + dir,
		"--proxy-server=http://" + proxyAddr,
		"--proxy-bypass-list=localhost;127.0.0.1;::1",
		"--disable-quic",
		"--disable-features=UseDnsHttpsSvcb,UseDnsHttpsSvcbAlpn",
		"--no-first-run",
		"--no-default-browser-check",
		"--new-window",
	}
	if pin := certSPKIHash(caPEM); pin != "" {
		args = append(args, "--ignore-certificate-errors-spki-list="+pin)
	}
	args = append(args, sanitizeStartURL(startURL))
	cmd := exec.Command(exe, args...)
	if err := cmd.Start(); err != nil {
		return "", err
	}
	go func() { _ = cmd.Wait() }()
	return dir, nil
}

func restartUserBrowsers() (int, error) {
	type restartJob struct {
		exe     string
		profile string
	}
	out, err := run("powershell", "-NoProfile", "-NonInteractive", "-Command",
		`Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(chrome|msedge)\.exe$' } | ForEach-Object { '{0}|{1}|{2}' -f $_.ProcessId, $_.ExecutablePath, $_.CommandLine }`)
	if err != nil {
		return 0, fmt.Errorf("enum browsers: %v\n%s", err, strings.TrimSpace(out))
	}
	seen := map[string]restartJob{}
	pids := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}
		pid, exe, cmd := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), parts[2]
		if exe == "" || pid == "" || shouldSkipBrowserRestart(cmd) || shouldSkipBrowserRestart(exe) {
			continue
		}
		profile := extractUserDataDir(cmd)
		key := strings.ToLower(exe + "|" + profile)
		if _, ok := seen[key]; !ok {
			seen[key] = restartJob{exe: exe, profile: profile}
		}
		pids = append(pids, pid)
	}
	if len(pids) == 0 {
		return 0, nil
	}
	kill := []string{"/F"}
	for _, pid := range pids {
		kill = append(kill, "/PID", pid)
	}
	_, _ = run("taskkill", kill...)
	n := 0
	for _, job := range seen {
		args := []string{"--restore-last-session", "--no-first-run", "--no-default-browser-check"}
		if job.profile != "" {
			args = append([]string{"--user-data-dir=" + job.profile}, args...)
		}
		cmd := exec.Command(job.exe, args...)
		if err := cmd.Start(); err != nil {
			continue
		}
		go func() { _ = cmd.Wait() }()
		n++
	}
	return n, nil
}
