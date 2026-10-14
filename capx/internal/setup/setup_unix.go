//go:build !windows

package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

func isAdmin() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return os.Geteuid() == 0
}

func writeTempPEM(pemBytes []byte) (string, error) {
	path := filepath.Join(os.TempDir(), "capx-ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func caInstalled(thumbprint string) bool {
	if thumbprint == "" {
		return false
	}
	switch runtime.GOOS {
	case "darwin":
		out, _ := run("security", "find-certificate", "-c", "capx", "-a")
		return strings.Contains(strings.ToLower(out), "capx")
	default:
		home, _ := os.UserHomeDir()
		cands := []string{
			filepath.Join(home, ".pki", "nssdb"),
			filepath.Join(home, "snap", "chromium", "current", ".pki", "nssdb"),
		}
		for _, db := range cands {
			out, err := run("certutil", "-d", "sql:"+db, "-L")
			if err == nil && strings.Contains(out, "capx") {
				return true
			}
		}
		if _, err := os.Stat("/usr/local/share/ca-certificates/capx.crt"); err == nil {
			return true
		}
		if _, err := os.Stat("/etc/pki/ca-trust/source/anchors/capx.crt"); err == nil {
			return true
		}
	}
	return false
}

func installCA(pemBytes []byte) error {
	path, err := writeTempPEM(pemBytes)
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "darwin":
		out, err := run("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", userKeychain(), path)
		if err != nil {
			return fmt.Errorf("security add-trusted-cert: %v\n%s", err, strings.TrimSpace(out))
		}
		_ = installFirefoxPolicies(pemBytes, "")
		return nil
	default:
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		db := filepath.Join(home, ".pki", "nssdb")
		_ = os.MkdirAll(db, 0o700)
		if _, err := exec.LookPath("certutil"); err != nil {
			if isAdmin() {
				dst := "/usr/local/share/ca-certificates/capx.crt"
				if err := os.WriteFile(dst, pemBytes, 0o644); err != nil {
					return err
				}
				_, _ = run("update-ca-certificates")
				_ = installFirefoxPolicies(pemBytes, "")
				return nil
			}
			return fmt.Errorf("need nss certutil (libnss3-tools) or root to install CA")
		}
		out, err := run("certutil", "-d", "sql:"+db, "-A", "-t", "C,,", "-n", "capx", "-i", path)
		if err != nil {
			return fmt.Errorf("certutil NSS add: %v\n%s", err, strings.TrimSpace(out))
		}
		_ = installFirefoxPolicies(pemBytes, "")
		return nil
	}
}

func uninstallCA(pemBytes []byte) error {
	switch runtime.GOOS {
	case "darwin":
		out, err := run("security", "delete-certificate", "-c", "capx", userKeychain())
		if err != nil {
			return fmt.Errorf("security delete-certificate: %v\n%s", err, strings.TrimSpace(out))
		}
		return nil
	default:
		home, _ := os.UserHomeDir()
		db := filepath.Join(home, ".pki", "nssdb")
		out, err := run("certutil", "-d", "sql:"+db, "-D", "-n", "capx")
		if err != nil {
			return fmt.Errorf("certutil NSS delete: %v\n%s", err, strings.TrimSpace(out))
		}
		return nil
	}
}

func userKeychain() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Library", "Keychains", "login.keychain-db")
}

func currentProxy() proxySnapshot { snap, _ := readSystemProxy(); return snap }

func stripProxyURL(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "http://")
	v = strings.TrimPrefix(v, "https://")
	return strings.TrimRight(v, "/")
}

func proxyState(mitmAddr string) (set, owned bool, server, override string) {
	cur := currentProxy()
	server = cur.Server
	set = cur.Enable != 0 && strings.TrimSpace(cur.Server) != ""
	if mitmAddr != "" && set && strings.EqualFold(strings.TrimSpace(cur.Server), strings.TrimSpace(mitmAddr)) {
		owned = true
	}
	return set, owned, server, override
}

func readSystemProxy() (proxySnapshot, error) {
	get := func(command string, args ...string) (string, error) {
		out, err := run(command, args...)
		if err != nil {
			return "", fmt.Errorf("%s: %w: %s", command, err, strings.TrimSpace(out))
		}
		return out, nil
	}
	var snap proxySnapshot
	if runtime.GOOS == "darwin" {
		svc := macosNetworkService()
		web, err := get("networksetup", "-getwebproxy", svc)
		if err != nil {
			return snap, err
		}
		secure, err := get("networksetup", "-getsecurewebproxy", svc)
		if err != nil {
			return snap, err
		}
		pac, err := get("networksetup", "-getautoproxyurl", svc)
		if err != nil {
			return snap, err
		}
		snap.Enable, snap.Server = parseNetworkProxy(web)
		snap.SecureEnable, snap.SecureServer = parseNetworkProxy(secure)
		snap.PACEnable, snap.AutoConfigURL = parseNetworkPAC(pac)
		snap.Mode = "macos"
		return snap, nil
	}
	settings := []struct {
		schema, key string
		dest        *string
	}{
		{"org.gnome.system.proxy", "mode", &snap.Mode},
		{"org.gnome.system.proxy", "autoconfig-url", &snap.AutoConfigURL},
		{"org.gnome.system.proxy", "use-same-proxy", &snap.SameProxy},
	}
	for _, setting := range settings {
		out, err := get("gsettings", "get", setting.schema, setting.key)
		if err != nil {
			if setting.key == "use-same-proxy" {
				continue
			} // Absent in some GNOME schema versions.
			return snap, err
		}
		*setting.dest = gsettingsValue(out)
	}
	for _, secure := range []bool{false, true} {
		schema := "org.gnome.system.proxy.http"
		if secure {
			schema = "org.gnome.system.proxy.https"
		}
		host, err := get("gsettings", "get", schema, "host")
		if err != nil {
			return snap, err
		}
		port, err := get("gsettings", "get", schema, "port")
		if err != nil {
			return snap, err
		}
		host = gsettingsValue(host)
		port = gsettingsValue(port)
		addr := ""
		if host != "" && port != "0" {
			addr = host + ":" + port
		}
		if secure {
			snap.SecureServer = addr
		} else {
			snap.Server = addr
		}
	}
	if snap.Mode == "manual" {
		snap.Enable = 1
		snap.SecureEnable = 1
	}
	if snap.Mode == "auto" {
		snap.PACEnable = 1
	}
	return snap, nil
}

func targetSystemProxy(current proxySnapshot, addr string) proxySnapshot {
	current.Enable, current.Server = 1, addr
	current.SecureEnable, current.SecureServer = 1, addr
	current.PACEnable = 0
	if runtime.GOOS != "darwin" {
		current.Mode = "manual"
	}
	return current
}

func applySystemProxy(snap proxySnapshot) error {
	commands := [][]string{}
	if runtime.GOOS == "darwin" {
		svc := macosNetworkService()
		for _, item := range []struct {
			kind, addr string
			enabled    uint32
		}{{"webproxy", snap.Server, snap.Enable}, {"securewebproxy", snap.SecureServer, snap.SecureEnable}} {
			if item.addr != "" {
				host, port, err := splitHostPort(item.addr)
				if err != nil {
					return err
				}
				commands = append(commands, []string{"networksetup", "-set" + item.kind, svc, host, strconv.Itoa(port)})
			}
			state := "off"
			if item.enabled != 0 {
				state = "on"
			}
			commands = append(commands, []string{"networksetup", "-set" + item.kind + "state", svc, state})
		}
		if snap.AutoConfigURL != "" {
			commands = append(commands, []string{"networksetup", "-setautoproxyurl", svc, snap.AutoConfigURL})
		}
		state := "off"
		if snap.PACEnable != 0 {
			state = "on"
		}
		commands = append(commands, []string{"networksetup", "-setautoproxystate", svc, state})
	} else {
		for _, item := range []struct{ schema, addr string }{{"org.gnome.system.proxy.http", snap.Server}, {"org.gnome.system.proxy.https", snap.SecureServer}} {
			host, port := "", 0
			if item.addr != "" {
				var err error
				host, port, err = splitHostPort(item.addr)
				if err != nil {
					return err
				}
			}
			commands = append(commands, []string{"gsettings", "set", item.schema, "host", strconv.Quote(host)}, []string{"gsettings", "set", item.schema, "port", strconv.Itoa(port)})
		}
		commands = append(commands, []string{"gsettings", "set", "org.gnome.system.proxy", "autoconfig-url", strconv.Quote(snap.AutoConfigURL)})
		if snap.SameProxy != "" {
			commands = append(commands, []string{"gsettings", "set", "org.gnome.system.proxy", "use-same-proxy", snap.SameProxy})
		}
		mode := snap.Mode
		if mode == "" {
			mode = "none"
			if snap.Enable != 0 {
				mode = "manual"
			}
		}
		commands = append(commands, []string{"gsettings", "set", "org.gnome.system.proxy", "mode", mode})
	}
	for _, cmd := range commands {
		if out, err := run(cmd[0], cmd[1:]...); err != nil {
			return fmt.Errorf("%s: %w: %s", cmd[0], err, strings.TrimSpace(out))
		}
	}
	return nil
}

func disableSystemProxyNow() error {
	switch runtime.GOOS {
	case "darwin":
		svc := macosNetworkService()
		if _, err := run("networksetup", "-setwebproxystate", svc, "off"); err != nil {
			return err
		}
		_, err := run("networksetup", "-setsecurewebproxystate", svc, "off")
		return err
	default:
		_, err := run("gsettings", "set", "org.gnome.system.proxy", "mode", "none")
		return err
	}
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := splitLastColon(addr)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, p, nil
}

func macosNetworkService() string {
	if v := strings.TrimSpace(os.Getenv("CAPX_NETWORK_SERVICE")); v != "" {
		return v
	}
	out, _ := run("networksetup", "-listallnetworkservices")
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") {
			continue
		}
		low := strings.ToLower(line)
		if strings.Contains(low, "wi-fi") || strings.Contains(low, "wifi") || strings.Contains(low, "ethernet") {
			return line
		}
	}
	return "Wi-Fi"
}

func http3Disabled() bool {
	return chromeQuicPolicyPresent() || firefoxHTTP3Locked()
}

func disableHTTP3() error {
	_ = writeChromeQuicOff()
	_ = installFirefoxPolicies(nil, "")
	if runtime.GOOS == "darwin" {
		_, _ = run("defaults", "write", "com.google.Chrome", "QuicAllowed", "-bool", "false")
		_, _ = run("defaults", "write", "com.microsoft.Edge", "QuicAllowed", "-bool", "false")
	}
	if !http3Disabled() {
		return fmt.Errorf("could not write Chrome/Firefox HTTP/3 policy files")
	}
	return nil
}

func chromeProfileInfo() (bool, string) {
	return findChrome() != "", chromeProfileDir()
}

func findChrome() string {
	if p := strings.TrimSpace(os.Getenv("CAPX_BROWSER")); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	var cands []string
	if runtime.GOOS == "darwin" {
		cands = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	} else {
		cands = []string{
			"/usr/bin/google-chrome", "/usr/bin/google-chrome-stable",
			"/usr/bin/chromium", "/usr/bin/chromium-browser",
			"/usr/bin/microsoft-edge", "/snap/bin/chromium",
		}
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	for _, n := range []string{"google-chrome", "chromium", "chromium-browser", "microsoft-edge"} {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

func launchCaptureBrowser(proxyAddr, startURL string, caPEM []byte) (string, error) {
	exe := findChrome()
	if exe == "" {
		return "", fmt.Errorf("未找到 Chrome / Chromium / Edge")
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
	names := []string{"chrome", "chromium", "msedge", "Microsoft Edge", "Google Chrome"}
	n := 0
	for _, name := range names {
		if _, err := run("pkill", "-x", name); err == nil {
			n++
		}
	}
	return n, nil
}
