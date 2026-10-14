package setup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func firefoxProfilesINI() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch runtime.GOOS {
	case "windows":
		app := os.Getenv("APPDATA")
		if app == "" {
			app = filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(app, "Mozilla", "Firefox", "profiles.ini")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Firefox", "profiles.ini")
	default:
		return filepath.Join(home, ".mozilla", "firefox", "profiles.ini")
	}
}

func firefoxProfileDirs() []string {
	ini := firefoxProfilesINI()
	b, err := os.ReadFile(ini)
	if err != nil {
		return nil
	}
	root := filepath.Dir(ini)
	var out []string
	var path string
	isRel := true
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "path=") {
			path = strings.TrimSpace(line[5:])
		}
		if strings.HasPrefix(low, "isrelative=") {
			isRel = !strings.HasSuffix(low, "=0")
		}
		if line == "" || strings.HasPrefix(line, "[") {
			if path != "" {
				p := path
				if isRel {
					p = filepath.Join(root, path)
				}
				out = append(out, p)
			}
			path = ""
			isRel = true
		}
	}
	if path != "" {
		p := path
		if isRel {
			p = filepath.Join(root, path)
		}
		out = append(out, p)
	}
	return out
}

func firefoxPoliciesJSON(caPath, proxyAddr string) []byte {
	pref := map[string]any{
		"network.http.http3.enabled": map[string]any{"Value": false, "Status": "locked"},
	}
	policies := map[string]any{
		"DisableAppUpdate": true,
		"Preferences":      pref,
	}
	if caPath != "" {
		policies["Certificates"] = map[string]any{"Install": []string{caPath}}
	}
	if proxyAddr != "" {
		host, port, err := splitLastColon(proxyAddr)
		if err == nil {
			policies["Proxy"] = map[string]any{
				"Mode":                        "manual",
				"HTTPProxy":                   host + ":" + port,
				"UseHTTPProxyForAllProtocols": true,
				"Locked":                      true,
			}
		}
	}
	b, _ := json.MarshalIndent(map[string]any{"policies": policies}, "", "  ")
	return b
}

func installFirefoxPolicies(caPEM []byte, proxyAddr string) error {
	dirs := firefoxProfileDirs()
	if len(dirs) == 0 {
		return nil
	}
	caPath := ""
	if len(caPEM) > 0 {
		p, err := writeTempPEM(caPEM)
		if err != nil {
			return err
		}
		caPath = p
	}
	body := firefoxPoliciesJSON(caPath, proxyAddr)
	var last error
	for _, dir := range dirs {
		dst := filepath.Join(dir, "policies.json")
		if err := os.WriteFile(dst, body, 0o644); err != nil {
			last = err
		}
	}
	return last
}

func chromePolicyJSON() []byte {
	b, _ := json.MarshalIndent(map[string]any{"QuicAllowed": false}, "", "  ")
	return b
}

func chromeManagedPolicyDirs() []string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "darwin" {
		return []string{
			filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "policies", "managed"),
			filepath.Join(home, "Library", "Application Support", "Chromium", "policies", "managed"),
			filepath.Join(home, "Library", "Application Support", "Microsoft Edge", "policies", "managed"),
		}
	}
	return []string{
		filepath.Join(home, ".config", "google-chrome", "policies", "managed"),
		filepath.Join(home, ".config", "chromium", "policies", "managed"),
		filepath.Join(home, ".config", "microsoft-edge", "policies", "managed"),
	}
}

func writeChromeQuicOff() error {
	body := chromePolicyJSON()
	var last error
	n := 0
	for _, dir := range chromeManagedPolicyDirs() {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			last = err
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "capx.json"), body, 0o644); err != nil {
			last = err
			continue
		}
		n++
	}
	if n == 0 {
		return last
	}
	return nil
}

func chromeQuicPolicyPresent() bool {
	for _, dir := range chromeManagedPolicyDirs() {
		if _, err := os.Stat(filepath.Join(dir, "capx.json")); err == nil {
			return true
		}
	}
	return false
}

func firefoxHTTP3Locked() bool {
	for _, dir := range firefoxProfileDirs() {
		b, err := os.ReadFile(filepath.Join(dir, "policies.json"))
		if err != nil {
			continue
		}
		if strings.Contains(string(b), "network.http.http3.enabled") {
			return true
		}
	}
	return false
}
