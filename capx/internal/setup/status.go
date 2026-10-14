package setup

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SystemProxyConfig is read-only routing information. PAC URLs are not
// returned or executed; capture clients must explicitly configure that case.
type SystemProxyConfig struct {
	Enabled bool
	Server  string
	PAC     bool
}

func ReadSystemProxyConfig() (SystemProxyConfig, error) {
	s, err := readSystemProxy()
	if err != nil {
		return SystemProxyConfig{}, err
	}
	return SystemProxyConfig{Enabled: s.Enable != 0, Server: s.Server,
		PAC: s.AutoConfigURL != "" || s.PACEnable != 0 || s.Mode == "auto"}, nil
}

func Snapshot(caPEM []byte, mitmAddr string) Status {
	st := Status{OS: runtime.GOOS, Admin: isAdmin()}
	if tp, subj, err := certThumbprint(caPEM); err == nil {
		st.CAThumbprint = tp
		st.CASubject = subj
		st.CAInstalled = caInstalled(tp)
	}
	st.ProxySet, st.ProxyOwned, st.ProxyServer, st.ProxyOverride = proxyState(mitmAddr)
	st.HTTP3Disabled = http3Disabled()
	st.ChromeAvailable, st.ChromeProfile = chromeProfileInfo()
	st.ProxyBackup = hasProxyBackup()
	switch {
	case !st.CAInstalled:
		if st.Admin {
			st.Hint = "尚未安装 capx 根证书，HTTPS 解密会失败"
		} else {
			st.Hint = "尚未安装 capx 根证书。将写入当前用户信任库；系统级安装需要管理员"
		}
	case st.ProxyBackup && !st.ProxyOwned:
		st.Hint = "检测到上次系统代理备份。退出 capx 或点「关闭系统代理」可还原"
	case !st.ProxySet:
		st.Hint = "系统代理未指向 capx。可一键准备（会改整机代理），或用「打开抓包浏览器」只劫持该窗口"
	case !st.HTTP3Disabled:
		st.Hint = "建议关闭 Chrome/Edge HTTP/3，否则部分站点走 QUIC，MITM 历史是空的"
	}
	return st
}

func InstallCA(caPEM []byte) error { return installCA(caPEM) }

func UninstallCA(caPEM []byte) error { return uninstallCA(caPEM) }

func EnableSystemProxy(addr string) error { return enableSystemProxy(addr) }

func DisableSystemProxy() error { return restoreSystemProxy() }

func DisableHTTP3() error { return disableHTTP3() }

func LaunchCaptureBrowser(proxyAddr, startURL string, caPEM []byte) (string, error) {
	return launchCaptureBrowser(strings.TrimSpace(proxyAddr), startURL, caPEM)
}

func RestartUserBrowsers() (int, error) { return restartUserBrowsers() }

func HasProxyBackup() bool { return hasProxyBackup() }

func chromeProfileDir() string {
	if v := strings.TrimSpace(os.Getenv("CAPX_CHROME_PROFILE")); v != "" {
		return v
	}
	if runtime.GOOS == "windows" {
		base := strings.TrimSpace(os.Getenv("LOCALAPPDATA"))
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return ""
			}
			base = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(base, "capx", "chrome-capture-profile")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "capx-chrome-capture-profile")
	}
	return filepath.Join(home, ".capx", "chrome-capture-profile")
}

func dataDir() string {
	// System proxy ownership is per OS user, never per CA/state directory.
	// CAPX_DATA_DIR may differ between instances and must not split this lock.
	if runtime.GOOS == "windows" {
		if v := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); v != "" {
			return filepath.Join(v, "capx")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), "capx")
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Local", "capx")
	}
	return filepath.Join(home, ".capx")
}
