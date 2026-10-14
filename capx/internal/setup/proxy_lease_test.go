package setup

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hquip/capx/internal/runtimecfg"
)

type proxyMock struct {
	mu      sync.Mutex
	current proxySnapshot
	writes  int
	fail    bool
}

func (m *proxyMock) read() (proxySnapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current, nil
}
func (m *proxyMock) apply(s proxySnapshot) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("registry adapter failure")
	}
	m.current = s
	m.writes++
	return nil
}
func testProxyController(t *testing.T) (proxyLeaseController, *proxyMock) {
	t.Helper()
	m := &proxyMock{current: proxySnapshot{Enable: 1, Server: "original:8080", Override: "", AutoConfigURL: "http://pac.test/proxy.pac"}}
	return proxyLeaseController{filepath.Join(t.TempDir(), "sysproxy-backup.json"), "owner-a", 101, m.read, m.apply, func(pid int) bool { return pid == 101 || pid == 102 }}, m
}

func TestProxyLeaseOnlyOwningInstanceRestores(t *testing.T) {
	a, m := testProxyController(t)
	original, _ := m.read()
	if err := a.enable("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
	b := a
	b.owner = "owner-b"
	b.pid = 102
	if err := b.restore(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.read(); got.Server != "127.0.0.1:18080" {
		t.Fatal("unrelated instance changed proxy")
	}
	if err := b.enable("127.0.0.1:18081"); err == nil {
		t.Fatal("second live instance took proxy ownership")
	}
	if err := a.restore(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.read(); got != original {
		t.Fatalf("original settings not fully restored: %+v", got)
	}
	if _, err := os.Stat(a.path); !os.IsNotExist(err) {
		t.Fatalf("lease remained after restoration: %v", err)
	}
}

func TestProxyLeaseRepeatedEnablePreservesOriginal(t *testing.T) {
	a, m := testProxyController(t)
	original, _ := m.read()
	for _, addr := range []string{"127.0.0.1:18080", "127.0.0.1:18080", "127.0.0.1:18081"} {
		if err := a.enable(addr); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.restore(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.read(); got != original {
		t.Fatalf("original snapshot overwritten: %+v", got)
	}
}

func TestProxyLeaseCrashTakeoverKeepsOriginal(t *testing.T) {
	a, m := testProxyController(t)
	original, _ := m.read()
	if err := a.enable("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
	b := a
	b.owner = "owner-b"
	b.pid = 102
	b.alive = func(int) bool { return false }
	if err := b.enable("127.0.0.1:18081"); err != nil {
		t.Fatal(err)
	}
	if err := a.restore(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.read(); got.Server != "127.0.0.1:18081" {
		t.Fatal("old owner restored new owner's settings")
	}
	if err := b.restore(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.read(); got != original {
		t.Fatalf("crash takeover lost original snapshot: %+v", got)
	}
}

func TestProxyLeaseDoesNotClobberExternalChange(t *testing.T) {
	a, m := testProxyController(t)
	if err := a.enable("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
	external := proxySnapshot{Enable: 1, Server: "vpn.example:1234", AutoConfigURL: "http://vpn/pac"}
	m.apply(external)
	if err := a.restore(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.read(); got != external {
		t.Fatal("user/VPN settings were overwritten")
	}
}

func TestProxyLeaseFailedRestoreRetainsRetryableBackup(t *testing.T) {
	a, m := testProxyController(t)
	if err := a.enable("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
	m.fail = true
	if err := a.restore(false); err == nil {
		t.Fatal("adapter failure ignored")
	}
	if _, err := os.Stat(a.path); err != nil {
		t.Fatal("failed restoration destroyed backup")
	}
	m.fail = false
	if err := a.restore(false); err != nil {
		t.Fatal(err)
	}
}

func TestProxyLeaseAbsentBackupDoesNotReadOrWriteSystem(t *testing.T) {
	a, m := testProxyController(t)
	if err := a.restore(false); err != nil {
		t.Fatal(err)
	}
	if m.writes != 0 {
		t.Fatal("closing a capture-only instance touched system proxy")
	}
}

func TestProxyLeaseSerializesConcurrentOwners(t *testing.T) {
	a, _ := testProxyController(t)
	b := a
	b.owner = "b"
	b.pid = 102
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, c := range []proxyLeaseController{a, b} {
		go func(c proxyLeaseController) { <-start; results <- c.enable("127.0.0.1:18080") }(c)
	}
	close(start)
	success := 0
	for i := 0; i < 2; i++ {
		if <-results == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatalf("got %d owners", success)
	}
}

func TestProxyLeaseLockAcrossProcesses(t *testing.T) {
	if path := os.Getenv("CAPX_TEST_PROXY_LOCK"); path != "" {
		release, err := runtimecfg.AcquireFileLock(path)
		if err == nil {
			release()
			os.Exit(3)
		}
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "proxy.lock")
	release, err := runtimecfg.AcquireFileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProxyLeaseLockAcrossProcesses$")
	cmd.Env = append(os.Environ(), "CAPX_TEST_PROXY_LOCK="+path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child acquired parent's OS lock: %v %s", err, out)
	}
}

func TestProxyLeaseExplicitCrashRecoveryButNotUnrelatedShutdown(t *testing.T) {
	a, m := testProxyController(t)
	original, _ := m.read()
	if err := a.enable("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
	b := a
	b.owner = "recovery"
	b.pid = 103
	b.alive = func(int) bool { return false }
	if err := b.restore(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.read(); got == original {
		t.Fatal("unrelated exit recovered another generation")
	}
	if err := b.restore(true); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.read(); got != original {
		t.Fatal("explicit crash recovery did not restore")
	}
}

func TestProxyLeaseWaitsForShortCriticalSection(t *testing.T) {
	a, _ := testProxyController(t)
	release, err := runtimecfg.AcquireFileLock(a.path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- a.enable("127.0.0.1:18080") }()
	select {
	case err := <-done:
		release()
		t.Fatalf("did not wait: %v", err)
	case <-time.After(75 * time.Millisecond):
	}
	release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestProxyLeaseClaimsLegacyBackupOnlyAtExplicitExistingAddress(t *testing.T) {
	a, m := testProxyController(t)
	original, _ := m.read()
	b, _ := json.Marshal(original)
	if err := os.WriteFile(a.path, b, 0600); err != nil {
		t.Fatal(err)
	}
	m.apply(targetSystemProxy(original, "127.0.0.1:18080"))
	if err := a.restore(false); err != nil {
		t.Fatal("unrelated exit must ignore unowned legacy snapshot", err)
	}
	if err := a.enable("127.0.0.1:18081"); err == nil {
		t.Fatal("legacy snapshot was silently overwritten")
	}
	if err := a.enable("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
	if err := a.restore(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.read(); got != original {
		t.Fatal("migration lost original settings")
	}
}

func TestSystemProxyLockIsIndependentOfInstanceCADirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	t.Setenv("CAPX_DATA_DIR", filepath.Join(root, "ca-a"))
	a := backupPath()
	t.Setenv("CAPX_DATA_DIR", filepath.Join(root, "ca-b"))
	b := backupPath()
	if a != b {
		t.Fatal("per-instance CA directory split the user-wide system proxy lock")
	}
}

func TestNativeProxyParsersPreserveSeparateSecureAndPACSettings(t *testing.T) {
	enabled, addr := parseNetworkProxy("Enabled: Yes\nServer: proxy.example\nPort: 8080\nAuthenticated Proxy Enabled: 0")
	if enabled != 1 || addr != "proxy.example:8080" {
		t.Fatalf("web parse: %d %q", enabled, addr)
	}
	secure, secureAddr := parseNetworkProxy("Enabled: No\nServer: secure.example\nPort: 8443\n")
	if secure != 0 || secureAddr != "secure.example:8443" {
		t.Fatalf("secure parse: %d %q", secure, secureAddr)
	}
	pac, pacURL := parseNetworkPAC("URL: https://pac.example:8443/proxy.pac\nEnabled: Yes\n")
	if pac != 1 || pacURL != "https://pac.example:8443/proxy.pac" {
		t.Fatalf("PAC parse: %d %q", pac, pacURL)
	}
	if gsettingsValue("'auto'\n") != "auto" {
		t.Fatal("gsettings mode lost")
	}
}

func TestProxyLeaseSeparatesEmbeddedComponentsInSameProcess(t *testing.T) {
	a, m := testProxyController(t)
	original, _ := m.read()
	scopeA, scopeB := &struct{ ID int }{1}, &struct{ ID int }{2}
	a.owner = scopedProxyController(scopeA).owner
	a.pid = os.Getpid()
	a.alive = func(pid int) bool { return pid == os.Getpid() }
	b := a
	b.owner = scopedProxyController(scopeB).owner
	if a.owner == b.owner {
		t.Fatal("embedded components have the same owner")
	}
	if err := a.enable("127.0.0.1:18080"); err != nil {
		t.Fatal(err)
	}
	for _, recoverStale := range []bool{false, true} {
		if err := b.restore(recoverStale); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := m.read(); got.Server != "127.0.0.1:18080" {
		t.Fatal("sibling component restored active owner's proxy")
	}
	if err := b.enable("127.0.0.1:18081"); err == nil {
		t.Fatal("sibling component took live lease")
	}
	if err := a.enable("127.0.0.1:18082"); err != nil {
		t.Fatal(err)
	}
	if err := a.restore(false); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.read(); got != original {
		t.Fatal("owning component failed to restore after its proxy address changed")
	}
}
