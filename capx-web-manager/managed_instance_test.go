package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestManagedSleeper(t *testing.T) {
	if os.Getenv("CAPX_MANAGER_HELPER_PROCESS") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}

func TestStartRequestDecodesManagedFields(t *testing.T) {
	var request startRequest
	err := json.Unmarshal([]byte(`{
		"captured_path":"captured.exe",
		"instance_id":"app_codex",
		"project_root":"C:\\project",
		"cdp_port":43103,
		"auto_ports":true
	}`), &request)
	if err != nil {
		t.Fatal(err)
	}
	if request.CapturedPath != "captured.exe" || request.InstanceID != "app_codex" || request.CDPPort != 43103 || !request.AutoPorts {
		t.Fatalf("unexpected decoded request: %+v", request)
	}
}

func TestStartManagedInstancePublishesResolverCompatibleManifest(t *testing.T) {
	root, project := managedProjectFixture(t, "managed_test")
	var helperPID int
	restoreManagedHooks(t)
	managedCapxLauncher = func(string, string, string, string, portSet, bool) (*exec.Cmd, error) {
		cmd := managedSleeperCommand(t)
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		helperPID = cmd.Process.Pid
		return cmd, nil
	}
	managedRuntimeWaiter = func(_, _ string, stateDir string, _ portSet) (string, error) {
		if err := os.WriteFile(filepath.Join(stateDir, "token"), []byte("managed-test-token"), 0o600); err != nil {
			return "", err
		}
		return "managed-test-token", nil
	}
	managedBrowserLauncher = func(string, string, string, portSet) (int, error) { return os.Getpid(), nil }

	result, err := startManagedInstance(startRequest{
		config:     config{CapturedPath: "ignored", Count: 1, AutoPorts: true},
		InstanceID: "managed_test",
		ProjectDir: project,
	})
	if err != nil {
		t.Fatalf("startManagedInstance: %v", err)
	}
	t.Cleanup(func() {
		if helperPID > 0 {
			if process, findErr := os.FindProcess(helperPID); findErr == nil {
				_ = process.Kill()
			}
		}
	})

	manifest, err := loadInstanceManifest("managed_test")
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if !manifest.IdentityRequired || manifest.PID != result.PID || manifest.BrowserPID != os.Getpid() {
		t.Fatalf("unexpected lifecycle fields: %+v", manifest)
	}
	if manifest.CDPPort != result.CDPPort || manifest.APIBase == "" || manifest.Proxy == "" {
		t.Fatalf("unexpected endpoints: %+v", manifest)
	}
	if raw, err := os.ReadFile(result.ManifestPath); err != nil {
		t.Fatal(err)
	} else if strings.Contains(string(raw), "managed-test-token") {
		t.Fatal("manifest embedded token contents")
	}
	if !strings.HasPrefix(result.ManifestPath, root) {
		t.Fatalf("manifest escaped test registry: %s", result.ManifestPath)
	}
}

func TestStartManagedInstanceRollsBackProcessWhenPublishFails(t *testing.T) {
	_, project := managedProjectFixture(t, "rollback_test")
	restoreManagedHooks(t)
	var helper *exec.Cmd
	managedCapxLauncher = func(string, string, string, string, portSet, bool) (*exec.Cmd, error) {
		helper = managedSleeperCommand(t)
		if err := helper.Start(); err != nil {
			return nil, err
		}
		return helper, nil
	}
	managedRuntimeWaiter = func(_, _ string, stateDir string, _ portSet) (string, error) {
		_ = os.WriteFile(filepath.Join(stateDir, "token"), []byte("rollback-token"), 0o600)
		return "rollback-token", nil
	}
	managedBrowserLauncher = func(string, string, string, portSet) (int, error) { return 999999, nil }
	managedManifestWriter = func(instanceManifest) error { return errors.New("publish failed") }

	_, err := startManagedInstance(startRequest{
		config:     config{CapturedPath: "ignored", Count: 1, AutoPorts: true},
		InstanceID: "rollback_test",
		ProjectDir: project,
	})
	if err == nil || !strings.Contains(err.Error(), "publish failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if helper == nil {
		t.Fatal("helper process was not started")
	}
	done := make(chan struct{})
	go func() {
		_ = helper.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = helper.Process.Kill()
		t.Fatal("managed Capx process was not rolled back")
	}
}

func TestInstanceLifecycleLockRejectsLiveManagerAndRecoversAfterRelease(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("manager lifecycle ownership uses Windows process discovery")
	}
	root := t.TempDir()
	t.Setenv("CAPX_INSTANCE_DIR", filepath.Join(root, "instances"))
	release, err := acquireInstanceLifecycleLock("lock_test")
	if err != nil {
		t.Fatal(err)
	}
	if second, secondErr := acquireInstanceLifecycleLock("lock_test"); secondErr == nil {
		second()
		t.Fatal("a second live manager acquired the same instance lock")
	}
	release()
	third, err := acquireInstanceLifecycleLock("lock_test")
	if err != nil {
		t.Fatalf("lock was not reusable after release: %v", err)
	}
	third()
}

func TestManagedStopRejectsLegacyManifestBeforeAnyLifecycleAction(t *testing.T) {
	err := stopManagedInstance(instanceManifest{
		InstanceID: "legacy_instance",
		Generation: "legacy-generation",
		PID:        12345,
	})
	if err == nil || !strings.Contains(err.Error(), "legacy manifest") {
		t.Fatalf("legacy managed stop was not rejected: %v", err)
	}
}

type fakeManagedBrowserHandle struct {
	path       string
	terminated bool
	closed     bool
}

func (handle *fakeManagedBrowserHandle) imagePath() (string, error) {
	return handle.path, nil
}

func (handle *fakeManagedBrowserHandle) terminate() (bool, error) {
	handle.terminated = true
	return true, nil
}

func (handle *fakeManagedBrowserHandle) close() {
	handle.closed = true
}

func TestTerminateManagedBrowserRejectsListenerPIDMismatch(t *testing.T) {
	manifest := managedBrowserTerminationFixture()
	handle := installManagedBrowserTerminationFakes(t, manifest, `C:\Chrome\chrome.exe`, manifest.BrowserPID+1)

	if _, err := terminateManagedBrowser(manifest); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unexpected listener mismatch result: %v", err)
	}
	if handle.terminated || !handle.closed {
		t.Fatalf("unexpected handle state: %+v", handle)
	}
}

func TestTerminateManagedBrowserRejectsNonBrowserExecutable(t *testing.T) {
	manifest := managedBrowserTerminationFixture()
	handle := installManagedBrowserTerminationFakes(t, manifest, `C:\Windows\System32\notepad.exe`, manifest.BrowserPID)

	if _, err := terminateManagedBrowser(manifest); err == nil || !strings.Contains(err.Error(), "not Chrome or Edge") {
		t.Fatalf("unexpected executable mismatch result: %v", err)
	}
	if handle.terminated || !handle.closed {
		t.Fatalf("unexpected handle state: %+v", handle)
	}
}

func TestTerminateManagedBrowserSucceedsWithoutWMI(t *testing.T) {
	manifest := managedBrowserTerminationFixture()
	handle := installManagedBrowserTerminationFakes(t, manifest, `C:\Chrome\chrome.exe`, manifest.BrowserPID)

	terminated, err := terminateManagedBrowser(manifest)
	if err != nil || !terminated {
		t.Fatalf("managed browser was not terminated: terminated=%v err=%v", terminated, err)
	}
	if !handle.terminated || !handle.closed {
		t.Fatalf("unexpected handle state: %+v", handle)
	}
}

func TestManagedBrowserProcessHandleTerminatesHeldProcess(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("managed browser process handles are Windows-only")
	}
	helper := managedSleeperCommand(t)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = helper.Process.Kill() })

	handle, err := openManagedBrowserProcessHandle(helper.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.close()
	if _, err := handle.imagePath(); err != nil {
		t.Fatal(err)
	}
	terminated, err := handle.terminate()
	if err != nil || !terminated {
		t.Fatalf("held process was not terminated: terminated=%v err=%v", terminated, err)
	}
	done := make(chan error, 1)
	go func() { done <- helper.Wait() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("terminated helper did not exit")
	}
}

func managedBrowserTerminationFixture() instanceManifest {
	return instanceManifest{
		InstanceID: "stop_browser_test",
		Generation: "stop-generation",
		StateDir:   `C:\state-stop-browser`,
		Proxy:      "http://127.0.0.1:45102",
		CDPPort:    45103,
		BrowserPID: 45104,
	}
}

func installManagedBrowserTerminationFakes(
	t *testing.T,
	manifest instanceManifest,
	executablePath string,
	listenerPID int,
) *fakeManagedBrowserHandle {
	t.Helper()
	oldOpen := openManagedBrowserHandle
	oldListener := managedBrowserListenerPID
	oldProcessQuery := managedBrowserProcessQuery
	handle := &fakeManagedBrowserHandle{path: executablePath}
	openManagedBrowserHandle = func(pid int) (managedBrowserProcessHandle, error) {
		if pid != manifest.BrowserPID {
			t.Fatalf("opened PID %d, want %d", pid, manifest.BrowserPID)
		}
		return handle, nil
	}
	managedBrowserListenerPID = func(port int) (int, error) {
		if port != manifest.CDPPort {
			t.Fatalf("queried CDP port %d, want %d", port, manifest.CDPPort)
		}
		return listenerPID, nil
	}
	managedBrowserProcessQuery = func(int) ([]procInfo, error) {
		return nil, errors.New("CIM unavailable: 0x800705af")
	}
	t.Cleanup(func() {
		openManagedBrowserHandle = oldOpen
		managedBrowserListenerPID = oldListener
		managedBrowserProcessQuery = oldProcessQuery
	})
	return handle
}

func TestManifestAssociationRequiresManagedIdentityAndProcessFlags(t *testing.T) {
	_, project := managedProjectFixture(t, "association_test")
	stateDir, err := managedStateDir("association_test")
	if err != nil {
		t.Fatal(err)
	}
	manifest := instanceManifest{
		SchemaVersion: instanceManifestSchemaVersion,
		InstanceID:    "association_test",
		ProjectRoot:   project,
		APIBase:       "http://127.0.0.1:45101",
		Proxy:         "http://127.0.0.1:45102",
		StateDir:      stateDir,
		TokenFile:     filepath.Join(stateDir, "token"),
		CDPPort:       45103,
		PID:           12345,
		Generation:    "association-generation",
		UpdatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeInstanceManifest(manifest); err != nil {
		t.Fatal(err)
	}
	info := procInfo{
		ProcessID: 12345,
		CommandLine: "capx-captured.next.exe --instance-id association_test " +
			"--generation association-generation --state-dir \"" + stateDir + "\"",
	}
	if _, ok := manifestForProcess(info); !ok {
		t.Fatal("verified managed process was not associated with its manifest")
	}

	path, err := instanceManifestPath("association_test")
	if err != nil {
		t.Fatal(err)
	}
	manifest.IdentityRequired = false
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := manifestForProcess(info); ok {
		t.Fatal("legacy manifest promoted a process to managed status")
	}
}

func TestTerminateProcessVerifiedPreservesMismatchAndTerminatesMatch(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("verified process termination uses a Windows process handle")
	}
	helper := managedSleeperCommand(t)
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = helper.Process.Kill() })
	if _, err := getProcessInfos(fmt.Sprintf(`Get-CimInstance Win32_Process -Filter "ProcessId=%d"`, helper.Process.Pid)); err != nil {
		t.Skipf("Windows process command-line metadata is unavailable: %v", err)
	}

	if _, err := terminateProcessVerified(helper.Process.Pid, func(procInfo) bool { return false }); err == nil {
		t.Fatal("identity mismatch did not block process termination")
	}
	if !processRunning(helper.Process.Pid) {
		t.Fatal("identity mismatch terminated the helper")
	}
	terminated, err := terminateProcessVerified(helper.Process.Pid, func(info procInfo) bool {
		return strings.Contains(info.CommandLine, "TestManagedSleeper")
	})
	if err != nil || !terminated {
		t.Fatalf("verified helper was not terminated: terminated=%v err=%v", terminated, err)
	}
	if processRunning(helper.Process.Pid) {
		t.Fatal("verified helper remained alive")
	}
}

func TestStopGhostInfoVerifiesAndStopsGhostHelper(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Ghost process discovery uses Windows process metadata")
	}
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ghostPath := filepath.Join(t.TempDir(), "ghost.exe")
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	out, err := os.OpenFile(ghostPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o700)
	if err != nil {
		_ = in.Close()
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = in.Close()
		_ = out.Close()
		t.Fatal(err)
	}
	_ = in.Close()
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(ghostPath, "-test.run=TestManagedSleeper", "--", "--addr", "127.0.0.1:46101", "--config", "config-api-45101.yaml")
	cmd.Env = append(os.Environ(), "CAPX_MANAGER_HELPER_PROCESS=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	var info procInfo
	var lastQueryErr error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		infos, queryErr := getProcessInfos(fmt.Sprintf(`Get-CimInstance Win32_Process -Filter "ProcessId=%d"`, cmd.Process.Pid))
		lastQueryErr = queryErr
		if queryErr == nil && len(infos) == 1 {
			info = infos[0]
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if info.ProcessID == 0 {
		if lastQueryErr != nil {
			t.Skipf("Windows process command-line metadata is unavailable: %v", lastQueryErr)
		}
		t.Fatal("Ghost helper process metadata was not available")
	}
	if err := stopGhostInfo(ghostInfo{PID: info.ProcessID, CommandLine: info.CommandLine}); err != nil {
		t.Fatal(err)
	}
	if processRunning(info.ProcessID) {
		t.Fatal("verified Ghost helper remained running")
	}
}

func managedProjectFixture(t *testing.T, id string) (string, string) {
	t.Helper()
	root := t.TempDir()
	registry := filepath.Join(root, "registry")
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(filepath.Join(project, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(project, ".codex", "config.toml"),
		[]byte("[mcp_servers.test.env]\nCAPX_INSTANCE_ID = '"+id+"'\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPX_INSTANCE_DIR", registry)
	return root, project
}

func managedSleeperCommand(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestManagedSleeper$")
	cmd.Env = append(os.Environ(), "CAPX_MANAGER_HELPER_PROCESS=1")
	return cmd
}

func restoreManagedHooks(t *testing.T) {
	t.Helper()
	oldCapx := managedCapxLauncher
	oldWaiter := managedRuntimeWaiter
	oldBrowser := managedBrowserLauncher
	oldWriter := managedManifestWriter
	t.Cleanup(func() {
		managedCapxLauncher = oldCapx
		managedRuntimeWaiter = oldWaiter
		managedBrowserLauncher = oldBrowser
		managedManifestWriter = oldWriter
	})
}
