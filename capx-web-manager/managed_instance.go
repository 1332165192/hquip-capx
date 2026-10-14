package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const managedReadyTimeout = 12 * time.Second
const netstatQueryTimeout = 2 * time.Second
const managedBrowserMetadataTimeout = time.Second

var managedLifecycleMu sync.Mutex

var (
	managedBrowserImagePath    = processExecutablePath
	managedBrowserProcessQuery = defaultManagedBrowserProcessQuery
)

var (
	managedCapxLauncher    = launchManagedCapx
	managedRuntimeWaiter   = waitManagedRuntime
	managedBrowserLauncher = launchManagedBrowser
	managedManifestWriter  = writeInstanceManifest
)

type managedStartResult struct {
	InstanceID   string `json:"instance_id"`
	ProjectRoot  string `json:"project_root"`
	APIPort      int    `json:"api_port"`
	ProxyPort    int    `json:"proxy_port"`
	CDPPort      int    `json:"cdp_port"`
	PID          int    `json:"pid"`
	BrowserPID   int    `json:"browser_pid"`
	StateDir     string `json:"state_dir"`
	ManifestPath string `json:"manifest_path"`
	Generation   string `json:"generation"`
}

type capxHealth struct {
	Status   string `json:"status"`
	Identity struct {
		InstanceID string `json:"instance_id"`
		Generation string `json:"generation"`
	} `json:"identity"`
}

type capxProxyStatus struct {
	Running bool   `json:"running"`
	Addr    string `json:"addr"`
}

func startManagedInstance(req startRequest) (managedStartResult, error) {
	managedLifecycleMu.Lock()
	defer managedLifecycleMu.Unlock()

	id := strings.TrimSpace(req.InstanceID)
	projectDir, err := validateManagedProject(id, req.ProjectDir)
	if err != nil {
		return managedStartResult{}, err
	}
	if req.Count > 1 {
		return managedStartResult{}, errors.New("a managed CAPX_INSTANCE_ID can start exactly one instance")
	}
	releaseInstanceLock, err := acquireInstanceLifecycleLock(id)
	if err != nil {
		return managedStartResult{}, err
	}
	defer releaseInstanceLock()

	stateDir, err := managedStateDir(id)
	if err != nil {
		return managedStartResult{}, err
	}
	if existing, loadErr := loadInstanceManifest(id); loadErr == nil {
		if !sameCanonicalPath(existing.ProjectRoot, projectDir) {
			return managedStartResult{}, errors.New("existing manifest belongs to another project")
		}
		active, inspectErr := inspectManagedRuntime(existing)
		if inspectErr != nil {
			return managedStartResult{}, fmt.Errorf("inspect existing managed instance: %w", inspectErr)
		}
		if active {
			return managedStartResult{}, fmt.Errorf("managed instance %s is already running", id)
		}
		stateDir = existing.StateDir
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return managedStartResult{}, fmt.Errorf("load existing instance manifest: %w", loadErr)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return managedStartResult{}, fmt.Errorf("create managed state directory: %w", err)
	}

	requested := portRequest{API: req.APIPort, Proxy: req.ProxyPort, CDP: req.CDPPort}
	if req.AutoPorts {
		requested = portRequest{}
	}
	ports, releasePorts, err := allocatePortSet(requested)
	if err != nil {
		return managedStartResult{}, err
	}
	defer releasePorts()

	generation, err := newRuntimeGeneration()
	if err != nil {
		return managedStartResult{}, err
	}
	startedAt := time.Now().UTC().Format(time.RFC3339Nano)

	unlockHandoff := lockPortHandoff()
	releasePorts()
	capxCmd, err := managedCapxLauncher(req.CapturedPath, id, generation, stateDir, ports, req.AllowActive)
	unlockHandoff()
	if err != nil {
		return managedStartResult{}, err
	}
	capxPID := capxCmd.Process.Pid
	rollbackCapx := true
	defer func() {
		if rollbackCapx {
			_ = capxCmd.Process.Kill()
		}
	}()

	token, err := managedRuntimeWaiter(id, generation, stateDir, ports)
	if err != nil {
		return managedStartResult{}, err
	}
	browserPID, err := managedBrowserLauncher(id, generation, stateDir, ports)
	if err != nil {
		return managedStartResult{}, err
	}
	rollbackBrowser := true
	defer func() {
		if rollbackBrowser {
			_, _ = terminateProcessVerified(browserPID, func(current procInfo) bool {
				line := strings.ToLower(current.CommandLine)
				return strings.Contains(line, "--capx-instance-id="+strings.ToLower(id)) &&
					strings.Contains(line, "--capx-generation="+strings.ToLower(generation)) &&
					strings.Contains(line, "--remote-debugging-port="+strconv.Itoa(ports.CDP))
			})
		}
	}()

	manifest := instanceManifest{
		SchemaVersion:    instanceManifestSchemaVersion,
		InstanceID:       id,
		ProjectRoot:      projectDir,
		APIBase:          fmt.Sprintf("http://127.0.0.1:%d", ports.API),
		Proxy:            fmt.Sprintf("http://127.0.0.1:%d", ports.Proxy),
		StateDir:         stateDir,
		TokenFile:        filepath.Join(stateDir, "token"),
		CDPPort:          ports.CDP,
		PID:              capxPID,
		BrowserPID:       browserPID,
		Generation:       generation,
		UpdatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		ProcessStartedAt: startedAt,
	}
	if err := managedManifestWriter(manifest); err != nil {
		return managedStartResult{}, err
	}
	if req.OwnerPID > 0 {
		go monitorManagedOwner(id, generation, req.OwnerPID)
	}
	manifestPath, _ := instanceManifestPath(id)

	// The token is intentionally used only for readiness and is never returned
	// or written to the manifest.
	_ = token
	_ = capxCmd.Process.Release()
	rollbackCapx = false
	rollbackBrowser = false
	return managedStartResult{
		InstanceID: id, ProjectRoot: projectDir,
		APIPort: ports.API, ProxyPort: ports.Proxy, CDPPort: ports.CDP,
		PID: capxPID, BrowserPID: browserPID, StateDir: stateDir,
		ManifestPath: manifestPath, Generation: generation,
	}, nil
}

func monitorManagedOwner(instanceID, generation string, ownerPID int) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for processRunning(ownerPID) {
		<-ticker.C
	}
	manifest, err := loadInstanceManifest(instanceID)
	if err != nil || !manifest.IdentityRequired || manifest.Generation != generation {
		return
	}
	_ = stopManagedInstance(manifest)
}

func managedStateDir(id string) (string, error) {
	registry, err := instanceRegistryDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(registry), "state-"+id), nil
}

func newRuntimeGeneration() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate runtime generation: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func acquireInstanceLifecycleLock(id string) (func(), error) {
	registry, err := instanceRegistryDirectory()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(registry, 0o700); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(registry, "."+id+".lifecycle.lock")
	file, unlock, err := acquireLifecycleFileLock(lockPath)
	if err != nil {
		if errors.Is(err, errLifecycleLockBusy) {
			return nil, fmt.Errorf("managed instance %s is being changed by another manager", id)
		}
		return nil, err
	}
	record := struct {
		PID       int    `json:"pid"`
		UpdatedAt string `json:"updated_at"`
	}{PID: os.Getpid(), UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	data, _ := json.Marshal(record)
	cleanup := func() {
		_ = unlock()
		_ = file.Close()
	}
	if err := file.Truncate(0); err != nil {
		cleanup()
		return nil, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		cleanup()
		return nil, err
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(cleanup) }, nil
}

func launchManagedCapx(exe, id, generation, stateDir string, ports portSet, allow bool) (*exec.Cmd, error) {
	if strings.TrimSpace(exe) == "" {
		exe = defaultCapturedPath()
	}
	if _, err := os.Stat(exe); err != nil {
		return nil, fmt.Errorf("capx-captured.exe is unavailable: %w", err)
	}
	logDir := filepath.Join(stateDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, err
	}
	args := []string{
		"--addr", fmt.Sprintf("127.0.0.1:%d", ports.API),
		"--proxy", fmt.Sprintf("127.0.0.1:%d", ports.Proxy),
		"--state-dir", stateDir,
		"--instance-id", id,
		"--generation", generation,
		"--strict-addr",
	}
	if allow {
		args = append(args, "--allow-active")
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = filepath.Dir(exe)
	cmd.Env = upsertEnv(os.Environ(), map[string]string{"CAPX_AUTH": "1"})
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = hiddenSysProcAttr()
	}
	stdout, err := os.OpenFile(filepath.Join(logDir, "stdout.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	stderr, err := os.OpenFile(filepath.Join(logDir, "stderr.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer stderr.Close()
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start managed Capx: %w", err)
	}
	return cmd, nil
}

func waitManagedRuntime(id, generation, stateDir string, ports portSet) (string, error) {
	deadline := time.Now().Add(managedReadyTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		token := tokenText(stateDir)
		if token != "" {
			manifest := instanceManifest{
				InstanceID: id, Generation: generation,
				APIBase: fmt.Sprintf("http://127.0.0.1:%d", ports.API),
				Proxy:   fmt.Sprintf("http://127.0.0.1:%d", ports.Proxy),
			}
			if err := verifyRuntimeEndpoints(manifest, token, true); err == nil {
				return token, nil
			} else {
				lastErr = err
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = errors.New("token or runtime endpoint did not become ready")
	}
	return "", fmt.Errorf("managed Capx readiness failed: %w", lastErr)
}

func inspectManagedRuntime(manifest instanceManifest) (bool, error) {
	client := &http.Client{Timeout: 700 * time.Millisecond}
	var health capxHealth
	if err := runtimeJSON(client, http.MethodGet, manifest.APIBase+"/health", "", &health); err != nil {
		return false, nil
	}
	if health.Status != "ok" {
		return false, errors.New("existing endpoint is not healthy")
	}
	tokenBytes, err := os.ReadFile(manifest.TokenFile)
	if err != nil {
		return false, fmt.Errorf("healthy endpoint has no selected token: %w", err)
	}
	if err := verifyRuntimeEndpoints(manifest, strings.TrimSpace(string(tokenBytes)), manifest.IdentityRequired); err != nil {
		return false, err
	}
	return true, nil
}

func verifyRuntimeEndpoints(manifest instanceManifest, token string, requireIdentity bool) error {
	client := &http.Client{Timeout: 1200 * time.Millisecond}
	var health capxHealth
	if err := runtimeJSON(client, http.MethodGet, manifest.APIBase+"/health", "", &health); err != nil {
		return err
	}
	if health.Status != "ok" {
		return errors.New("health status is not ok")
	}
	if requireIdentity || health.Identity.InstanceID != "" || health.Identity.Generation != "" {
		if health.Identity.InstanceID != manifest.InstanceID || health.Identity.Generation != manifest.Generation {
			return errors.New("runtime health identity does not match manifest")
		}
	}
	var proxy capxProxyStatus
	if err := runtimeJSON(client, http.MethodGet, manifest.APIBase+"/api/proxy/status", token, &proxy); err != nil {
		return err
	}
	expected := strings.TrimPrefix(manifest.Proxy, "http://")
	if !proxy.Running || proxy.Addr != expected {
		return fmt.Errorf("proxy mismatch: expected %s, got %s", expected, proxy.Addr)
	}
	return nil
}

func runtimeJSON(client *http.Client, method, endpoint, token string, output any) error {
	req, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Capx-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned HTTP %d", endpoint, resp.StatusCode)
	}
	if output == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(output); err != nil {
		return fmt.Errorf("decode %s: %w", endpoint, err)
	}
	return nil
}

func launchManagedBrowser(id, generation, stateDir string, ports portSet) (int, error) {
	if !portFree(ports.CDP) {
		return 0, fmt.Errorf("CDP port %d was occupied during startup", ports.CDP)
	}
	browser := findBrowserExe()
	if browser == "" {
		return 0, errors.New("Chrome or Edge was not found")
	}
	profile := filepath.Join(stateDir, "browser-profile")
	if err := os.MkdirAll(profile, 0o700); err != nil {
		return 0, err
	}
	flags := []string{
		fmt.Sprintf("--remote-debugging-port=%d", ports.CDP),
		"--remote-allow-origins=*",
		"--enable-automation",
		"--user-data-dir=" + profile,
		fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", ports.Proxy),
		"--proxy-bypass-list=<-loopback>",
		"--capx-instance-id=" + id,
		"--capx-generation=" + generation,
		"--disable-quic",
		"--disable-http3",
		"--disable-features=DnsOverHttps,UseDnsHttpsSvcbAlpn",
		"--no-first-run",
		"--no-default-browser-check",
		"--hide-crash-restore-bubble",
		fmt.Sprintf("http://127.0.0.1:%d/#proxy", ports.API),
	}
	if os.Getenv("CAPX_MANAGER_BROWSER_HEADLESS") == "1" {
		flags = append([]string{"--headless=new", "--disable-gpu"}, flags...)
	}
	logFile, err := os.OpenFile(filepath.Join(stateDir, "logs", "browser.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, err
	}
	cmd := exec.Command(browser, flags...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = hiddenSysProcAttr()
	}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return 0, err
	}
	_ = logFile.Close()
	launcherPID := cmd.Process.Pid
	deadline := time.Now().Add(managedReadyTimeout)
	var lastOwnerErr error
	cdpBecameReady := false
	for time.Now().Before(deadline) {
		if managedCDPReady(ports.CDP) {
			cdpBecameReady = true
			identityFlags := []string{
				fmt.Sprintf("--remote-debugging-port=%d", ports.CDP),
				"--user-data-dir=" + profile,
				fmt.Sprintf("--proxy-server=http://127.0.0.1:%d", ports.Proxy),
				"--capx-instance-id=" + id,
				"--capx-generation=" + generation,
			}
			owner, ownerErr := findManagedBrowserPID(ports.CDP, identityFlags)
			if ownerErr == nil && owner > 0 {
				_ = cmd.Process.Release()
				return owner, nil
			}
			lastOwnerErr = ownerErr
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	if cdpBecameReady {
		return 0, fmt.Errorf(
			"managed browser CDP became ready on port %d, but owner verification failed (launcher pid %d): %w",
			ports.CDP,
			launcherPID,
			lastOwnerErr,
		)
	}
	return 0, fmt.Errorf("managed browser CDP did not become ready on port %d (launcher pid %d)", ports.CDP, launcherPID)
}

func managedCDPReady(port int) bool {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	var version struct {
		WebSocket string `json:"webSocketDebuggerUrl"`
	}
	return runtimeJSON(client, http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/json/version", port), "", &version) == nil && version.WebSocket != ""
}

func openManagedBrowserTab(manifest instanceManifest) error {
	if !managedCDPReady(manifest.CDPPort) {
		return errors.New("managed browser CDP is not ready")
	}
	endpoint := fmt.Sprintf(
		"http://127.0.0.1:%d/json/new?%s",
		manifest.CDPPort,
		url.QueryEscape(manifest.APIBase+"/#proxy"),
	)
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	return runtimeJSON(client, http.MethodPut, endpoint, "", nil)
}

func findManagedBrowserPID(cdpPort int, flags []string) (int, error) {
	listenerPID, err := findLoopbackListenerPID(cdpPort)
	if err != nil {
		return 0, err
	}
	return verifyManagedBrowserPID(listenerPID, flags)
}

func verifyManagedBrowserPID(listenerPID int, flags []string) (int, error) {
	executablePath, err := managedBrowserImagePath(listenerPID)
	if err != nil {
		return 0, fmt.Errorf("query CDP listener process %d image: %w", listenerPID, err)
	}
	if err := verifyManagedBrowserIdentity(listenerPID, executablePath, flags); err != nil {
		return 0, err
	}
	return listenerPID, nil
}

func verifyManagedBrowserIdentity(listenerPID int, executablePath string, flags []string) error {
	if !managedBrowserExecutable(executablePath) {
		return fmt.Errorf("CDP listener process %d is not Chrome or Edge: %s", listenerPID, executablePath)
	}

	// The listener PID and executable image are verified without WMI. Command-line
	// flags are an additional check when CIM is healthy; resource exhaustion in
	// the WMI provider must not block a browser just launched on a reserved port.
	infos, queryErr := managedBrowserProcessQuery(listenerPID)
	if queryErr == nil && len(infos) > 0 {
		if len(infos) != 1 || infos[0].ProcessID != listenerPID {
			return fmt.Errorf("CDP listener process %d metadata did not match the listener", listenerPID)
		}
		info := infos[0]
		info.ExecutablePath = executablePath
		if !managedBrowserProcessMatchesFlags(info, flags) {
			return fmt.Errorf("CDP listener process %d did not match managed browser identity", listenerPID)
		}
	}
	return nil
}

func managedBrowserExecutable(executablePath string) bool {
	normalized := strings.ReplaceAll(strings.TrimSpace(executablePath), `\`, "/")
	executable := strings.ToLower(filepath.Base(normalized))
	switch executable {
	case
		// Windows image names.
		"chrome.exe", "msedge.exe",
		// Linux Chrome/Chromium/Edge binary names (as reported by /proc/<pid>/exe).
		"chrome", "google-chrome", "google-chrome-stable", "google-chrome-beta",
		"chromium", "chromium-browser",
		"microsoft-edge", "microsoft-edge-stable", "microsoft-edge-beta", "msedge":
		return true
	default:
		return false
	}
}

func managedBrowserProcessMatchesFlags(info procInfo, flags []string) bool {
	if !managedBrowserExecutable(info.ExecutablePath) {
		return false
	}
	line := strings.ToLower(info.CommandLine)
	for _, flag := range flags {
		if !strings.Contains(line, strings.ToLower(flag)) {
			return false
		}
	}
	return true
}

func findLoopbackListenerPID(port int) (int, error) {
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid listener port %d", port)
	}
	if runtime.GOOS != "windows" {
		return findLoopbackListenerPIDFromProc(port)
	}
	ctx, cancel := context.WithTimeout(context.Background(), netstatQueryTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "netstat.exe", "-ano", "-p", "tcp")
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = hiddenSysProcAttr()
	}
	cmd.WaitDelay = 500 * time.Millisecond
	output, err := cmd.Output()
	if ctx.Err() != nil {
		return 0, fmt.Errorf("netstat listener query timed out after %s: %w", netstatQueryTimeout, ctx.Err())
	}
	if err != nil {
		return 0, fmt.Errorf("query TCP listeners with netstat: %w", err)
	}
	return parseNetstatListenerPID(string(output), port)
}

func parseNetstatListenerPID(output string, port int) (int, error) {
	var selectedPID int
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.EqualFold(fields[0], "TCP") || !strings.EqualFold(fields[3], "LISTENING") {
			continue
		}
		host, localPort, ok := parseNetstatEndpoint(fields[1])
		if !ok || host != "127.0.0.1" || localPort != port {
			continue
		}
		pid, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil || pid <= 0 {
			continue
		}
		if selectedPID != 0 && selectedPID != pid {
			return 0, fmt.Errorf("multiple processes listen on 127.0.0.1:%d", port)
		}
		selectedPID = pid
	}
	if selectedPID == 0 {
		return 0, fmt.Errorf("no TCP listener found on 127.0.0.1:%d", port)
	}
	return selectedPID, nil
}

func parseNetstatEndpoint(endpoint string) (string, int, bool) {
	separator := strings.LastIndex(endpoint, ":")
	if separator <= 0 || separator == len(endpoint)-1 {
		return "", 0, false
	}
	host := strings.Trim(endpoint[:separator], "[]")
	port, err := strconv.Atoi(endpoint[separator+1:])
	if err != nil {
		return "", 0, false
	}
	return host, port, true
}

func stopManagedInstance(manifest instanceManifest) error {
	managedLifecycleMu.Lock()
	defer managedLifecycleMu.Unlock()
	if !manifest.IdentityRequired {
		return errors.New("refusing managed stop because this legacy manifest cannot prove runtime identity")
	}
	if manifest.PID <= 0 || strings.TrimSpace(manifest.Generation) == "" {
		return errors.New("refusing managed stop without a positive PID and generation")
	}
	releaseInstanceLock, err := acquireInstanceLifecycleLock(manifest.InstanceID)
	if err != nil {
		return err
	}
	defer releaseInstanceLock()

	tokenBytes, _ := os.ReadFile(manifest.TokenFile)
	token := strings.TrimSpace(string(tokenBytes))
	shutdownRequested := false
	if token != "" && verifyManagedRuntimeIdentity(manifest) == nil {
		client := &http.Client{Timeout: 1500 * time.Millisecond}
		if err := requestRuntimeShutdown(client, manifest.APIBase, token, manifest.InstanceID, manifest.Generation); err == nil {
			shutdownRequested = true
		} else if errors.Is(err, errRuntimeShutdownIdentity) {
			return err
		}
	}
	if shutdownRequested {
		deadline := time.Now().Add(20 * time.Second)
		for processRunning(manifest.PID) && time.Now().Before(deadline) {
			time.Sleep(150 * time.Millisecond)
		}
	}
	if processRunning(manifest.PID) {
		if _, err := terminateProcessVerified(manifest.PID, func(current procInfo) bool {
			return managedCapxProcessInfoMatches(manifest, current)
		}); err != nil {
			return fmt.Errorf("refusing to terminate managed Capx: %w", err)
		}
	}
	if manifest.BrowserPID > 0 {
		if _, err := terminateManagedBrowser(manifest); err != nil && processRunning(manifest.BrowserPID) {
			return fmt.Errorf("refusing to terminate managed browser: %w", err)
		}
	}
	reserved, err := reserveInstanceManifestIfMatch(manifest)
	if err != nil {
		return err
	}
	if !reserved {
		return errors.New("managed manifest changed during stop; replacement was preserved")
	}
	return nil
}

func verifyManagedRuntimeIdentity(manifest instanceManifest) error {
	client := &http.Client{Timeout: 1200 * time.Millisecond}
	var health capxHealth
	if err := runtimeJSON(client, http.MethodGet, manifest.APIBase+"/health", "", &health); err != nil {
		return err
	}
	if health.Status != "ok" || health.Identity.InstanceID != manifest.InstanceID || health.Identity.Generation != manifest.Generation {
		return errors.New("runtime health identity does not match manifest")
	}
	return nil
}

func processRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := processExecutablePath(pid)
	return err == nil
}

func managedCapxProcessMatches(manifest instanceManifest) bool {
	infos, err := getProcessInfos(fmt.Sprintf(`Get-CimInstance Win32_Process -Filter "ProcessId=%d"`, manifest.PID))
	if err != nil || len(infos) != 1 {
		return false
	}
	return managedCapxProcessInfoMatches(manifest, infos[0])
}

func managedCapxProcessInfoMatches(manifest instanceManifest, info procInfo) bool {
	return strings.EqualFold(argValue(info.CommandLine, "instance-id"), manifest.InstanceID) &&
		strings.EqualFold(argValue(info.CommandLine, "generation"), manifest.Generation) &&
		sameCanonicalPath(argValue(info.CommandLine, "state-dir"), manifest.StateDir)
}

func managedBrowserProcessMatches(manifest instanceManifest) bool {
	infos, err := getProcessInfos(fmt.Sprintf(`Get-CimInstance Win32_Process -Filter "ProcessId=%d"`, manifest.BrowserPID))
	if err != nil || len(infos) != 1 {
		return false
	}
	return managedBrowserProcessInfoMatches(manifest, infos[0])
}

func managedBrowserProcessInfoMatches(manifest instanceManifest, info procInfo) bool {
	line := strings.ToLower(info.CommandLine)
	return strings.Contains(line, "--capx-instance-id="+strings.ToLower(manifest.InstanceID)) &&
		strings.Contains(line, "--capx-generation="+strings.ToLower(manifest.Generation)) &&
		strings.Contains(line, "--remote-debugging-port="+strconv.Itoa(manifest.CDPPort))
}

func listInstanceManifests() []instanceManifest {
	dir, err := instanceRegistryDirectory()
	if err != nil {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	result := make([]instanceManifest, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		manifest, err := loadInstanceManifest(id)
		if err == nil {
			result = append(result, manifest)
		}
	}
	return result
}

func manifestForProcess(info procInfo) (instanceManifest, bool) {
	for _, manifest := range listInstanceManifests() {
		if manifest.IdentityRequired && manifest.PID > 0 && manifest.PID == info.ProcessID && managedCapxProcessInfoMatches(manifest, info) {
			return manifest, true
		}
	}
	return instanceManifest{}, false
}
