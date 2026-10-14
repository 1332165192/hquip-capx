package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type config struct {
	CapturedPath   string `json:"captured_path"`
	GhostPath      string `json:"ghost_path"`
	ADBPath        string `json:"adb_path"`
	ADBSerial      string `json:"adb_serial"`
	JADXDir        string `json:"jadx_dir"`
	APIPort        int    `json:"api_port"`
	ProxyPort      int    `json:"proxy_port"`
	AutoPorts      bool   `json:"auto_ports"`
	AutoProxy      bool   `json:"auto_proxy"`
	AllowActive    bool   `json:"allow_active"`
	Count          int    `json:"count"`
	ShowOnlyPath   bool   `json:"show_only_path"`
	OpenAfterStart bool   `json:"open_after_start"`
}

type startRequest struct {
	config
	InstanceID string `json:"instance_id"`
	ProjectDir string `json:"project_root"`
	CDPPort    int    `json:"cdp_port"`
	OwnerPID   int    `json:"owner_pid"`
}

type instance struct {
	Status      string `json:"status"`
	InstanceID  string `json:"instance_id,omitempty"`
	ProjectDir  string `json:"project_root,omitempty"`
	Generation  string `json:"generation,omitempty"`
	APIPort     int    `json:"api_port"`
	ProxyPort   int    `json:"proxy_port"`
	CDPPort     int    `json:"cdp_port,omitempty"`
	PID         int    `json:"pid"`
	BrowserPID  int    `json:"browser_pid,omitempty"`
	Manifest    string `json:"manifest_path,omitempty"`
	Addr        string `json:"addr"`
	Proxy       string `json:"proxy"`
	StateDir    string `json:"state_dir"`
	Token       string `json:"token"`
	Exe         string `json:"exe"`
	CommandLine string `json:"command_line"`
	GhostPort   int    `json:"ghost_port"`
	GhostPID    int    `json:"ghost_pid"`
	GhostURL    string `json:"ghost_url"`
	GhostStatus string `json:"ghost_status"`
	ADBStatus   string `json:"adb_status"`
	ADBProxy    string `json:"adb_proxy"`
}

type procInfo struct {
	ProcessID      int    `json:"ProcessId"`
	ExecutablePath string `json:"ExecutablePath"`
	CommandLine    string `json:"CommandLine"`
}

type ghostInfo struct {
	Port        int
	PID         int
	URL         string
	Status      string
	StateDir    string
	ProxyPort   int
	CommandLine string
}

type apiResp struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Data    any    `json:"data,omitempty"`
	Message string `json:"message,omitempty"`
}

const defaultManagerPort = 18990

var srv *http.Server
var currentManagerPort int

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/ping", handlePing)
	mux.HandleFunc("/api/config", handleConfig)
	mux.HandleFunc("/api/instances", handleInstances)
	mux.HandleFunc("/api/start", handleStart)
	mux.HandleFunc("/api/stop", handleStop)
	mux.HandleFunc("/api/stop-all", handleStopAll)
	mux.HandleFunc("/api/open", handleOpen)
	mux.HandleFunc("/api/browser", handleBrowser)
	mux.HandleFunc("/api/ghost", handleGhost)
	mux.HandleFunc("/api/ghost-stop", handleGhostStop)
	mux.HandleFunc("/api/adb", handleADB)
	mux.HandleFunc("/api/adb-stop", handleADBStop)
	mux.HandleFunc("/api/adb-devices", handleADBDevices)
	mux.HandleFunc("/api/choose-free", handleChooseFree)
	mux.HandleFunc("/api/open-dir", handleOpenDir)
	mux.HandleFunc("/api/copy", handleCopy)
	mux.HandleFunc("/api/src-template", handleSRCTemplate)
	mux.HandleFunc("/api/select-directory", handleSelectDirectory)
	mux.HandleFunc("/api/exit", handleExit)

	ln, err := listenManager()
	if err != nil {
		panic(err)
	}
	if _, port, err := net.SplitHostPort(ln.Addr().String()); err == nil {
		currentManagerPort = atoiDefault(port, defaultManagerPort)
	}
	url := "http://" + ln.Addr().String() + "/"
	srv = &http.Server{Handler: managerRequestGuard(mux)}
	go func() { _ = srv.Serve(ln) }()
	if os.Getenv("CAPX_MANAGER_NO_BROWSER") != "1" {
		go func() { time.Sleep(250 * time.Millisecond); openURL(url) }()
	}
	select {}
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = renderManagerIndex(w)
}
func handlePing(w http.ResponseWriter, r *http.Request) {
	writeOK(w, map[string]any{"pid": os.Getpid(), "manager_port": currentManagerPort}, "pong")
}

// configView 在持久化 config 之外附带运行时提示（server_mode=true 表示无本地桌面
// 环境），供前端隐藏“打开浏览器/网页/目录”等只在本地有意义的按钮；不写入 settings.json。
type configView struct {
	config
	ServerMode bool   `json:"server_mode"`
	Platform   string `json:"platform"`
}

// serverMode 表示运行在无本地桌面 GUI 的服务器环境（本工具仅 Windows 版视为本地
// 桌面用法，其余平台一律按远程服务器处理）。
func serverMode() bool { return runtime.GOOS != "windows" }

func handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeOK(w, configView{config: loadConfig(), ServerMode: serverMode(), Platform: runtime.GOOS}, "")
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, "method not allowed")
		return
	}
	var c config
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeErr(w, "bad json")
		return
	}
	if c.CapturedPath == "" {
		c.CapturedPath = defaultCapturedPath()
	}
	if c.GhostPath == "" {
		c.GhostPath = defaultGhostPath()
	}
	if c.ADBPath == "" {
		c.ADBPath = defaultADBPath()
	}
	if c.Count <= 0 {
		c.Count = 1
	}
	if err := saveConfig(c); err != nil {
		writeErr(w, err.Error())
		return
	}
	writeOK(w, c, "已保存")
}
func handleInstances(w http.ResponseWriter, r *http.Request) {
	current := loadConfig()
	items, err := getInstances(current.CapturedPath, current.ShowOnlyPath)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	writeOK(w, items, "")
}
func handleChooseFree(w http.ResponseWriter, r *http.Request) {
	request := portRequest{
		API:   atoiDefault(r.URL.Query().Get("api"), 0),
		Proxy: atoiDefault(r.URL.Query().Get("proxy"), 0),
		CDP:   atoiDefault(r.URL.Query().Get("cdp"), 0),
	}
	ports, release, err := allocatePortSet(request)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	defer release()
	writeOK(w, map[string]int{"api_port": ports.API, "proxy_port": ports.Proxy, "cdp_port": ports.CDP}, "")
}
func handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "method not allowed")
		return
	}
	var req startRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, "bad json")
		return
	}
	current := loadConfig()
	if req.CapturedPath == "" {
		req.CapturedPath = current.CapturedPath
	}
	if req.GhostPath == "" {
		req.GhostPath = current.GhostPath
	}
	if req.ADBPath == "" {
		req.ADBPath = current.ADBPath
	}
	if req.ADBSerial == "" {
		req.ADBSerial = current.ADBSerial
	}
	if strings.TrimSpace(req.InstanceID) != "" || strings.TrimSpace(req.ProjectDir) != "" {
		if req.Count <= 0 {
			req.Count = 1
		}
		result, err := startManagedInstance(req)
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		saved := req.config
		saved.APIPort = result.APIPort
		saved.ProxyPort = result.ProxyPort
		saved.Count = 1
		_ = saveConfig(saved)
		writeOK(w, result, "受管 Capx 实例已启动并登记")
		return
	}
	if req.APIPort == 0 {
		req.APIPort = current.APIPort
	}
	if req.ProxyPort == 0 {
		req.ProxyPort = current.ProxyPort
	}
	if req.Count <= 0 {
		req.Count = 1
	}
	if req.Count > 50 {
		writeErr(w, "一次最多启动 50 个")
		return
	}
	started := []int{}
	firstPorts := portSet{}
	for i := 0; i < req.Count; i++ {
		requested := portRequest{}
		if req.APIPort > 0 {
			requested.API = req.APIPort + i
		}
		if req.ProxyPort > 0 {
			requested.Proxy = req.ProxyPort + i
		}
		ports, release, err := allocatePortSet(requested)
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		unlock := lockPortHandoff()
		release()
		err = startCapx(req.CapturedPath, ports.API, ports.Proxy, req.AllowActive)
		unlock()
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		if i == 0 {
			firstPorts = ports
		}
		started = append(started, ports.API)
	}
	saved := req.config
	saved.APIPort = firstPorts.API
	saved.ProxyPort = firstPorts.Proxy
	saved.AutoProxy = false
	_ = saveConfig(saved)
	time.Sleep(500 * time.Millisecond)
	if req.OpenAfterStart {
		for _, p := range started {
			openURL(fmt.Sprintf("http://127.0.0.1:%d/#proxy", p))
		}
	}
	writeOK(w, map[string]any{"started": started}, fmt.Sprintf("已启动 %d 个实例", len(started)))
}
func handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "method not allowed")
		return
	}
	var req struct {
		PID        int    `json:"pid"`
		InstanceID string `json:"instance_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if strings.TrimSpace(req.InstanceID) != "" {
		manifest, err := loadInstanceManifest(strings.TrimSpace(req.InstanceID))
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		if req.PID > 0 && manifest.PID != req.PID {
			writeErr(w, "pid does not match the selected managed instance")
			return
		}
		failures := cleanupInstanceAuxiliaries(portFromAddr(manifest.APIBase), portFromAddr(manifest.Proxy))
		if err := stopManagedInstance(manifest); err != nil {
			failures = append(failures, err)
		}
		if len(failures) > 0 {
			writeErr(w, "实例已执行停止，但存在清理失败: "+joinErrors(failures))
			return
		}
		writeOK(w, nil, "受管实例已停止并取消登记")
		return
	}
	if req.PID <= 0 {
		writeErr(w, "pid required")
		return
	}
	current := loadConfig()
	items, err := getInstances(current.CapturedPath, current.ShowOnlyPath)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	var selected *instance
	for _, item := range items {
		if item.PID == req.PID {
			copy := item
			selected = &copy
			break
		}
	}
	if selected == nil {
		writeErr(w, "pid is not a listed capx-captured instance")
		return
	}
	failures := cleanupInstanceAuxiliaries(selected.APIPort, selected.ProxyPort)
	if _, err := stopLegacyInstance(*selected); err != nil {
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		writeErr(w, "实例已执行停止，但存在清理失败: "+joinErrors(failures))
		return
	}
	writeOK(w, nil, "已停止")
}
func handleStopAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, "method not allowed")
		return
	}
	current := loadConfig()
	items, err := getInstances(current.CapturedPath, current.ShowOnlyPath)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	stopped := 0
	failures := make([]string, 0)
	for _, cleanupErr := range stopAllAuxiliaries(items, current) {
		failures = append(failures, cleanupErr.Error())
	}
	for _, it := range items {
		if it.InstanceID != "" && it.Generation != "" {
			manifest, loadErr := loadInstanceManifest(it.InstanceID)
			if loadErr == nil && manifest.PID > 0 {
				if stopErr := stopManagedInstance(manifest); stopErr != nil {
					failures = append(failures, fmt.Sprintf("%s: %v", it.InstanceID, stopErr))
				} else {
					stopped++
				}
				continue
			}
		}
		if terminated, stopErr := stopLegacyInstance(it); stopErr != nil {
			failures = append(failures, fmt.Sprintf("PID %d: %v", it.PID, stopErr))
		} else if terminated {
			stopped++
		}
	}
	if len(failures) > 0 {
		writeErr(w, fmt.Sprintf("已停止 %d 个实例；%d 项清理失败：%s", stopped, len(failures), strings.Join(failures, "; ")))
		return
	}
	writeOK(w, nil, fmt.Sprintf("已停止 %d 个实例", stopped))
}
func handleOpen(w http.ResponseWriter, r *http.Request) {
	if serverMode() {
		writeErr(w, "服务器无桌面浏览器；capx 页面地址为 http://127.0.0.1:<API 端口>/，请通过隧道或 nginx 在本机访问")
		return
	}
	port := atoiDefault(r.URL.Query().Get("port"), 0)
	page := r.URL.Query().Get("page")
	if page == "" {
		page = "proxy"
	}
	if port <= 0 {
		writeErr(w, "port required")
		return
	}
	openURL(fmt.Sprintf("http://127.0.0.1:%d/#%s", port, page))
	writeOK(w, nil, "已打开")
}
func handleBrowser(w http.ResponseWriter, r *http.Request) {
	if serverMode() {
		writeErr(w, "服务器无桌面环境，无法启动代理浏览器；请在你本机配置该实例代理后访问")
		return
	}
	if id := strings.TrimSpace(r.URL.Query().Get("instance_id")); id != "" {
		manifest, err := loadInstanceManifest(id)
		if err != nil {
			writeErr(w, err.Error())
			return
		}
		if err := openManagedBrowserTab(manifest); err != nil {
			writeErr(w, err.Error())
			return
		}
		writeOK(w, nil, "已在受管浏览器中打开 Capx")
		return
	}
	apiPort := atoiDefault(r.URL.Query().Get("api"), 0)
	proxyPort := atoiDefault(r.URL.Query().Get("proxy"), 0)
	if apiPort <= 0 || proxyPort <= 0 {
		writeErr(w, "api/proxy port required")
		return
	}
	if err := openProxyBrowser(apiPort, proxyPort); err != nil {
		writeErr(w, err.Error())
		return
	}
	writeOK(w, nil, "已打开独立代理浏览器")
}
func handleGhost(w http.ResponseWriter, r *http.Request) {
	apiPort := atoiDefault(r.URL.Query().Get("api"), 0)
	proxyPort := atoiDefault(r.URL.Query().Get("proxy"), 0)
	stateDir := r.URL.Query().Get("state")
	if apiPort <= 0 || proxyPort <= 0 {
		writeErr(w, "api/proxy port required")
		return
	}
	if stateDir == "" {
		stateDir = stateDirForPort(apiPort)
	}
	info, err := ensureGhost(apiPort, proxyPort, stateDir)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	openURL(info.URL)
	writeOK(w, info, "已打开信息收集")
}
func handleGhostStop(w http.ResponseWriter, r *http.Request) {
	apiPort := atoiDefault(r.URL.Query().Get("api"), 0)
	if apiPort <= 0 {
		writeErr(w, "api port required")
		return
	}
	gi, ok := findGhostByAPIPort(apiPort)
	if !ok || gi.PID <= 0 {
		writeOK(w, nil, "该实例没有运行中的 Ghost")
		return
	}
	if err := stopGhostInfo(gi); err != nil {
		writeErr(w, err.Error())
		return
	}
	writeOK(w, nil, "已停止 Ghost 信息收集")
}

func stopGhostInfo(gi ghostInfo) error {
	if gi.PID <= 0 {
		return nil
	}
	_, err := terminateProcessVerified(gi.PID, func(current procInfo) bool {
		return ghostExecutable(current.ExecutablePath) && current.CommandLine == gi.CommandLine
	})
	return err
}

func cleanupInstanceAuxiliaries(apiPort, proxyPort int) []error {
	var failures []error
	if gi, ok := findGhostByAPIPort(apiPort); ok {
		if err := stopGhostInfo(gi); err != nil {
			failures = append(failures, fmt.Errorf("Ghost API %d: %w", apiPort, err))
		}
	}
	failures = append(failures, stopRecordedBrowsers(apiPort, proxyPort)...)
	state := loadRuntimeSessions()
	hasRecordedADB := false
	for _, session := range state.ADB {
		if session.ProxyPort == proxyPort {
			hasRecordedADB = true
			break
		}
	}
	if hasRecordedADB {
		failures = append(failures, stopRecordedADB(proxyPort, "")...)
	}
	return failures
}

func stopAllAuxiliaries(items []instance, current config) []error {
	var failures []error
	ghosts, err := getGhostMap()
	if err != nil {
		failures = append(failures, fmt.Errorf("枚举 Ghost: %w", err))
	} else {
		// 只停当前列表实例对应的 ghost，避免误杀不属于任何实例的独立 ghost。
		managed := make(map[int]struct{}, len(items))
		for _, it := range items {
			if it.APIPort > 0 {
				managed[it.APIPort] = struct{}{}
			}
		}
		for apiPort, ghost := range ghosts {
			if _, ok := managed[apiPort]; !ok {
				continue
			}
			if err := stopGhostInfo(ghost); err != nil {
				failures = append(failures, fmt.Errorf("Ghost API %d: %w", apiPort, err))
			}
		}
	}
	failures = append(failures, stopRecordedBrowsers(0, 0)...)
	state := loadRuntimeSessions()
	if len(state.ADB) > 0 {
		failures = append(failures, stopRecordedADB(0, "")...)
	} else if serial := strings.TrimSpace(current.ADBSerial); serial != "" {
		seen := map[int]struct{}{}
		if current.ProxyPort > 0 {
			seen[current.ProxyPort] = struct{}{}
			failures = append(failures, stopRecordedADB(current.ProxyPort, serial)...)
		}
		for _, item := range items {
			if item.ProxyPort <= 0 {
				continue
			}
			if _, exists := seen[item.ProxyPort]; exists {
				continue
			}
			seen[item.ProxyPort] = struct{}{}
			failures = append(failures, stopRecordedADB(item.ProxyPort, serial)...)
		}
	}
	return failures
}

func joinErrors(values []error) string {
	parts := make([]string, 0, len(values))
	for _, err := range values {
		if err != nil {
			parts = append(parts, err.Error())
		}
	}
	return strings.Join(parts, "; ")
}
func handleADB(w http.ResponseWriter, r *http.Request) {
	proxyPort := atoiDefault(r.URL.Query().Get("proxy"), 0)
	serial := strings.TrimSpace(r.URL.Query().Get("serial"))
	if serial == "" {
		serial = loadConfig().ADBSerial
	}
	if proxyPort <= 0 {
		writeErr(w, "proxy port required")
		return
	}
	info, err := startADBProxy(proxyPort, serial)
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	writeOK(w, info, "已开启 ADB App 抓包")
}
func handleADBStop(w http.ResponseWriter, r *http.Request) {
	proxyPort := atoiDefault(r.URL.Query().Get("proxy"), 0)
	serial := strings.TrimSpace(r.URL.Query().Get("serial"))
	if serial == "" {
		serial = loadConfig().ADBSerial
	}
	if err := stopADBProxy(proxyPort, serial); err != nil {
		writeErr(w, err.Error())
		return
	}
	writeOK(w, nil, "已关闭 ADB App 抓包")
}
func handleADBDevices(w http.ResponseWriter, r *http.Request) {
	devs, err := adbDevices()
	if err != nil {
		writeErr(w, err.Error())
		return
	}
	writeOK(w, devs, "")
}
func handleOpenDir(w http.ResponseWriter, r *http.Request) {
	if serverMode() {
		writeErr(w, "服务器无桌面文件管理器，无法打开目录；路径见列表 StateDir 列")
		return
	}
	dir := r.URL.Query().Get("dir")
	if dir == "" {
		writeErr(w, "dir required")
		return
	}
	openURL(dir)
	writeOK(w, nil, "已打开目录")
}
func handleCopy(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("text")
	if text == "" {
		writeErr(w, "text required")
		return
	}
	copyText(text)
	writeOK(w, nil, "已复制")
}
func handleExit(w http.ResponseWriter, r *http.Request) {
	if systemdManaged() {
		writeErr(w, "本管理器由 systemd 托管（capx-manager.service），网页无法真正退出：进程退出后会被自动重启。如需彻底停止，请在服务器执行 systemctl stop capx-manager.service")
		return
	}
	writeOK(w, nil, "管理器已退出")
	go func() {
		time.Sleep(200 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		os.Exit(0)
	}()
}

// systemdManaged 表示本进程是否作为 systemd 服务单元启动。systemd 会为每个被
// 激活的单元设置 INVOCATION_ID，值非空即可可靠判断“网页退出”无法真正停止进程
// （Restart=always 会立即把它拉起）。
func systemdManaged() bool {
	return strings.TrimSpace(os.Getenv("INVOCATION_ID")) != ""
}
func writeOK(w http.ResponseWriter, data any, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(apiResp{OK: true, Data: data, Message: msg})
}
func writeErr(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(apiResp{OK: false, Error: msg})
}

func managerDir() string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "capx-web-manager")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".capx-web-manager")
}
func configPath() string { return filepath.Join(managerDir(), "manager.json") }
func exePath() string    { p, _ := os.Executable(); return p }
func projectRoot() string {
	packetRoot, _ := discoverLayout(filepath.Dir(exePath()))
	return packetRoot
}
func suiteRoot() string {
	_, root := discoverLayout(filepath.Dir(exePath()))
	return root
}
func suiteRootFromPacketRoot(root string) string {
	if strings.EqualFold(filepath.Base(root), "packet-capture") {
		return filepath.Dir(root)
	}
	return root
}
func directoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
func discoverLayout(start string) (packetRoot, repositoryRoot string) {
	start = filepath.Clean(start)
	for current, depth := start, 0; depth < 8; depth++ {
		if strings.EqualFold(filepath.Base(current), "packet-capture") &&
			directoryExists(filepath.Join(current, "capx")) {
			return current, filepath.Dir(current)
		}
		packet := filepath.Join(current, "packet-capture")
		if directoryExists(filepath.Join(packet, "capx")) {
			return packet, current
		}
		if directoryExists(filepath.Join(current, "capx")) &&
			directoryExists(filepath.Join(current, "capx-desktop")) {
			return current, current
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	packetRoot = filepath.Dir(start)
	return packetRoot, suiteRootFromPacketRoot(packetRoot)
}
func defaultCapturedPath() string {
	if runtime.GOOS != "windows" {
		for _, p := range []string{"/usr/local/bin/capx-captured", "/usr/bin/capx-captured"} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		if p, err := exec.LookPath("capx-captured"); err == nil {
			return p
		}
		return "/usr/local/bin/capx-captured"
	}
	root := projectRoot()
	cands := []string{
		filepath.Join(root, "capx-desktop", "build", "bin", "capx-captured.exe"),
		filepath.Join(root, "capx-desktop", "build", "bin", "capx-captured.next.exe"),
		filepath.Join(root, "capx-desktop", "build", "bin", "capx-captured.autonext.exe"),
		filepath.Join(root, "capx", "capx-captured.exe"),
	}
	for _, p := range cands {
		if _, err := os.Stat(p); err == nil {
			a, _ := filepath.Abs(p)
			return a
		}
	}
	return cands[0]
}
func defaultGhostPath() string {
	if runtime.GOOS != "windows" {
		for _, p := range []string{"/usr/local/bin/ghost", "/usr/bin/ghost"} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		if p, err := exec.LookPath("ghost"); err == nil {
			return p
		}
		return "/usr/local/bin/ghost"
	}
	root := suiteRoot()
	cands := []string{
		filepath.Join(root, "information-gathering", "bin", "ghost-verify.exe"),
		filepath.Join(root, "information-gathering", "bin", "Ghost.exe"),
		filepath.Join(root, "information-gathering", "ghost.exe"),
	}
	for _, p := range cands {
		if _, err := os.Stat(p); err == nil {
			a, _ := filepath.Abs(p)
			return a
		}
	}
	return cands[0]
}
func defaultADBPath() string {
	if runtime.GOOS != "windows" {
		if env := strings.TrimSpace(os.Getenv("ADB_PATH")); env != "" {
			return env
		}
		for _, p := range []string{"/usr/local/bin/adb", "/usr/bin/adb"} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
		if p, err := exec.LookPath("adb"); err == nil {
			return p
		}
		return "adb"
	}
	cands := []string{
		strings.TrimSpace(os.Getenv("ADB_PATH")),
		filepath.Join(suiteRoot(), ".codex", "adb", "adb.exe"),
		filepath.Join(suiteRoot(), "adb", "adb.exe"),
	}
	for _, p := range cands {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			a, _ := filepath.Abs(p)
			return a
		}
	}
	if p, err := exec.LookPath("adb.exe"); err == nil {
		return p
	}
	return "adb.exe"
}
func migrateCapturedPath(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	separator := string(filepath.Separator)
	oldMarker := separator + "capx-desktop" + separator
	newMarker := separator + "packet-capture" + separator + "capx-desktop" + separator
	candidate := strings.Replace(path, oldMarker, newMarker, 1)
	if candidate != path {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return path
}
func migrateGhostPath(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	root := filepath.Clean(suiteRoot())
	cleanPath := filepath.Clean(path)
	legacyDirectories := []string{root, filepath.Join(root, "bin")}
	legacy := false
	for _, directory := range legacyDirectories {
		if strings.EqualFold(filepath.Clean(filepath.Dir(cleanPath)), filepath.Clean(directory)) {
			legacy = true
			break
		}
	}
	if legacy {
		candidate := defaultGhostPath()
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return path
}
func loadConfig() config {
	c := config{CapturedPath: defaultCapturedPath(), GhostPath: defaultGhostPath(), ADBPath: defaultADBPath(), AutoPorts: true, AllowActive: true, Count: 1, ShowOnlyPath: true, OpenAfterStart: true}
	b, err := os.ReadFile(configPath())
	if err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if c.CapturedPath == "" {
		c.CapturedPath = defaultCapturedPath()
	} else {
		c.CapturedPath = migrateCapturedPath(c.CapturedPath)
	}
	if c.GhostPath == "" {
		c.GhostPath = defaultGhostPath()
	} else {
		c.GhostPath = migrateGhostPath(c.GhostPath)
	}
	if c.ADBPath == "" {
		c.ADBPath = defaultADBPath()
	}
	if c.Count == 0 {
		c.Count = 1
	}
	return c
}
func listenManager() (net.Listener, error) {
	addr := strings.TrimSpace(os.Getenv("CAPX_MANAGER_ADDR"))
	if addr == "" {
		addr = fmt.Sprintf("127.0.0.1:%d", defaultManagerPort)
	}
	host, _, splitErr := net.SplitHostPort(addr)
	if splitErr != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return nil, fmt.Errorf("CAPX_MANAGER_ADDR must be a loopback host:port")
	}
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, nil
	}
	url := "http://" + addr + "/"
	if pingManager(url) {
		openURL(url)
		os.Exit(0)
	}
	if os.Getenv("CAPX_MANAGER_ADDR") == "" {
		if fallback, fallbackErr := net.Listen("tcp", "127.0.0.1:0"); fallbackErr == nil {
			return fallback, nil
		}
	}
	return nil, fmt.Errorf("管理器地址 %s 已被占用且不是 capx Web Manager", addr)
}
func pingManager(baseURL string) bool {
	client := &http.Client{Timeout: 700 * time.Millisecond}
	resp, err := client.Get(strings.TrimRight(baseURL, "/") + "/api/ping")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var out apiResp
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return false
	}
	return out.OK
}
func stateDirForPort(p int) string {
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "capx", fmt.Sprintf("state-%d", p))
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".capx", fmt.Sprintf("state-%d", p))
}
func ghostPortForAPI(api int) int {
	p := api + 1000
	if p < 1 || p > 65535 {
		return 20080
	}
	return p
}
func portFree(p int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}
func atoiDefault(s string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return n
}
func startCapx(exe string, api, proxy int, allow bool) error {
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("capx-captured.exe 不存在: %s", exe)
	}
	if !portFree(api) {
		return fmt.Errorf("API 端口 %d 已被占用", api)
	}
	if !portFree(proxy) {
		return fmt.Errorf("代理端口 %d 已被占用", proxy)
	}
	state := stateDirForPort(api)
	logDir := filepath.Join(state, "logs")
	_ = os.MkdirAll(logDir, 0700)
	generation, err := newRuntimeGeneration()
	if err != nil {
		return err
	}
	args := []string{"--addr", fmt.Sprintf("127.0.0.1:%d", api), "--proxy", fmt.Sprintf("127.0.0.1:%d", proxy), "--state-dir", state, "--strict-addr", "--instance-id", fmt.Sprintf("legacy-%d", api), "--generation", generation}
	if allow {
		args = append(args, "--allow-active")
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = filepath.Dir(exe)
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = hiddenSysProcAttr()
	}
	stdout, _ := os.OpenFile(filepath.Join(logDir, "stdout.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	stderr, _ := os.OpenFile(filepath.Join(logDir, "stderr.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if stdout != nil {
		defer stdout.Close()
		cmd.Stdout = stdout
	}
	if stderr != nil {
		defer stderr.Close()
		cmd.Stderr = stderr
	}
	return cmd.Start()
}
func argValue(cmdline, name string) string {
	re := regexp.MustCompile(`(?i)(?:^|\s)--?` + regexp.QuoteMeta(name) + `(?:=|\s+)(?:"([^"]*)"|'([^']*)'|(\S+))`)
	m := re.FindStringSubmatch(cmdline)
	if len(m) == 0 {
		return ""
	}
	for i := 1; i < len(m); i++ {
		if m[i] != "" {
			return m[i]
		}
	}
	return ""
}
func portFromAddr(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	re := regexp.MustCompile(`:(\d+)$`)
	m := re.FindStringSubmatch(s)
	if len(m) > 1 {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}
func tokenText(state string) string {
	b, err := os.ReadFile(filepath.Join(state, "token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

const processQueryTimeout = 3 * time.Second

func getProcessInfos(script string) ([]procInfo, error) {
	return getProcessInfosWithin(script, processQueryTimeout)
}

func getProcessInfosWithin(script string, timeout time.Duration) ([]procInfo, error) {
	if timeout <= 0 {
		return nil, errors.New("positive process query timeout is required")
	}
	if runtime.GOOS != "windows" {
		// On Linux there is no WMI; enumerate /proc and let callers post-filter
		// by executable base name and/or PID (the WMI script is Windows-only).
		return platformEnumerateAllProcesses()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	ps := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", `[Console]::OutputEncoding=[Text.UTF8Encoding]::UTF8; `+script+` | Select-Object ProcessId,ExecutablePath,CommandLine | ConvertTo-Json -Compress`)
	if runtime.GOOS == "windows" {
		ps.SysProcAttr = hiddenSysProcAttr()
	}
	ps.WaitDelay = 500 * time.Millisecond
	out, err := ps.Output()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("PowerShell process query timed out after %s: %w", timeout, ctx.Err())
	}
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(out))
	infos := []procInfo{}
	if raw != "" {
		if strings.HasPrefix(raw, "[") {
			_ = json.Unmarshal([]byte(raw), &infos)
		} else {
			var one procInfo
			if json.Unmarshal([]byte(raw), &one) == nil && one.ProcessID != 0 {
				infos = append(infos, one)
			}
		}
	}
	return infos, nil
}

func powershellSingleQuoted(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func capxProcessQuery(pathFilter string, manifests []instanceManifest) (string, map[string]struct{}) {
	// "capx-captured.exe" is the Windows image name; "capx-captured" is the Linux
	// binary name (e.g. /usr/local/bin/capx-captured). Both are allowed so the
	// getInstances base-name post-filter matches on either platform. On Windows
	// the extra "capx-captured" WMI term matches nothing (image names carry .exe).
	names := map[string]struct{}{"capx-captured.exe": {}, "capx-captured": {}}
	if name := strings.ToLower(strings.TrimSpace(filepath.Base(pathFilter))); name != "" && name != "." {
		names[name] = struct{}{}
	}

	orderedNames := make([]string, 0, len(names))
	for name := range names {
		orderedNames = append(orderedNames, name)
	}
	sort.Strings(orderedNames)

	filterParts := make([]string, 0, len(orderedNames)+len(manifests))
	for _, name := range orderedNames {
		filterParts = append(filterParts, "Name='"+strings.ReplaceAll(name, "'", "''")+"'")
	}
	for _, manifest := range manifests {
		if manifest.PID > 0 {
			filterParts = append(filterParts, fmt.Sprintf("ProcessId=%d", manifest.PID))
		}
	}
	filter := strings.Join(filterParts, " OR ")
	return "Get-CimInstance Win32_Process -Filter " + powershellSingleQuoted(filter), names
}

func getInstances(pathFilter string, onlyPath bool) ([]instance, error) {
	manifests := listInstanceManifests()
	query, allowedNames := capxProcessQuery(pathFilter, manifests)
	infos, err := getProcessInfos(query)
	if err != nil {
		return managedInstancesFromManifests(manifests, pathFilter, onlyPath), nil
	}
	manifestByPID := make(map[int]instanceManifest, len(manifests))
	for _, manifest := range manifests {
		if manifest.PID > 0 {
			manifestByPID[manifest.PID] = manifest
		}
	}
	filtered := infos[:0]
	for _, info := range infos {
		if _, ok := allowedNames[strings.ToLower(filepath.Base(info.ExecutablePath))]; ok {
			filtered = append(filtered, info)
			continue
		}
		if manifest, ok := manifestByPID[info.ProcessID]; ok && managedCapxProcessInfoMatches(manifest, info) {
			filtered = append(filtered, info)
		}
	}
	infos = filtered
	ghosts, _ := getGhostMap()
	filterAbs := ""
	if pathFilter != "" {
		if a, err := filepath.Abs(pathFilter); err == nil {
			filterAbs = strings.ToLower(a)
		}
	}
	items := []instance{}
	for _, pi := range infos {
		exeAbs := pi.ExecutablePath
		if a, err := filepath.Abs(exeAbs); err == nil {
			exeAbs = a
		}
		if onlyPath && filterAbs != "" && strings.ToLower(exeAbs) != filterAbs {
			continue
		}
		addr := argValue(pi.CommandLine, "addr")
		proxy := argValue(pi.CommandLine, "proxy")
		state := argValue(pi.CommandLine, "state-dir")
		apiPort := portFromAddr(addr)
		proxyPort := portFromAddr(proxy)
		if state == "" && apiPort > 0 {
			state = stateDirForPort(apiPort)
		}
		it := instance{Status: "运行中", APIPort: apiPort, ProxyPort: proxyPort, PID: pi.ProcessID, Addr: addr, Proxy: proxy, StateDir: state, Token: tokenText(state), Exe: pi.ExecutablePath, CommandLine: pi.CommandLine, GhostPort: ghostPortForAPI(apiPort), GhostURL: fmt.Sprintf("http://127.0.0.1:%d/", ghostPortForAPI(apiPort)), GhostStatus: "未启动"}
		if manifest, ok := manifestForProcess(pi); ok {
			manifestPath, _ := instanceManifestPath(manifest.InstanceID)
			it.Status = "受管运行中"
			it.InstanceID = manifest.InstanceID
			it.ProjectDir = manifest.ProjectRoot
			it.Generation = manifest.Generation
			it.CDPPort = manifest.CDPPort
			it.BrowserPID = manifest.BrowserPID
			it.Manifest = manifestPath
		}
		if gi, ok := ghosts[apiPort]; ok {
			it.GhostPort = gi.Port
			it.GhostPID = gi.PID
			it.GhostURL = gi.URL
			it.GhostStatus = gi.Status
		}
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].APIPort == items[j].APIPort {
			return items[i].PID < items[j].PID
		}
		return items[i].APIPort < items[j].APIPort
	})
	return items, nil
}

var (
	managedFallbackProcessPath = processExecutablePath
	managedFallbackIdentity    = verifyManagedRuntimeIdentity
)

func managedInstancesFromManifests(manifests []instanceManifest, pathFilter string, onlyPath bool) []instance {
	items := []instance{}
	for _, manifest := range manifests {
		if !manifest.IdentityRequired || manifest.PID <= 0 || strings.TrimSpace(manifest.Generation) == "" {
			continue
		}
		if err := managedFallbackIdentity(manifest); err != nil {
			continue
		}
		executablePath, err := managedFallbackProcessPath(manifest.PID)
		if err != nil || !fallbackPathMatches(executablePath, pathFilter, onlyPath) {
			continue
		}
		apiPort := portFromAddr(manifest.APIBase)
		proxyPort := portFromAddr(manifest.Proxy)
		manifestPath, _ := instanceManifestPath(manifest.InstanceID)
		items = append(items, instance{
			Status:      "受管运行中",
			InstanceID:  manifest.InstanceID,
			ProjectDir:  manifest.ProjectRoot,
			Generation:  manifest.Generation,
			APIPort:     apiPort,
			ProxyPort:   proxyPort,
			CDPPort:     manifest.CDPPort,
			PID:         manifest.PID,
			BrowserPID:  manifest.BrowserPID,
			Manifest:    manifestPath,
			Addr:        trimEndpointScheme(manifest.APIBase),
			Proxy:       trimEndpointScheme(manifest.Proxy),
			StateDir:    manifest.StateDir,
			Token:       tokenText(manifest.StateDir),
			Exe:         executablePath,
			GhostPort:   ghostPortForAPI(apiPort),
			GhostURL:    fmt.Sprintf("http://127.0.0.1:%d/", ghostPortForAPI(apiPort)),
			GhostStatus: "未启动",
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].APIPort == items[j].APIPort {
			return items[i].PID < items[j].PID
		}
		return items[i].APIPort < items[j].APIPort
	})
	return items
}

func fallbackPathMatches(executablePath, pathFilter string, onlyPath bool) bool {
	if !onlyPath || strings.TrimSpace(pathFilter) == "" {
		return true
	}
	executableAbs, executableErr := filepath.Abs(executablePath)
	filterAbs, filterErr := filepath.Abs(pathFilter)
	return executableErr == nil && filterErr == nil && strings.EqualFold(executableAbs, filterAbs)
}

func trimEndpointScheme(endpoint string) string {
	value := strings.TrimSpace(endpoint)
	value = strings.TrimPrefix(value, "http://")
	return strings.TrimPrefix(value, "https://")
}

func ghostStateDir(apiPort int, stateDir string) string {
	if stateDir != "" {
		return filepath.Join(stateDir, "ghost")
	}
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "capx", fmt.Sprintf("ghost-%d", apiPort))
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".capx", fmt.Sprintf("ghost-%d", apiPort))
}
func ghostConfigPath(apiPort int, stateDir string) string {
	return filepath.Join(ghostStateDir(apiPort, stateDir), fmt.Sprintf("config-api-%d.yaml", apiPort))
}
func apiPortFromGhostCommand(cmdline string) int {
	cfgPath := argValue(cmdline, "config")
	re := regexp.MustCompile(`(?i)config-api-(\d+)\.ya?ml`)
	if m := re.FindStringSubmatch(cfgPath); len(m) > 1 {
		return atoiDefault(m[1], 0)
	}
	addr := argValue(cmdline, "addr")
	if p := portFromAddr(addr); p > 1000 {
		return p - 1000
	}
	return 0
}
func ghostExecutable(executablePath string) bool {
	normalized := strings.ReplaceAll(strings.TrimSpace(executablePath), `\`, "/")
	base := strings.ToLower(filepath.Base(normalized))
	return base == "ghost.exe" || base == "ghost"
}

func getGhostMap() (map[int]ghostInfo, error) {
	infos, err := getProcessInfos(`Get-CimInstance Win32_Process -Filter "name='ghost.exe'"`)
	if err != nil {
		return nil, err
	}
	out := map[int]ghostInfo{}
	for _, pi := range infos {
		// On Linux getProcessInfos returns every process (no WMI name pre-filter),
		// so re-check the executable base name here. On Windows this is redundant
		// with the WMI "name='ghost.exe'" filter but harmless.
		if !ghostExecutable(pi.ExecutablePath) {
			continue
		}
		apiPort := apiPortFromGhostCommand(pi.CommandLine)
		if apiPort <= 0 {
			continue
		}
		addr := argValue(pi.CommandLine, "addr")
		port := portFromAddr(addr)
		if port <= 0 {
			port = ghostPortForAPI(apiPort)
		}
		url := fmt.Sprintf("http://127.0.0.1:%d/", port)
		out[apiPort] = ghostInfo{Port: port, PID: pi.ProcessID, URL: url, Status: "运行中", CommandLine: pi.CommandLine}
	}
	return out, nil
}
func findGhostByAPIPort(apiPort int) (ghostInfo, bool) {
	m, err := getGhostMap()
	if err != nil {
		return ghostInfo{}, false
	}
	gi, ok := m[apiPort]
	return gi, ok
}
func ghostHealth(url string) bool {
	client := &http.Client{Timeout: 900 * time.Millisecond}
	resp, err := client.Get(strings.TrimRight(url, "/") + "/api/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
func findNextFreePort(start int) (int, error) {
	for p := start; p < 65535; p++ {
		if portFree(p) {
			return p, nil
		}
	}
	return 0, fmt.Errorf("没有找到空闲端口")
}
func writeGhostConfig(apiPort, proxyPort int, stateDir string) (string, error) {
	cfgPath := ghostConfigPath(apiPort, stateDir)
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0700); err != nil {
		return "", err
	}
	doc := map[string]any{}
	basePath := filepath.Join(suiteRoot(), "information-gathering", "config.yaml")
	if b, err := os.ReadFile(basePath); err == nil && len(b) > 0 {
		_ = yaml.Unmarshal(b, &doc)
	}
	if doc == nil {
		doc = map[string]any{}
	}
	// 不把代理写进 Ghost 配置文件；直接通过进程环境变量注入。
	// 这样可以避免 Ghost runner 自动套用默认 NO_PROXY 导致 fofa/quake 等国内接口绕过 capx。
	delete(doc, "proxy")
	delete(doc, "proxies")
	runnerCfg, _ := doc["runner"].(map[string]any)
	if runnerCfg == nil {
		runnerCfg = map[string]any{}
	}
	runnerCfg["proxy"] = ""
	if _, ok := runnerCfg["timeout"]; !ok {
		runnerCfg["timeout"] = 60
	}
	if _, ok := runnerCfg["max_concurrency"]; !ok {
		runnerCfg["max_concurrency"] = 8
	}
	doc["runner"] = runnerCfg
	b, err := yaml.Marshal(doc)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(cfgPath, b, 0600); err != nil {
		return "", err
	}
	return cfgPath, nil
}
func ensureGhost(apiPort, proxyPort int, stateDir string) (ghostInfo, error) {
	if gi, ok := findGhostByAPIPort(apiPort); ok {
		if ghostHealth(gi.URL) {
			return gi, nil
		}
		return gi, nil
	}
	exe := loadConfig().GhostPath
	if exe == "" {
		exe = defaultGhostPath()
	}
	if _, err := os.Stat(exe); err != nil {
		return ghostInfo{}, fmt.Errorf("ghost.exe 不存在: %s", exe)
	}
	cfgPath, err := writeGhostConfig(apiPort, proxyPort, stateDir)
	if err != nil {
		return ghostInfo{}, fmt.Errorf("写 Ghost 配置失败: %w", err)
	}
	gdir := ghostStateDir(apiPort, stateDir)
	logDir := filepath.Join(gdir, "logs")
	_ = os.MkdirAll(logDir, 0700)
	port := ghostPortForAPI(apiPort)
	if !portFree(port) {
		port, err = findNextFreePort(port + 1)
		if err != nil {
			return ghostInfo{}, err
		}
	}
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", proxyPort)
	args := []string{"server", "--addr", fmt.Sprintf("127.0.0.1:%d", port), "--config", cfgPath}
	cmd := exec.Command(exe, args...)
	cmd.Dir = gdir
	cmd.Env = upsertEnv(os.Environ(), map[string]string{
		"HTTP_PROXY":      proxyURL,
		"HTTPS_PROXY":     proxyURL,
		"ALL_PROXY":       proxyURL,
		"NO_PROXY":        "localhost,127.0.0.1,::1",
		"no_proxy":        "localhost,127.0.0.1,::1",
		"GHOST_CACHE_DIR": filepath.Join(gdir, "cache"),
	})
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = hiddenSysProcAttr()
	}
	stdout, _ := os.OpenFile(filepath.Join(logDir, "stdout.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	stderr, _ := os.OpenFile(filepath.Join(logDir, "stderr.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if stdout != nil {
		defer stdout.Close()
		cmd.Stdout = stdout
	}
	if stderr != nil {
		defer stderr.Close()
		cmd.Stderr = stderr
	}
	if err := cmd.Start(); err != nil {
		return ghostInfo{}, err
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	for i := 0; i < 20; i++ {
		if ghostHealth(url) {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	return ghostInfo{Port: port, PID: cmd.Process.Pid, URL: url, Status: "运行中", StateDir: gdir, ProxyPort: proxyPort}, nil
}
func upsertEnv(base []string, kv map[string]string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(base)+len(kv))
	for _, e := range base {
		k := e
		if i := strings.Index(e, "="); i >= 0 {
			k = e[:i]
		}
		if v, ok := kv[k]; ok {
			out = append(out, k+"="+v)
			seen[k] = true
		} else {
			out = append(out, e)
		}
	}
	for k, v := range kv {
		if !seen[k] {
			out = append(out, k+"="+v)
		}
	}
	return out
}
func browserProfileDir(apiPort, proxyPort int) string {
	name := fmt.Sprintf("browser-%d-%d", apiPort, proxyPort)
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "capx", name)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".capx", name)
}
func findBrowserExe() string {
	cands := []string{}
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		cands = append(cands,
			filepath.Join(pf, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
		)
	}
	if pf := os.Getenv("ProgramFiles(x86)"); pf != "" {
		cands = append(cands,
			filepath.Join(pf, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
		)
	}
	if la := os.Getenv("LOCALAPPDATA"); la != "" {
		cands = append(cands,
			filepath.Join(la, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(la, "Microsoft", "Edge", "Application", "msedge.exe"),
		)
	}
	for _, p := range cands {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
func openProxyBrowser(apiPort, proxyPort int) error {
	browser := findBrowserExe()
	if browser == "" {
		return fmt.Errorf("未找到 Chrome/Edge 浏览器")
	}
	profile := browserProfileDir(apiPort, proxyPort)
	_ = os.MkdirAll(profile, 0700)
	proxyAddr := "127.0.0.1:" + strconv.Itoa(proxyPort)
	args := []string{
		"--user-data-dir=" + profile,
		"--proxy-server=http=" + proxyAddr + ";https=" + proxyAddr,
		"--proxy-bypass-list=<-loopback>",
		"--disable-quic",
		"--disable-http3",
		"--disable-features=DnsOverHttps,UseDnsHttpsSvcbAlpn",
		"--disable-extensions",
		"--disable-background-networking",
		"--disable-sync",
		"--hide-crash-restore-bubble",
		"--no-first-run",
		"--new-window",
		fmt.Sprintf("http://127.0.0.1:%d/#proxy", apiPort),
	}
	if os.Getenv("CAPX_MANAGER_BROWSER_HEADLESS") == "1" {
		args = append([]string{"--headless=new", "--disable-gpu"}, args...)
	}
	cmd := exec.Command(browser, args...)
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = hiddenSysProcAttr()
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = cmd.Process.Release()
	profileFlag := "--user-data-dir=" + profile
	proxyFlag := "--proxy-server=http=" + proxyAddr + ";https=" + proxyAddr
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		infos, err := getProcessInfos(`Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('chrome.exe','msedge.exe') }`)
		if err == nil {
			for _, info := range infos {
				line := strings.ToLower(info.CommandLine)
				if strings.Contains(line, strings.ToLower(profileFlag)) && strings.Contains(line, strings.ToLower(proxyFlag)) {
					session := browserSession{
						APIPort: apiPort, ProxyPort: proxyPort, PID: info.ProcessID,
						Executable: info.ExecutablePath, CommandLine: info.CommandLine,
						ProfileDir: profile, StartedAt: sessionStartedAt(),
					}
					if err := recordBrowserSession(session); err != nil {
						_, _ = terminateProcessVerified(info.ProcessID, func(current procInfo) bool {
							return sameCanonicalPath(current.ExecutablePath, info.ExecutablePath) && current.CommandLine == info.CommandLine
						})
						return fmt.Errorf("登记代理浏览器会话失败: %w", err)
					}
					return nil
				}
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fmt.Errorf("代理浏览器已启动，但无法确认 profile 所属进程")
}
func openURL(s string) { _ = openSystemTarget(s) }
func clipboardCommand(s string) *exec.Cmd {
	cmd := exec.Command(
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
		"$value = [Console]::In.ReadToEnd(); Set-Clipboard -Value $value",
	)
	cmd.Stdin = strings.NewReader(s)
	return cmd
}
func copyText(s string) {
	if runtime.GOOS == "windows" {
		cmd := clipboardCommand(s)
		cmd.SysProcAttr = hiddenSysProcAttr()
		_ = cmd.Run()
	}
}

type adbProxyInfo struct {
	Serial    string `json:"serial"`
	Proxy     string `json:"proxy"`
	Reverse   string `json:"reverse"`
	DeviceOut string `json:"device_out,omitempty"`
}

func adbExe() string {
	if path := loadConfig().ADBPath; path != "" {
		return path
	}
	return defaultADBPath()
}
func adbBaseArgs(serial string, args ...string) []string {
	out := []string{}
	if strings.TrimSpace(serial) != "" {
		out = append(out, "-s", strings.TrimSpace(serial))
	}
	out = append(out, args...)
	return out
}
func adbRun(serial string, args ...string) (string, error) {
	exe := adbExe()
	if _, err := os.Stat(exe); err != nil && !strings.EqualFold(exe, "adb.exe") {
		return "", fmt.Errorf("adb.exe 不存在: %s", exe)
	}
	cmd := exec.Command(exe, adbBaseArgs(serial, args...)...)
	if exe != "adb.exe" {
		cmd.Dir = filepath.Dir(exe)
	}
	if runtime.GOOS == "windows" {
		cmd.SysProcAttr = hiddenSysProcAttr()
	}
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if s == "" {
			s = err.Error()
		}
		return s, fmt.Errorf("%s", s)
	}
	return s, nil
}

var adbCommandRunner = adbRun

func adbDevices() ([]string, error) {
	out, err := adbRun("", "devices")
	if err != nil {
		return nil, err
	}
	devs := []string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "list of devices") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "device" {
			devs = append(devs, fields[0])
		}
	}
	return devs, nil
}
func effectiveADBSerial(serial string) (string, error) {
	serial = strings.TrimSpace(serial)
	if serial != "" {
		return serial, nil
	}
	devs, err := adbDevices()
	if err != nil {
		return "", err
	}
	if len(devs) == 0 {
		return "", fmt.Errorf("没有检测到 Android 设备；请先 USB 连接并授权 adb")
	}
	if len(devs) > 1 {
		return "", fmt.Errorf("检测到多个设备，请在 ADB设备 填 serial：%s", strings.Join(devs, ", "))
	}
	return devs[0], nil
}
func startADBProxy(proxyPort int, serial string) (adbProxyInfo, error) {
	serial, err := effectiveADBSerial(serial)
	if err != nil {
		return adbProxyInfo{}, err
	}
	port := strconv.Itoa(proxyPort)
	if out, err := adbRun(serial, "reverse", "tcp:"+port, "tcp:"+port); err != nil {
		return adbProxyInfo{}, fmt.Errorf("adb reverse 失败: %s", out)
	}
	proxy := "127.0.0.1:" + port
	out, err := adbRun(serial, "shell", "settings", "put", "global", "http_proxy", proxy)
	if err != nil {
		return adbProxyInfo{}, fmt.Errorf("设置设备代理失败: %s", out)
	}
	replaced, err := recordADBSession(adbSession{Serial: serial, ProxyPort: proxyPort, StartedAt: sessionStartedAt()})
	if err != nil {
		_, _ = adbRun(serial, "shell", "settings", "delete", "global", "http_proxy")
		_, _ = adbRun(serial, "reverse", "--remove", "tcp:"+port)
		return adbProxyInfo{}, fmt.Errorf("登记 ADB 抓包会话失败: %w", err)
	}
	for _, previous := range replaced {
		if previous.ProxyPort != proxyPort {
			if _, cleanupErr := adbRun(serial, "reverse", "--remove", "tcp:"+strconv.Itoa(previous.ProxyPort)); cleanupErr != nil {
				_ = ensureADBSession(previous)
			}
		}
	}
	current := loadConfig()
	current.ADBSerial = serial
	_ = saveConfig(current)
	return adbProxyInfo{Serial: serial, Proxy: proxy, Reverse: "tcp:" + port + " -> tcp:" + port, DeviceOut: out}, nil
}
func stopADBProxy(proxyPort int, serial string) error {
	serial, err := effectiveADBSerial(serial)
	if err != nil {
		return err
	}
	failures := stopRecordedADB(proxyPort, serial)
	return errors.Join(failures...)
}
