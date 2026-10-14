package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails-bound backend. It talks to a running capx instance over its
// REST API (default http://127.0.0.1:19091), and can also start/stop the local
// capx backend so the user never has to launch capx by hand. Bound methods are
// callable from the frontend as window.go.main.App.<Method>().
type App struct {
	ctx             context.Context
	mu              sync.Mutex
	lifecycleMu     sync.Mutex
	base            string
	proxyAddr       string
	token           string
	hc              *http.Client
	cmd             *exec.Cmd
	streamConnected bool
}

type desktopSettings struct {
	BaseURL   string `json:"base_url,omitempty"`
	ProxyAddr string `json:"proxy_addr,omitempty"`
}

type desktopRuntime struct {
	BaseURL    string `json:"base_url,omitempty"`
	ProxyAddr  string `json:"proxy_addr,omitempty"`
	StateDir   string `json:"state_dir,omitempty"`
	PID        int    `json:"pid,omitempty"`
	StartedAt  string `json:"started_at,omitempty"`
	TokenFile  string `json:"token_file,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
	Generation string `json:"generation,omitempty"`
	Exe        string `json:"exe,omitempty"`
}

func NewApp() *App {
	settings := readDesktopSettings()
	runtime := readDesktopRuntime()
	usingRuntime := false
	base := normalizeBaseURL(strings.TrimSpace(os.Getenv("CAPX_BASE")))
	if base == "" {
		base = normalizeBaseURL(settings.BaseURL)
	}
	if base == "" {
		// 如果上次是“自动端口”启动，并且桌面窗口被关闭后后台 capx 仍在，
		// 重新打开桌面端时优先接回上次那个后端，避免又分配一个新端口。
		if rb := normalizeBaseURL(runtime.BaseURL); rb != "" && runtimeHealthOK(runtime, 900*time.Millisecond) {
			base = rb
			usingRuntime = true
		}
	}
	if base == "" {
		// 多开桌面端时，不再强占固定 19091；若默认端口已被另一个
		// capx 实例占用，则自动向后寻找空闲端口。19092 预留给 native hook。
		base = "http://" + chooseFreeTCPAddr("127.0.0.1", 19091, 100, map[int]bool{19092: true})
	}
	proxy := strings.TrimSpace(os.Getenv("CAPX_PROXY"))
	if proxy == "" {
		proxy = normalizeTCPAddr(settings.ProxyAddr)
	}
	if proxy == "" && usingRuntime {
		proxy = normalizeTCPAddr(runtime.ProxyAddr)
	}
	if proxy == "" {
		// 同理，MITM 代理也自动避开 18080 冲突，便于多个实例同时抓包。
		proxy = chooseFreeTCPAddr("127.0.0.1", 18080, 100, nil)
	}
	return &App{
		base:      strings.TrimRight(base, "/"),
		proxyAddr: proxy,
		token:     readTokenFor(base),
		hc:        &http.Client{Timeout: 15 * time.Second},
	}
}

func settingsPath() string {
	if v := strings.TrimSpace(os.Getenv("CAPX_DESKTOP_SETTINGS")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); v != "" {
		return filepath.Join(v, "capx-desktop", "settings.json")
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".capx-desktop", "settings.json")
	}
	return "capx-desktop-settings.json"
}

func runtimePath() string {
	p := settingsPath()
	if dir := filepath.Dir(p); dir != "." && dir != "" {
		return filepath.Join(dir, "runtime.json")
	}
	return "capx-desktop-runtime.json"
}

func readDesktopSettings() desktopSettings {
	var s desktopSettings
	b, err := os.ReadFile(settingsPath())
	if err != nil {
		return s
	}
	_ = json.Unmarshal(b, &s)
	return s
}

func saveDesktopSettings(s desktopSettings) error {
	p := settingsPath()
	if dir := filepath.Dir(p); dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(p, b, 0o644)
}

func readDesktopRuntime() desktopRuntime {
	var rt desktopRuntime
	b, err := os.ReadFile(runtimePath())
	if err != nil {
		return rt
	}
	_ = json.Unmarshal(b, &rt)
	return rt
}

func saveDesktopRuntime(rt desktopRuntime) error {
	p := runtimePath()
	if dir := filepath.Dir(p); dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	b, _ := json.MarshalIndent(rt, "", "  ")
	return os.WriteFile(p, b, 0o644)
}

func clearDesktopRuntime() {
	_ = os.Remove(runtimePath())
}

func capxHealthOK(base string, timeout time.Duration) bool {
	_, err := fetchCapxHealth(base, timeout)
	return err == nil
}

func normalizeBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	return strings.TrimRight(raw, "/")
}

func normalizeTCPAddr(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.EqualFold(raw, "auto") || raw == "自动" {
		return ""
	}
	if _, err := strconv.Atoi(raw); err == nil {
		raw = net.JoinHostPort("127.0.0.1", raw)
	}
	if strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil {
			raw = u.Host
		}
	}
	host, port, err := net.SplitHostPort(raw)
	if err != nil || strings.TrimSpace(port) == "" {
		return ""
	}
	if strings.TrimSpace(host) == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func resolveBaseInput(raw string) (currentBase, storedBase string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "auto") || raw == "自动" {
		return "http://" + chooseFreeTCPAddr("127.0.0.1", 19091, 100, map[int]bool{19092: true}), "", nil
	}
	if _, convErr := strconv.Atoi(raw); convErr == nil {
		raw = net.JoinHostPort("127.0.0.1", raw)
	}
	base := normalizeBaseURL(raw)
	u, parseErr := url.Parse(base)
	if parseErr != nil || strings.TrimSpace(u.Host) == "" {
		return "", "", fmt.Errorf("REST API 地址格式不对，可填 19091 或 127.0.0.1:19091")
	}
	if _, port, splitErr := net.SplitHostPort(u.Host); splitErr != nil || strings.TrimSpace(port) == "" {
		return "", "", fmt.Errorf("REST API 地址需要包含端口，例如 19091 或 127.0.0.1:19091")
	}
	normalized := "http://" + u.Host
	return normalized, normalized, nil
}

func resolveProxyInput(raw string) (currentProxy, storedProxy string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "auto") || raw == "自动" {
		return chooseFreeTCPAddr("127.0.0.1", 18080, 100, nil), "", nil
	}
	addr := normalizeTCPAddr(raw)
	if addr == "" {
		return "", "", fmt.Errorf("代理地址格式不对，可填 18080 或 127.0.0.1:18080")
	}
	return addr, addr, nil
}

func chooseFreeTCPAddr(host string, preferred, attempts int, skip map[int]bool) string {
	if strings.TrimSpace(host) == "" {
		host = "127.0.0.1"
	}
	if attempts <= 0 {
		attempts = 1
	}
	for p := preferred; p < preferred+attempts; p++ {
		if skip != nil && skip[p] {
			continue
		}
		addr := net.JoinHostPort(host, strconv.Itoa(p))
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			_ = ln.Close()
			return addr
		}
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err == nil {
		addr := ln.Addr().String()
		_ = ln.Close()
		if _, port, splitErr := net.SplitHostPort(addr); splitErr == nil {
			return net.JoinHostPort(host, port)
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(preferred))
}

func baseListenAddr(base string) string {
	u, err := url.Parse(normalizeBaseURL(base))
	if err == nil && u.Host != "" {
		return u.Host
	}
	return strings.TrimPrefix(strings.TrimPrefix(strings.TrimRight(base, "/"), "http://"), "https://")
}

func basePort(base string) string {
	hostPort := baseListenAddr(base)
	if _, p, err := net.SplitHostPort(hostPort); err == nil {
		return p
	}
	if strings.Contains(hostPort, ":") {
		parts := strings.Split(hostPort, ":")
		return parts[len(parts)-1]
	}
	return ""
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.streamLoop()
}

// streamLoop subscribes to capx's SSE event stream and forwards events to the
// frontend (Wails event "capx:event"), so the UI updates live instead of polling.
// It auto-reconnects when capx is down or the stream drops.
func (a *App) streamLoop() {
	client := &http.Client{} // no timeout: this is a long-lived stream
	for {
		if a.ctx == nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if a.ctx.Err() != nil {
			return
		}
		base, token := a.connection()
		req, err := http.NewRequestWithContext(a.ctx, http.MethodGet, base+"/api/stream", nil)
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		req.Header.Set("Accept", "text/event-stream")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("X-Capx-Token", token)
		}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode >= 400 {
			if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
				a.refreshToken()
			}
			if resp != nil {
				resp.Body.Close()
			}
			wruntime.EventsEmit(a.ctx, "capx:stream", "down")
			a.setStreamStatus(false)
			time.Sleep(3 * time.Second)
			continue
		}
		a.setStreamStatus(true)
		wruntime.EventsEmit(a.ctx, "capx:stream", "up")
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "data:") {
				wruntime.EventsEmit(a.ctx, "capx:event", strings.TrimSpace(line[5:]))
			}
		}
		resp.Body.Close()
		wruntime.EventsEmit(a.ctx, "capx:stream", "down")
		time.Sleep(2 * time.Second)
	}
}

func readToken() string {
	if t := strings.TrimSpace(os.Getenv("CAPX_TOKEN")); t != "" {
		return t
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(home, ".capx", "token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (a *App) do(method, path string, body []byte) (string, error) {
	out, status, err := a.doOnce(method, path, body)
	if err != nil {
		return "", err
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		a.refreshToken()
		out, status, err = a.doOnce(method, path, body)
		if err != nil {
			return "", err
		}
	}
	if status >= 400 {
		return "", fmt.Errorf("capx 返回 %d：%s", status, truncate(out, 300))
	}
	return out, nil
}

func (a *App) doOnce(method, path string, body []byte) (string, int, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	base, token := a.connection()
	req, err := http.NewRequest(method, base+path, rdr)
	if err != nil {
		return "", 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" && path != "/health" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Capx-Token", token)
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("连接 capx 失败（%s 是否在运行？）：%w", base, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return string(out), resp.StatusCode, nil
}
func (a *App) get(path string) (string, error) { return a.do(http.MethodGet, path, nil) }
func (a *App) post(path string, body []byte) (string, error) {
	return a.do(http.MethodPost, path, body)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// findCapxExe locates capx-captured.exe (env CAPX_EXE, next to this exe, or the
// dev repo layout: <root>/packet-capture/capx/capx-captured.exe).
func findCapxExe() string {
	if e := strings.TrimSpace(os.Getenv("CAPX_EXE")); fileExists(e) {
		return e
	}
	self, _ := os.Executable()
	cwd, _ := os.Getwd()
	cands := backendCandidates(runtime.GOOS, self, cwd)
	for _, c := range cands {
		if fileExists(c) {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	return ""
}

func defaultStateDir(base string) string {
	if v := strings.TrimSpace(os.Getenv("CAPX_STATE_DIR")); v != "" {
		return v
	}
	name := "state"
	if p := basePort(base); p != "" && p != "19091" {
		name = "state-" + p
	}
	if v := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); v != "" {
		return filepath.Join(v, "capx", name)
	}
	if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".capx", name)
	}
	return ""
}

func backendPIDFile(stateDir string) string {
	if strings.TrimSpace(stateDir) == "" {
		return ""
	}
	return filepath.Join(stateDir, "capx-captured.pid")
}

func writeBackendPID(stateDir string, pid int) error {
	if strings.TrimSpace(stateDir) == "" || pid <= 0 {
		return nil
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(backendPIDFile(stateDir), []byte(strconv.Itoa(pid)), 0o644)
}

func readBackendPID(stateDir string) (int, string, error) {
	pidPath := backendPIDFile(stateDir)
	if pidPath == "" {
		return 0, "", fmt.Errorf("state dir is empty")
	}
	b, err := os.ReadFile(pidPath)
	if err != nil {
		return 0, pidPath, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0, pidPath, fmt.Errorf("bad pid file: %s", pidPath)
	}
	return pid, pidPath, nil
}

// ---- backend lifecycle (bound) ----

// CapxRunning reports whether capx REST answers /health quickly.
func (a *App) CapxRunning() bool {
	base, _ := a.connection()
	if !runtimeHealthOK(runtimeForBase(base), 2*time.Second) {
		return false
	}
	a.refreshToken()
	_, token := a.connection()
	req, err := http.NewRequest(http.MethodGet, base+"/api/policy", nil)
	if err != nil {
		return false
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// StartCapx launches the local capx backend (REST a.base + MITM a.proxyAddr) if
// it isn't already running, and waits briefly for it to become healthy.
func (a *App) StartCapx() (string, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if a.CapxRunning() {
		return "capx 已在运行 ✓", nil
	}
	if capxHealthOK(a.base, time.Second) {
		return "", fmt.Errorf("端口已有 Capx，但当前实例认证或身份校验失败；未启动替换进程")
	}
	exe := findCapxExe()
	if exe == "" {
		return "", fmt.Errorf("未找到 capx-captured.exe（请设环境变量 CAPX_EXE 指向它，或把它放到桌面端 exe 同目录）")
	}
	addr := baseListenAddr(a.base)
	// --allow-active enables the active primitives (memory write/freeze, etc.) so
	// the desktop's 内存 tab can edit/freeze values like Cheat Engine out of the box.
	generation := newDesktopGeneration()
	instanceID := "desktop-" + basePort(a.base)
	args := []string{"--addr", addr, "--proxy", a.proxyAddr, "--allow-active", "--strict-addr", "--instance-id", instanceID, "--generation", generation}
	stateDir := defaultStateDir(a.base)
	if stateDir != "" {
		_ = os.MkdirAll(stateDir, 0o755)
		args = append(args, "--state-dir", stateDir)
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = filepath.Dir(exe)
	cmd.Env = os.Environ()
	detachBackendProcess(cmd) // 后端独立常驻：关闭桌面窗口不跟着退出
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("启动失败：%w", err)
	}
	pid := cmd.Process.Pid
	_ = writeBackendPID(stateDir, pid)
	_ = saveDesktopRuntime(desktopRuntime{
		BaseURL:    a.base,
		ProxyAddr:  a.proxyAddr,
		StateDir:   stateDir,
		PID:        pid,
		StartedAt:  time.Now().Format(time.RFC3339),
		TokenFile:  filepath.Join(stateDir, "token"),
		InstanceID: instanceID, Generation: generation, Exe: exe,
	})
	// 不 Wait 后端，也不把生命周期绑在 Wails 桌面进程上；Release 只释放
	// 当前桌面端持有的进程句柄，capx-captured.exe 会继续在后台运行。
	_ = cmd.Process.Release()
	a.mu.Lock()
	a.cmd = nil
	a.mu.Unlock()
	a.refreshToken() // capx writes/refreshes ~/.capx/token on start
	for i := 0; i < 24; i++ {
		time.Sleep(350 * time.Millisecond)
		if health, healthErr := fetchCapxHealth(a.base, time.Second); healthErr == nil && health.Identity.Generation == generation && health.Identity.InstanceID == instanceID {
			a.refreshToken()
			return "capx 已启动 ✓（后台常驻，关闭桌面窗口不会停止）", nil
		}
	}
	return "", fmt.Errorf("capx 未在预期端口就绪；请检查后台日志和端口占用")
}

// StopCapx terminates the local capx backend for this instance only.
func (a *App) StopCapx() (string, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	base, _ := a.connection()
	rt := runtimeForBase(base)
	var proc backendStopProcess
	if rt.PID > 0 && rt.Generation != "" && rt.Exe != "" {
		var err error
		proc, err = openOwnedBackend(rt)
		if err != nil {
			return "", fmt.Errorf("无法确认后台进程身份，未停止：%w", err)
		}
		if proc != nil {
			defer proc.Close()
		}
	}
	a.refreshToken()
	_, token := a.connection()
	if err := stopCapxRuntime(base, token, rt, proc, 20*time.Second); err != nil {
		return "", err
	}
	if rt.PID > 0 {
		clearRuntimeIfMatch(rt)
	}
	return "capx 已停止", nil
}

// ---- data (bound) ----

func (a *App) BaseURL() string   { base, _ := a.connection(); return base }
func (a *App) ProxyAddr() string { a.mu.Lock(); defer a.mu.Unlock(); return a.proxyAddr }

// ConfigurePorts updates the desktop-selected capx REST API and MITM proxy
// ports. apiAddr/proxyAddr may be a bare port ("19093"), host:port, full API URL
// for the REST endpoint, or empty/"auto" to keep automatic conflict avoidance.
func (a *App) ConfigurePorts(apiAddr, proxyAddr string) (string, error) {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if a.CapxRunning() {
		return "", fmt.Errorf("请先停止当前 capx，再修改端口")
	}
	base, storedBase, err := resolveBaseInput(apiAddr)
	if err != nil {
		return "", err
	}
	proxy, storedProxy, err := resolveProxyInput(proxyAddr)
	if err != nil {
		return "", err
	}
	a.mu.Lock()
	a.base = strings.TrimRight(base, "/")
	a.proxyAddr = proxy
	a.token = readTokenFor(base)
	a.mu.Unlock()
	if err := saveDesktopSettings(desktopSettings{BaseURL: storedBase, ProxyAddr: storedProxy}); err != nil {
		return "", fmt.Errorf("端口已应用，但保存设置失败：%w", err)
	}
	mode := "已自定义"
	if storedBase == "" && storedProxy == "" {
		mode = "已切回自动分配"
	}
	return fmt.Sprintf("%s：REST %s，代理 %s", mode, a.base, a.proxyAddr), nil
}

func (a *App) Health() (string, error)      { return a.get("/health") }
func (a *App) Flows() (string, error)       { return a.get("/api/flows") }
func (a *App) PassiveScan() (string, error) { return a.get("/api/scan/passive") }
func (a *App) ProxyStatus() (string, error) { return a.get("/api/proxy/status") }

func (a *App) ListHTTP(scheme string) (string, error) {
	p := "/api/http"
	if s := strings.TrimSpace(scheme); s != "" {
		p += "?scheme=" + s
	}
	return a.get(p)
}

// ---- repeater (bound) ----

// Repeater replays a raw HTTP request to host over scheme through capx
// (POST /api/repeater/send) and returns the response JSON.
func (a *App) Repeater(scheme, host, raw string) (string, error) {
	if strings.TrimSpace(scheme) == "" {
		scheme = "https"
	}
	body, _ := json.Marshal(map[string]any{"scheme": scheme, "host": host, "raw": raw})
	return a.post("/api/repeater/send", body)
}

// ---- match & replace rules (bound) ----

func (a *App) ListRules() (string, error)              { return a.get("/api/rules") }
func (a *App) AddRule(jsonBody string) (string, error) { return a.post("/api/rules", []byte(jsonBody)) }
func (a *App) DeleteRule(id string) (string, error) {
	return a.do(http.MethodDelete, "/api/rules/"+id, nil)
}

// ---- generic passthrough (bound) ----
// The frontend builds the rich capx features (intercept / scope / decode / HaE /
// CaA / keylog / sitemap / mem …) by calling capx endpoints directly through
// these authenticated proxies — one place handles the token, the UI does the rest.

func (a *App) ApiGet(path string) (string, error)        { return a.get(path) }
func (a *App) ApiPost(path, body string) (string, error) { return a.post(path, []byte(body)) }
func (a *App) ApiDelete(path string) (string, error)     { return a.do(http.MethodDelete, path, nil) }

// OpenFolder reveals a local directory in the system file explorer.
func (a *App) OpenFolder(path string) (string, error) {
	cmd := exec.Command("explorer", path)
	hideChildWindow(cmd)
	_ = cmd.Start()
	return "ok", nil
}

func (a *App) SelectFolder(current string) (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("窗口未就绪")
	}
	return wruntime.OpenDirectoryDialog(a.ctx, wruntime.OpenDialogOptions{
		Title:            "选择 Applet 目录",
		DefaultDirectory: current,
	})
}

func wxSafeAppletRoot(root string) (string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", fmt.Errorf("目录为空")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	clean := strings.ToLower(filepath.Clean(abs))
	if !strings.Contains(clean, `tencent\xwechat\radium\applet`) && !strings.Contains(clean, `tencent\wechat\applet`) {
		return "", fmt.Errorf("拒绝清理非微信 Applet 目录: %s", abs)
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return "", fmt.Errorf("目录不存在: %s", abs)
	}
	return abs, nil
}

func (a *App) ClearWxAppletDir(root string) (string, error) {
	abs, err := wxSafeAppletRoot(root)
	if err != nil {
		return "", err
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return "", err
	}
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(strings.ToLower(name), "wx") {
			continue
		}
		if err := os.RemoveAll(filepath.Join(abs, name)); err != nil {
			return "", err
		}
		removed++
	}
	return fmt.Sprintf("已清理 %d 个小程序缓存项", removed), nil
}

func (a *App) ClearWxUnpackedDirs(root string) (string, error) {
	abs, err := wxSafeAppletRoot(root)
	if err != nil {
		return "", err
	}
	removed := 0
	err = filepath.WalkDir(abs, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() || path == abs {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), "_unpacked") {
			if err := os.RemoveAll(path); err != nil {
				return err
			}
			removed++
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("已清理 %d 个解包输出目录", removed), nil
}

// ---- one-click trust capx CA (bound) ----

// InstallCA fetches capx's root CA and trusts it in the current user's Root
// store (silently via Import-Certificate), so HTTPS through capx validates.
func (a *App) InstallCA() (string, error) {
	pem, err := a.get("/api/proxy/ca")
	if err != nil {
		return "", err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".capx")
	_ = os.MkdirAll(dir, 0o755)
	crt := filepath.Join(dir, "ca-desktop.crt")
	if err := os.WriteFile(crt, []byte(pem), 0o644); err != nil {
		return "", err
	}
	ps := "Import-Certificate -FilePath '" + crt + "' -CertStoreLocation Cert:\\CurrentUser\\Root | Out-Null; 'OK'"
	psCmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps)
	hideChildWindow(psCmd) // no console-window flash
	out, err := psCmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("安装失败：%s", strings.TrimSpace(string(out)))
	}
	return "capx CA 已安装到「当前用户·受信任的根证书」✓ 重启浏览器后 HTTPS 即正常", nil
}

// SaveFromCapx downloads a capx endpoint (e.g. /api/http/export HAR, /api/export/pcap)
// as raw bytes and saves to a user-chosen file via a native save dialog.
func (a *App) SaveFromCapx(path, suggestedName string) (string, error) {
	base, token := a.connection()
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Capx-Token", token)
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("下载失败：%w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("capx 返回 %d：%s", resp.StatusCode, truncate(string(data), 200))
	}
	dest, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{DefaultFilename: suggestedName})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(dest) == "" {
		return "已取消", nil
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return "", err
	}
	return "已保存到 " + dest + "（" + fmt.Sprintf("%d", len(data)) + " 字节）", nil
}

// SavePostToCapx POSTs a JSON body to a capx endpoint and saves the response
// bytes to a user-chosen file (e.g. /api/intruder/export → CSV).
func (a *App) SavePostToCapx(path, body, suggestedName string) (string, error) {
	base, token := a.connection()
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader([]byte(body)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Capx-Token", token)
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("请求失败：%w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("capx 返回 %d：%s", resp.StatusCode, truncate(string(data), 200))
	}
	dest, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{DefaultFilename: suggestedName})
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(dest) == "" {
		return "已取消", nil
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return "", err
	}
	return "已保存到 " + dest, nil
}
