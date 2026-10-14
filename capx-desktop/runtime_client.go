package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type desktopHealth struct {
	Status   string `json:"status"`
	Sniffer  string `json:"sniffer"`
	Hook     string `json:"hook"`
	Inline   string `json:"inline"`
	Identity struct {
		InstanceID string `json:"instance_id"`
		Generation string `json:"generation"`
	} `json:"identity"`
}

func fetchCapxHealth(base string, timeout time.Duration) (desktopHealth, error) {
	var health desktopHealth
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(normalizeBaseURL(base) + "/health")
	if err != nil {
		return health, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return health, fmt.Errorf("health returned %d", resp.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64<<10))
	if err := dec.Decode(&health); err != nil {
		return health, fmt.Errorf("invalid Capx health: %w", err)
	}
	if health.Status != "ok" || health.Sniffer == "" || health.Hook == "" || health.Inline == "" {
		return health, errors.New("not a Capx health response")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return health, errors.New("unexpected data after Capx health")
	}
	return health, nil
}

func runtimeHealthOK(rt desktopRuntime, timeout time.Duration) bool {
	health, err := fetchCapxHealth(rt.BaseURL, timeout)
	return err == nil && (rt.Generation == "" || rt.Generation == health.Identity.Generation) && (rt.InstanceID == "" || rt.InstanceID == health.Identity.InstanceID)
}

func (a *App) connection() (string, string) { a.mu.Lock(); defer a.mu.Unlock(); return a.base, a.token }
func (a *App) refreshToken() {
	base, _ := a.connection()
	token := readTokenFor(base)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.base == base {
		a.token = token
	}
}

func newDesktopGeneration() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err == nil {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("desktop-%d-%d", os.Getpid(), time.Now().UnixNano())
}

func runtimePaths(base string) []string {
	paths := []string{runtimePath(), filepath.Join(filepath.Dir(runtimePath()), "runtime-"+basePort(base)+".json")}
	registry := strings.TrimSpace(os.Getenv("CAPX_INSTANCE_DIR"))
	if registry == "" {
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			registry = filepath.Join(local, "capx", "instances")
		} else if home, err := os.UserHomeDir(); err == nil {
			registry = filepath.Join(home, ".capx", "instances")
		}
	}
	if registry != "" {
		entries, _ := filepath.Glob(filepath.Join(registry, "*.json"))
		paths = append(paths, entries...)
	}
	return paths
}

func decodeRuntime(path string) desktopRuntime {
	var record struct {
		desktopRuntime
		APIBase string `json:"api_base"`
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64<<10 || json.Unmarshal(b, &record) != nil {
		return desktopRuntime{}
	}
	if record.BaseURL == "" {
		record.BaseURL = record.APIBase
	}
	return record.desktopRuntime
}

func runtimeForBase(base string) desktopRuntime {
	for _, path := range runtimePaths(base) {
		rt := decodeRuntime(path)
		if normalizeBaseURL(rt.BaseURL) == normalizeBaseURL(base) {
			return rt
		}
	}
	state := defaultStateDir(base)
	pid, _, _ := readBackendPID(state)
	return desktopRuntime{BaseURL: base, StateDir: state, TokenFile: filepath.Join(state, "token"), PID: pid}
}

func tokenWithinState(state, tokenFile string) bool {
	if state == "" || tokenFile == "" {
		return false
	}
	root, err := filepath.Abs(state)
	if err != nil {
		return false
	}
	path, err := filepath.Abs(tokenFile)
	if err != nil {
		return false
	}
	// Resolve existing symlinks before checking the manifest boundary.
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func readTokenFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 8192 {
		return ""
	}
	return strings.TrimSpace(string(b))
}
func readTokenFor(base string) string {
	if token := strings.TrimSpace(os.Getenv("CAPX_TOKEN")); token != "" {
		return token
	}
	if path := strings.TrimSpace(os.Getenv("CAPX_TOKEN_FILE")); path != "" {
		return readTokenFile(path)
	}
	rt := runtimeForBase(base)
	if rt.TokenFile != "" && tokenWithinState(rt.StateDir, rt.TokenFile) {
		if token := readTokenFile(rt.TokenFile); token != "" {
			return token
		}
	}
	for _, state := range []string{strings.TrimSpace(os.Getenv("CAPX_STATE_DIR")), rt.StateDir, defaultStateDir(base)} {
		if state != "" {
			if token := readTokenFile(filepath.Join(state, "token")); token != "" {
				return token
			}
		}
	}
	// Legacy Manager used state-19091, while the original desktop used state.
	state := defaultStateDir(base)
	if basePort(base) == "19091" && state != "" {
		if token := readTokenFile(filepath.Join(filepath.Dir(state), "state-19091", "token")); token != "" {
			return token
		}
	}
	return readToken() // compatibility with pre-instance daemons only
}

type backendStopProcess interface {
	Running() bool
	Terminate() error
	Close()
}

func stopCapxRuntime(base, token string, rt desktopRuntime, proc backendStopProcess, timeout time.Duration) error {
	if proc != nil && !proc.Running() {
		return nil
	}
	health, healthErr := fetchCapxHealth(base, 1500*time.Millisecond)
	requested := false
	if healthErr == nil {
		if (rt.Generation != "" && health.Identity.Generation != rt.Generation) || (rt.InstanceID != "" && health.Identity.InstanceID != rt.InstanceID) {
			return errors.New("Capx runtime identity changed; replacement instance was preserved")
		}
		if token == "" {
			return errors.New("未找到当前实例 token；未发送停止请求")
		}
		condition, _ := json.Marshal(map[string]string{"expected_instance_id": health.Identity.InstanceID, "expected_generation": health.Identity.Generation})
		req, err := http.NewRequest(http.MethodPost, normalizeBaseURL(base)+"/api/runtime/shutdown", bytes.NewReader(condition))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusConflict {
				return fmt.Errorf("停止认证失败 (%d)，未强制结束", resp.StatusCode)
			}
			requested = resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK
		}
	}
	if requested {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if proc != nil {
				if !proc.Running() {
					return nil
				}
			} else if !capxHealthOK(base, 300*time.Millisecond) {
				return nil
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	if proc == nil {
		return errors.New("后台未正常结束，且没有可验证的本实例进程句柄；未强制结束")
	}
	if err := proc.Terminate(); err != nil {
		return fmt.Errorf("停止已验证的后台失败: %w", err)
	}
	return nil
}

func runtimeArg(line, name string) string {
	re := regexp.MustCompile(`(?i)(?:^|\s)--?` + regexp.QuoteMeta(name) + `(?:=|\s+)(?:"([^"]*)"|'([^']*)'|(\S+))`)
	m := re.FindStringSubmatch(line)
	if len(m) == 0 {
		return ""
	}
	for _, value := range m[1:] {
		if value != "" {
			return value
		}
	}
	return ""
}

func backendIdentityMatches(rt desktopRuntime, exe, line string) bool {
	if rt.PID <= 0 || rt.Generation == "" || rt.Exe == "" || rt.StateDir == "" {
		return false
	}
	a, err := filepath.Abs(rt.Exe)
	if err != nil {
		return false
	}
	b, err := filepath.Abs(exe)
	if err != nil || !strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) {
		return false
	}
	a, err = filepath.Abs(rt.StateDir)
	if err != nil {
		return false
	}
	b, err = filepath.Abs(runtimeArg(line, "state-dir"))
	if err != nil {
		return false
	}
	return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) && runtimeArg(line, "generation") == rt.Generation && runtimeArg(line, "instance-id") == rt.InstanceID && runtimeArg(line, "addr") == baseListenAddr(rt.BaseURL)
}

func clearRuntimeIfMatch(expected desktopRuntime) {
	for _, path := range runtimePaths(expected.BaseURL) {
		// Manager manifests are owned by Manager, never remove them here.
		if filepath.Dir(path) != filepath.Dir(runtimePath()) {
			continue
		}
		actual := decodeRuntime(path)
		if actual.PID == expected.PID && actual.Generation == expected.Generation {
			_ = os.Remove(path)
		}
	}
	if pid, path, err := readBackendPID(expected.StateDir); err == nil && pid == expected.PID {
		_ = os.Remove(path)
	}
}
