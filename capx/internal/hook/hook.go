package hook

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	_ "embed"

	"github.com/hquip/capx/internal/backgroundprocess"
	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

//go:embed driver.py
var driverPy []byte

//go:embed agents/tls.js
var agentTLS []byte

//go:embed agents/java_tls.js
var agentJavaTLS []byte

//go:embed agents/apimon.js
var agentAPIMon []byte

var ErrNoFrida = errors.New("hook: frida not available (place runtime/frida/frida.exe next to capx, set CAPX_FRIDA, or pip install frida)")

type Process struct {
	PID  uint32 `json:"pid"`
	Name string `json:"name"`
}

type Session struct {
	ID            string    `json:"id"`
	PID           uint32    `json:"pid"`
	Agent         string    `json:"agent"`
	Started       time.Time `json:"started"`
	State         string    `json:"state"`
	DriverLoaded  bool      `json:"driver_loaded"`
	AgentReady    bool      `json:"agent_ready"`
	Ready         bool      `json:"ready"`
	Error         string    `json:"error,omitempty"`
	Diagnostic    string    `json:"diagnostic,omitempty"`
	Redirected    uint64    `json:"redirected"`
	Hooks         []string  `json:"hooks,omitempty"`
	Ended         time.Time `json:"ended,omitempty"`
	cancel        context.CancelFunc
	done          chan struct{}
	stopRequested bool
}

type Manager struct {
	st      *store.Store
	python  string
	frida   string
	version string

	mu           sync.Mutex
	launchMu     sync.Mutex
	sessions     map[string]*Session
	workers      map[string]chan struct{}
	history      map[string]*Session
	historyOrder []string
	closed       bool
	seq          int
	onKeylog     func(string)
}

func New(st *store.Store) *Manager {
	return &Manager{
		st:       st,
		python:   detectPython(),
		frida:    detectFridaCLI(),
		version:  readBundledVersion(),
		sessions: map[string]*Session{},
	}
}

func (m *Manager) SetKeylogSink(fn func(string)) {
	m.mu.Lock()
	m.onKeylog = fn
	m.mu.Unlock()
}

func (m *Manager) Available() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.closed && (m.frida != "" || m.python != "")
}

func (m *Manager) Backend() string {
	if m.python != "" {
		return "frida"
	}
	if m.frida != "" {
		return "frida-cli"
	}
	return "stub"
}

func (m *Manager) FridaPath() string    { return m.frida }
func (m *Manager) FridaVersion() string { return m.version }

func builtinAgent(name string) ([]byte, bool) {
	switch name {
	case "", "tls":
		return agentTLS, true
	case "java", "java_tls", "android":
		return agentJavaTLS, true
	case "apimon", "api":
		return agentAPIMon, true
	}
	return nil, false
}

var (
	customMu     sync.RWMutex
	customAgents = map[string][]byte{}
)

func RegisterAgent(name string, script []byte) {
	customMu.Lock()
	customAgents[name] = append([]byte(nil), script...)
	customMu.Unlock()
}

func UnregisterAgent(name string) bool {
	customMu.Lock()
	defer customMu.Unlock()
	_, ok := customAgents[name]
	delete(customAgents, name)
	return ok
}

func ListAgents() []string {
	names := []string{"tls", "java", "apimon"}
	customMu.RLock()
	for k := range customAgents {
		names = append(names, k)
	}
	customMu.RUnlock()
	return names
}

func resolveAgent(name string) ([]byte, bool) {
	if script, ok := builtinAgent(name); ok {
		return script, true
	}
	customMu.RLock()
	script, ok := customAgents[name]
	customMu.RUnlock()
	return append([]byte(nil), script...), ok
}

func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".capx", "hook")
	return dir, os.MkdirAll(dir, 0o755)
}

func (m *Manager) Sessions() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, copySession(s))
	}
	return out
}

func (m *Manager) Attach(pid uint32, agent string) (*Session, error) {
	if pid == 0 {
		return nil, fmt.Errorf("pid required")
	}
	return m.launch([]string{"--pid", strconv.FormatUint(uint64(pid), 10)}, pid, agent)
}

func (m *Manager) AttachSpawn(program string, args []string, agent string) (*Session, error) {
	if program == "" {
		return nil, fmt.Errorf("program required")
	}
	driverArgs := append([]string{"--spawn", program}, args...)
	return m.launch(driverArgs, 0, agent)
}

func (m *Manager) launch(targetArgs []string, pid uint32, agent string) (*Session, error) {
	m.launchMu.Lock()
	defer m.launchMu.Unlock()
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return nil, errors.New("hook manager is closed")
	}
	if m.frida == "" && m.python == "" {
		return nil, ErrNoFrida
	}
	script, ok := resolveAgent(agent)
	if !ok {
		return nil, fmt.Errorf("unknown agent %q (register with RegisterAgent first)", agent)
	}
	dir, err := cacheDir()
	if err != nil {
		return nil, err
	}
	runtimeTemp, err := os.MkdirTemp(dir, "hook-session-")
	if err != nil {
		return nil, fmt.Errorf("create hook runtime: %w", err)
	}
	started := false
	defer func() {
		if !started {
			_ = os.RemoveAll(runtimeTemp)
		}
	}()
	agentPath := filepath.Join(runtimeTemp, "agent.js")
	if m.python == "" {
		script = append(append([]byte(cliMessageShim), script...), []byte("\nconsole.log(JSON.stringify({event:'loaded'}));\n")...)
	}
	if err := os.WriteFile(agentPath, script, 0o644); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	var cmd *exec.Cmd
	if m.python != "" {
		// 首选 python 驱动(frida 官方绑定):会话由驱动进程常驻持有,可靠。
		// frida CLI 在批处理模式下注入后会自行退出(frida 16 实测),仅作回退。
		driverPath := filepath.Join(runtimeTemp, "driver.py")
		if err := os.WriteFile(driverPath, driverPy, 0o644); err != nil {
			cancel()
			return nil, err
		}
		cmdArgs := append([]string{driverPath}, targetArgs...)
		cmdArgs = append(cmdArgs, "--agent", agentPath)
		cmd = backgroundprocess.CommandContext(ctx, m.python, cmdArgs...)
		cmd.Env = append(os.Environ(),
			"TEMP="+runtimeTemp,
			"TMP="+runtimeTemp,
			"TMPDIR="+runtimeTemp,
		)
	} else {
		args, err := fridaCLIArgs(targetArgs, agentPath)
		if err != nil {
			cancel()
			return nil, err
		}
		cmd = backgroundprocess.CommandContext(ctx, m.frida, args...)
		cmd.Dir = filepath.Dir(m.frida)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		if runtimeTemp != "" {
			_ = os.RemoveAll(runtimeTemp)
		}
		return nil, err
	}
	// frida CLI 的 REPL 在脚本求值后可能自行退出(frida 16 实测);
	// 持有一个不写入的 stdin 管道作为额外保险,直到 Detach 结束进程。
	// 必须由 pump 持有引用,防止 GC finalizer 提前关闭管道。
	var stdinW io.WriteCloser
	if m.python == "" && m.frida != "" {
		if w, pipeErr := cmd.StdinPipe(); pipeErr == nil {
			stdinW = w
		}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		if stdinW != nil {
			stdinW.Close()
		}
		return nil, err
	}
	cmd.WaitDelay = 2 * time.Second
	hideDriverWindow(cmd)
	if err := cmd.Start(); err != nil {
		cancel()
		if runtimeTemp != "" {
			_ = os.RemoveAll(runtimeTemp)
		}
		if stdinW != nil {
			stdinW.Close()
		}
		return nil, err
	}

	m.mu.Lock()
	m.seq++
	sid := fmt.Sprintf("hook-%d", m.seq)
	sess := &Session{ID: sid, PID: pid, Agent: nonEmpty(agent, "tls"), Started: time.Now().UTC(), State: "pending", cancel: cancel, done: make(chan struct{})}
	if m.sessions == nil {
		m.sessions = map[string]*Session{}
	}
	m.sessions[sid] = sess
	if m.workers == nil {
		m.workers = map[string]chan struct{}{}
	}
	m.workers[sid] = sess.done
	result := copySession(sess)
	m.mu.Unlock()

	started = true
	stderrDone := make(chan struct{})
	go func() { defer close(stderrDone); m.pumpStderr(sid, stderr) }()
	go m.pump(sid, pid, stdout, cmd, cancel, runtimeTemp, stdinW, stderrDone, sess.done)
	return result, nil
}

func fridaCLIArgs(targetArgs []string, agentPath string) ([]string, error) {
	// 注意:frida 16+ 已移除 --no-pause(spawn 默认即恢复主线程,反向开关为 --pause),
	// 传了会直接报 unrecognized arguments 退出,导致注入静默失败。
	out := []string{"-q"}
	i := 0
	for i < len(targetArgs) {
		switch targetArgs[i] {
		case "--pid":
			if i+1 >= len(targetArgs) {
				return nil, fmt.Errorf("missing pid")
			}
			out = append(out, "-p", targetArgs[i+1])
			i += 2
		case "--spawn":
			if i+1 >= len(targetArgs) {
				return nil, fmt.Errorf("missing spawn program")
			}
			out = append(out, "-f", targetArgs[i+1])
			i += 2
			if i < len(targetArgs) {
				out = append(out, "--")
				out = append(out, targetArgs[i:]...)
				i = len(targetArgs)
			}
		default:
			return nil, fmt.Errorf("unsupported frida target %q", targetArgs[i])
		}
	}
	out = append(out, "-l", agentPath)
	return out, nil
}

func (m *Manager) Detach(sid string) error {
	sess, err := m.requestDetach(sid)
	if err != nil {
		return err
	}
	return waitSessions([]*Session{sess}, 3*time.Second)
}

// RequestDetach cancels this manager's driver without blocking a status poll.
// Detach/Close can still wait on the retained pump completion channel.
func (m *Manager) RequestDetach(sid string) error { _, err := m.requestDetach(sid); return err }
func (m *Manager) requestDetach(sid string) (*Session, error) {
	m.mu.Lock()
	sess, ok := m.sessions[sid]
	if ok {
		sess.stopRequested = true
		sess.Ready = false
		sess.State = "stopping"
	}
	m.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("session %s not found", sid)
	}
	if sess.cancel != nil {
		sess.cancel()
	}
	return sess, nil
}

type driverMsg struct {
	Event      string   `json:"event"`
	Func       string   `json:"func"`
	Dir        string   `json:"dir"`
	Len        int      `json:"len"`
	Peer       string   `json:"peer"`
	PID        uint32   `json:"pid"`
	DataB64    string   `json:"data_b64"`
	Msg        string   `json:"msg"`
	Stage      string   `json:"stage"`
	Fatal      bool     `json:"fatal"`
	Redirected uint64   `json:"redirected"`
	Hooks      []string `json:"hooks"`
	Hooked     []string `json:"hooked"`
}

func (m *Manager) pump(sid string, pid uint32, stdout io.Reader, cmd *exec.Cmd, cancel context.CancelFunc, runtimeTemp string, stdinW io.WriteCloser, stderrDone, done chan struct{}) {
	defer func() { close(done); m.mu.Lock(); delete(m.workers, sid); m.mu.Unlock() }()
	if stdinW != nil {
		defer stdinW.Close()
	}
	if runtimeTemp != "" {
		defer os.RemoveAll(runtimeTemp)
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var dm driverMsg
		if err := json.Unmarshal(sc.Bytes(), &dm); err != nil {
			continue
		}
		m.observe(sid, dm)
		switch dm.Event {
		case "spawned":
			if dm.PID != 0 {
				pid = dm.PID
				m.mu.Lock()
				if s := m.sessions[sid]; s != nil {
					s.PID = pid
				}
				m.mu.Unlock()
			}
		case "keylog":
			m.mu.Lock()
			sink := m.onKeylog
			m.mu.Unlock()
			if sink != nil && dm.Msg != "" {
				sink(dm.Msg)
			}
		case "tls":
			raw, _ := base64.StdEncoding.DecodeString(dm.DataB64)
			m.st.AddHookEvent(&model.HookEvent{
				PID: pid, Func: dm.Func, Dir: dm.Dir, Len: dm.Len,
				Peer: dm.Peer, Data: preview(raw),
			})
		case "error":
			m.st.Publish(model.Event{Source: model.SourceHook, Kind: "hook_error",
				Data: map[string]any{"session": sid, "pid": pid, "error": dm.Msg}})
		}
	}
	if err := sc.Err(); err != nil {
		m.observe(sid, driverMsg{Event: "error", Msg: "driver output: " + err.Error(), Fatal: true})
		cancel()
	}
	err := cmd.Wait()
	<-stderrDone
	cancel()
	m.finish(sid, err)
	m.st.Publish(model.Event{Source: model.SourceHook, Kind: "hook_detached",
		Data: map[string]any{"session": sid, "pid": pid}})
}

const maxPreview = 64 * 1024

func preview(b []byte) string {
	if len(b) > maxPreview {
		b = b[:maxPreview]
	}
	if utf8.Valid(b) && isMostlyPrintable(b) {
		return string(b)
	}
	return fmt.Sprintf("%x", b)
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	bad := 0
	for _, c := range b {
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			bad++
		}
	}
	return bad*10 < len(b)
}

func nonEmpty(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}
