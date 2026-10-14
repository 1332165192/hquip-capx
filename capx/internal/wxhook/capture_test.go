package wxhook

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hquip/capx/internal/hook"
)

type fakeHookEngine struct {
	mu       sync.Mutex
	next     int
	sessions map[string]*hook.Session
	attached map[uint32]string
	detached []string
	err      error
	pending  bool
	history  map[string]*hook.Session
}

func newFakeHookEngine() *fakeHookEngine {
	return &fakeHookEngine{sessions: map[string]*hook.Session{}, attached: map[uint32]string{}, history: map[string]*hook.Session{}}
}

func (f *fakeHookEngine) Available() bool { return true }
func (f *fakeHookEngine) Backend() string { return "frida" }

func (f *fakeHookEngine) Attach(pid uint32, agent string) (*hook.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.next++
	id := fmt.Sprintf("fake-%d", f.next)
	session := &hook.Session{ID: id, PID: pid, Agent: agent, Started: time.Now(), DriverLoaded: !f.pending, AgentReady: !f.pending, Ready: !f.pending, State: "ready"}
	if f.pending {
		session.State = "pending"
	}
	f.sessions[id] = session
	f.attached[pid] = agent
	copy := *session
	return &copy, nil
}

func (f *fakeHookEngine) Detach(sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sessions[sessionID]; !ok {
		return errors.New("missing session")
	}
	copy := *f.sessions[sessionID]
	copy.Ended = time.Now()
	copy.Ready = false
	f.history[sessionID] = &copy
	delete(f.sessions, sessionID)
	f.detached = append(f.detached, sessionID)
	return nil
}

func (f *fakeHookEngine) RequestDetach(id string) error { return f.Detach(id) }
func (f *fakeHookEngine) Session(id string) (*hook.Session, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.sessions[id]
	if s == nil {
		s = f.history[id]
	}
	if s == nil {
		return nil, false
	}
	copy := *s
	return &copy, true
}

func (f *fakeHookEngine) Sessions() []*hook.Session {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*hook.Session, 0, len(f.sessions))
	for _, session := range f.sessions {
		copy := *session
		out = append(out, &copy)
	}
	return out
}

func testCaptureManager(engine hookEngine, list func() ([]Process, error)) *Manager {
	return &Manager{
		hooks:           engine,
		sessions:        map[uint32]string{},
		captureSessions: map[uint32]string{},
		captureRetry:    map[uint32]time.Time{},
		captureFailures: map[uint32]int{},
		listProcesses:   list,
	}
}

func TestCaptureRetryDelayBacksOffAndCaps(t *testing.T) {
	if got := captureRetryDelay(0); got != 5*time.Second {
		t.Fatalf("initial retry delay = %s", got)
	}
	if got := captureRetryDelay(3); got != 40*time.Second {
		t.Fatalf("retry delay after failures = %s", got)
	}
	if got := captureRetryDelay(99); got != 5*time.Minute {
		t.Fatalf("retry delay cap = %s", got)
	}
}

func TestCaptureStopIgnoresAlreadyDetachedSession(t *testing.T) {
	engine := newFakeHookEngine()
	manager := testCaptureManager(engine, func() ([]Process, error) { return nil, nil })
	manager.capturePort = 18446
	manager.captureSessions[33] = "already-gone"
	if err := manager.CaptureStop(); err != nil {
		t.Fatalf("idempotent stop: %v", err)
	}
	if manager.CaptureStatus().Running {
		t.Fatal("capture remained active")
	}
}

func TestRenderRedirectAgent(t *testing.T) {
	script, err := renderRedirectAgent(18443)
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	if strings.Contains(text, "@@PORT@@") || !strings.Contains(text, "CAPX_PORT = 18443") {
		t.Fatalf("redirect port was not rendered: %q", text[:80])
	}
	if !strings.Contains(text, "WSAConnect") || !strings.Contains(text, "SO_TYPE") {
		t.Fatal("redirect agent is missing Winsock/TCP guards")
	}
	if !strings.Contains(text, "ConnectEx") || !strings.Contains(text, "WSAIoctl") {
		t.Fatal("redirect agent is missing ConnectEx hook")
	}
	if !strings.Contains(text, "0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e") {
		t.Fatal("ConnectEx GUID Data4 is wrong (WSAID_CONNECTEX must start 8ee9...)")
	}
	if _, err := renderRedirectAgent(0); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestCaptureStartAndStopAllProcesses(t *testing.T) {
	engine := newFakeHookEngine()
	manager := testCaptureManager(engine, func() ([]Process, error) {
		return []Process{{PID: 22, Name: "WeChatAppEx.exe"}, {PID: 11, Name: "WeChatAppEx.exe"}}, nil
	})

	result, err := manager.CaptureStart(18443, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(result.PIDs); got != "[11 22]" {
		t.Fatalf("captured pids = %s", got)
	}
	for _, pid := range []uint32{11, 22} {
		if got := engine.attached[pid]; !strings.HasPrefix(got, "wxredirect-18443-") {
			t.Fatalf("pid %d agent = %q", pid, got)
		}
	}
	if err := manager.CaptureStop(); err != nil {
		t.Fatal(err)
	}
	if status := manager.CaptureStatus(); status.Running || len(status.PIDs) != 0 {
		t.Fatalf("capture still active after stop: %+v", status)
	}
	if len(engine.detached) != 2 {
		t.Fatalf("detached sessions = %d", len(engine.detached))
	}
}

func TestCaptureWatchAttachesNewProcess(t *testing.T) {
	engine := newFakeHookEngine()
	var mu sync.Mutex
	processes := []Process{}
	manager := testCaptureManager(engine, func() ([]Process, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]Process(nil), processes...), nil
	})
	defer manager.CaptureStop()

	result, err := manager.CaptureStart(18444, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.Running || !result.Enabled || !result.Watch || len(result.PIDs) != 0 {
		t.Fatalf("unexpected initial status: %+v", result)
	}
	mu.Lock()
	processes = []Process{{PID: 33, Name: "WeChatAppEx.exe"}}
	mu.Unlock()

	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := manager.CaptureStatus().PIDs; len(got) == 1 && got[0] == 33 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("watcher did not attach process: %+v", manager.CaptureStatus())
}

func TestCaptureStartReportsListerFailureWithoutFalseReadiness(t *testing.T) {
	engine := newFakeHookEngine()
	manager := testCaptureManager(engine, func() ([]Process, error) {
		return nil, errors.New("list failed")
	})
	defer manager.Close()
	if _, err := manager.CaptureStart(18445, nil, true); err == nil {
		t.Fatal("expected process list error")
	}
	if manager.CaptureStatus().Running {
		t.Fatal("capture remained active after start failure")
	}
}
