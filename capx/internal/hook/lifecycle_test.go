package hook

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hquip/capx/internal/store"
)

// The child is this test binary, not Python/Frida. It ignores target arguments
// entirely and only exercises owned-worker readiness and cancellation.
func TestMain(m *testing.M) {
	if os.Getenv("CAPX_TEST_HOOK_WORKER") == "1" {
		fmt.Println(`{"event":"loaded"}`)
		fmt.Println(`{"event":"ready","hooked":["fixture"]}`)
		for {
			time.Sleep(time.Second)
		}
	}
	os.Exit(m.Run())
}

func TestReadinessRequiresDriverLoadAndAgentSignalAndRetainsFailure(t *testing.T) {
	m := &Manager{st: store.New(16), sessions: map[string]*Session{"s": {ID: "s", PID: 7, Started: time.Now(), State: "pending"}}}
	if s, _ := m.Session("s"); s.Ready {
		t.Fatal("started process was called ready")
	}
	m.observe("s", driverMsg{Event: "wxredirect", Stage: "ready", Hooks: []string{"connect"}})
	if s, _ := m.Session("s"); s.Ready || !s.AgentReady {
		t.Fatal("agent signal bypassed driver loaded")
	}
	m.observe("s", driverMsg{Event: "loaded"})
	if s, _ := m.Session("s"); !s.Ready {
		t.Fatal("loaded+agent-ready not promoted")
	}
	m.observe("s", driverMsg{Event: "wxredirect", Stage: "redirect", Redirected: 11})
	m.observe("s", driverMsg{Event: "error", Msg: "fixture async JS failure", Fatal: true})
	m.observe("s", driverMsg{Event: "loaded"})
	if s, _ := m.Session("s"); s.Ready || s.Error == "" || s.Redirected != 11 {
		t.Fatalf("failure/stats lost: %+v", s)
	}
	m.finish("s", nil)
	if len(m.Sessions()) != 0 {
		t.Fatal("terminal session still active")
	}
	if s, ok := m.Session("s"); !ok || s.Error != "fixture async JS failure" || s.Ended.IsZero() {
		t.Fatalf("async error vanished: %+v", s)
	}
}

func TestSessionSnapshotsAreIndependentAndRaceSafe(t *testing.T) {
	m := &Manager{st: store.New(16), sessions: map[string]*Session{"s": {ID: "s", PID: 7, Hooks: []string{"connect"}}}}
	copy := m.Sessions()[0]
	copy.PID = 88
	copy.Hooks[0] = "mutated"
	if s, _ := m.Session("s"); s.PID != 7 || s.Hooks[0] != "connect" {
		t.Fatal("Sessions leaked shared mutable state")
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				m.observe("s", driverMsg{Event: "wxredirect", Stage: "redirect", Redirected: uint64(j)})
				_ = m.Sessions()
				_, _ = m.Session("s")
			}
		}()
	}
	wg.Wait()
}

func waitHookReady(t *testing.T, m *Manager, id string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s, _ := m.Session(id)
		if s != nil && s.Ready {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	s, _ := m.Session(id)
	t.Fatalf("test worker never ready: %+v", s)
}

func TestCloseOnlyCancelsThisManagersDrivers(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	t.Setenv("CAPX_TEST_HOOK_WORKER", "1")
	a := &Manager{st: store.New(16), frida: os.Args[0], sessions: map[string]*Session{}}
	b := &Manager{st: store.New(16), frida: os.Args[0], sessions: map[string]*Session{}}
	defer a.Close()
	defer b.Close()
	x, err := a.Attach(4000000001, "tls")
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.Attach(4000000002, "tls")
	if err != nil {
		t.Fatal(err)
	}
	waitHookReady(t, a, x.ID)
	waitHookReady(t, b, y.ID)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if len(a.Sessions()) != 0 {
		t.Fatal("closed manager retained driver")
	}
	if s, _ := a.Session(x.ID); s.State != "stopped" {
		t.Fatalf("requested close not recorded: %+v", s)
	}
	if s, _ := b.Session(y.ID); s == nil || !s.Ready {
		t.Fatal("unrelated manager driver was stopped")
	}
	if _, err := a.Attach(4000000003, "tls"); err == nil {
		t.Fatal("closed manager allowed new worker")
	}
	if err := b.DetachAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Attach(4000000004, "tls"); err != nil {
		t.Fatal("DetachAll permanently closed manager")
	}
}

func TestHistoryIsBounded(t *testing.T) {
	m := &Manager{sessions: map[string]*Session{}}
	for i := 0; i < sessionHistoryLimit+12; i++ {
		id := fmt.Sprint(i)
		m.sessions[id] = &Session{ID: id, stopRequested: true}
		m.finish(id, context.Canceled)
	}
	if len(m.History()) != sessionHistoryLimit {
		t.Fatal("terminal history is not bounded")
	}
}
