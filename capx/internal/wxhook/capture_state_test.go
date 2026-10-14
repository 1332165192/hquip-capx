package wxhook

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hquip/capx/internal/hook"
)

func TestCapturePendingIsNotSuccessAndAsyncErrorSurvivesRollback(t *testing.T) {
	engine := newFakeHookEngine()
	engine.pending = true
	m := testCaptureManager(engine, func() ([]Process, error) { return []Process{{PID: 33, Role: "network"}}, nil })
	defer m.Close()
	opts := CaptureOptions{Port: 18461, ExplicitPort: 18462, UpstreamProxy: "http://127.0.0.1:7897"}
	result, err := m.CaptureStartWithOptions(opts, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.Running || !result.Enabled || fmt.Sprint(result.PendingPIDs) != "[33]" || len(result.ReadyPIDs) != 0 || len(result.Attached) != 0 {
		t.Fatalf("cmd.Start masqueraded as ready: %+v", result)
	}
	if result.ExplicitPort != 18462 || !strings.Contains(result.Transport, "explicit-http-proxy") {
		t.Fatal("transport configuration missing")
	}
	engine.mu.Lock()
	session := engine.sessions["fake-1"]
	session.DriverLoaded = true
	session.State = "loaded"
	engine.mu.Unlock()
	if m.CaptureStatus().Running {
		t.Fatal("loaded without agent-ready marked running")
	}
	engine.mu.Lock()
	session.AgentReady = true
	session.Ready = true
	session.State = "ready"
	session.Redirected = 7
	engine.mu.Unlock()
	if got := m.CaptureStatus(); !got.Running || fmt.Sprint(got.ReadyPIDs) != "[33]" || got.Redirected != 7 {
		t.Fatalf("ready/statistics missing: %+v", got)
	}
	engine.mu.Lock()
	session.Error = "fixture asynchronous attach/load failure"
	session.Ready = false
	session.State = "error"
	session.Redirected = 9
	session.Ended = time.Now()
	copy := *session
	engine.history[session.ID] = &copy
	delete(engine.sessions, session.ID)
	engine.mu.Unlock()
	if got := m.CaptureStatus(); got.Running || !strings.Contains(got.Errors[33], "asynchronous") || got.Redirected != 9 || len(got.PIDs) != 0 {
		t.Fatalf("async failure vanished: %+v", got)
	}
	if err := m.CaptureStop(); err != nil {
		t.Fatal(err)
	}
	if got := m.CaptureStatus(); got.Enabled || got.Running || !strings.Contains(got.Errors[33], "asynchronous") {
		t.Fatalf("rollback erased diagnostic: %+v", got)
	}
}

func TestCaptureAllFailuresReturnErrorAndRetryBackoff(t *testing.T) {
	engine := newFakeHookEngine()
	engine.err = errors.New("fixture access denied")
	m := testCaptureManager(engine, func() ([]Process, error) { return []Process{{PID: 44, Role: "network"}}, nil })
	defer m.Close()
	result, err := m.CaptureStart(18463, nil, false)
	if err == nil || result == nil || result.Running || result.Errors[44] != "fixture access denied" {
		t.Fatalf("all failures presented as success: %+v %v", result, err)
	}
	m.mu.Lock()
	retry := m.captureRetry[44]
	failures := m.captureFailures[44]
	m.mu.Unlock()
	if failures != 1 || time.Until(retry) < captureRetryBase {
		t.Fatal("failed attach did not back off")
	}
	engine.err = nil
	result, err = m.CaptureStart(18463, nil, false)
	if err == nil || len(result.PIDs) != 0 || engine.next != 0 {
		t.Fatal("immediate retry bypassed failure backoff")
	}
}

func TestCaptureReadinessTimeoutCancelsOnlyOwnSession(t *testing.T) {
	engine := newFakeHookEngine()
	engine.pending = true
	m := testCaptureManager(engine, func() ([]Process, error) { return []Process{{PID: 55, Role: "network"}}, nil })
	defer m.Close()
	if _, err := m.CaptureStart(18464, nil, false); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.sessions["fake-1"].Started = time.Now().Add(-capturePendingTimeout - time.Second)
	engine.sessions["unrelated"] = &hook.Session{ID: "unrelated", PID: 66, Ready: true, Started: time.Now()}
	engine.mu.Unlock()
	got := m.CaptureStatus()
	if got.Running || !strings.Contains(got.Errors[55], "timed out") {
		t.Fatalf("readiness timeout not reported: %+v", got)
	}
	engine.mu.Lock()
	_, exists := engine.sessions["unrelated"]
	engine.mu.Unlock()
	if !exists {
		t.Fatal("unrelated session detached")
	}
}

func TestCaptureSelectsNetworkServiceWithoutTouchingRenderers(t *testing.T) {
	engine := newFakeHookEngine()
	m := testCaptureManager(engine, func() ([]Process, error) {
		return []Process{{PID: 11, Main: true}, {PID: 22, Role: "renderer"}, {PID: 33, Role: "gpu"}, {PID: 44, Role: "network"}}, nil
	})
	defer m.Close()
	got, err := m.CaptureStart(18465, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got.ReadyPIDs) != "[44]" || len(engine.attached) != 1 {
		t.Fatalf("automatic capture attached irrelevant processes: %+v", got)
	}
	if err := m.CaptureStop(); err != nil {
		t.Fatal(err)
	}
	got, err = m.CaptureStart(18465, []uint32{22}, false)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(got.ReadyPIDs) != "[22]" {
		t.Fatal("explicit validated PID selection was overridden")
	}
}

func TestCaptureAgentNamespaceIsManagerLocal(t *testing.T) {
	list := func() ([]Process, error) { return []Process{{PID: 99, Role: "network"}}, nil }
	a, b := testCaptureManager(newFakeHookEngine(), list), testCaptureManager(newFakeHookEngine(), list)
	defer a.Close()
	defer b.Close()
	if _, err := a.CaptureStart(18466, nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := b.CaptureStart(18466, nil, false); err != nil {
		t.Fatal(err)
	}
	if a.captureAgent == b.captureAgent {
		t.Fatal("manager shared mutable agent registration")
	}
	if err := a.CaptureStop(); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, name := range hook.ListAgents() {
		if name == b.captureAgent {
			found = true
		}
	}
	if !found || !b.CaptureStatus().Running {
		t.Fatal("one manager stop disrupted another manager")
	}
}

func TestProcessRoleUsesChromiumFlagsNotArbitraryText(t *testing.T) {
	for _, tc := range []struct{ line, role string }{
		{`WeChatAppEx.exe --type=utility --utility-sub-type=network.mojom.NetworkService`, "network"},
		{`WeChatAppEx.exe --type=utility --utility-sub-type="network.mojom.NetworkService"`, "network"},
		{`WeChatAppEx.exe --type=renderer`, "renderer"},
		{`WeChatAppEx.exe --type=gpu-process`, "gpu"},
		{`WeChatAppEx.exe --url=https://fixture/network.mojom.NetworkService`, ""},
	} {
		if got := processRole(tc.line); got != tc.role {
			t.Fatalf("role(%q)=%q want %q", tc.line, got, tc.role)
		}
	}
}
