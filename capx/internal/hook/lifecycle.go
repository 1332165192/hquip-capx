package hook

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hquip/capx/internal/model"
)

const sessionHistoryLimit = 128

func copySession(s *Session) *Session {
	if s == nil {
		return nil
	}
	out := *s
	out.Hooks = append([]string(nil), s.Hooks...)
	out.cancel = nil
	out.done = nil
	out.stopRequested = false
	return &out
}

// Session includes a bounded terminal history so an async load/attach failure
// cannot vanish between two wx status polls.
func (m *Manager) Session(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.sessions[id]; s != nil {
		return copySession(s), true
	}
	if s := m.history[id]; s != nil {
		return copySession(s), true
	}
	return nil, false
}

func (m *Manager) History() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0, len(m.historyOrder))
	for _, id := range m.historyOrder {
		if s := m.history[id]; s != nil {
			out = append(out, copySession(s))
		}
	}
	return out
}

func (m *Manager) observe(id string, dm driverMsg) {
	m.mu.Lock()
	s := m.sessions[id]
	if s == nil {
		m.mu.Unlock()
		return
	}
	if dm.Redirected > s.Redirected {
		s.Redirected = dm.Redirected
	}
	if len(dm.Hooks) > 0 {
		s.Hooks = append([]string(nil), dm.Hooks...)
	} else if len(dm.Hooked) > 0 {
		s.Hooks = append([]string(nil), dm.Hooked...)
	}
	switch dm.Event {
	case "loaded":
		s.DriverLoaded = true
	case "ready":
		s.AgentReady = true
	case "error":
		s.Error = boundedDiagnostic(dm.Msg)
		s.Ready = false
		s.State = "error"
	case "wxredirect":
		switch dm.Stage {
		case "ready":
			s.AgentReady = true
		case "error":
			s.Error = boundedDiagnostic(dm.Msg)
			s.Ready = false
			s.State = "error"
		case "diagnostic":
			s.Diagnostic = boundedDiagnostic(dm.Msg)
		}
	}
	if !s.stopRequested && s.Error == "" {
		s.Ready = s.DriverLoaded && s.AgentReady
		if s.Ready {
			s.State = "ready"
		} else if s.DriverLoaded {
			s.State = "loaded"
		}
	}
	pid := s.PID
	m.mu.Unlock()
	if dm.Event == "wxredirect" && m.st != nil {
		m.st.Publish(model.Event{Source: model.SourceHook, Kind: "wxredirect_" + nonEmpty(dm.Stage, "message"), Data: map[string]any{"session": id, "pid": pid, "message": dm.Msg, "redirected": dm.Redirected}})
	}
}

func boundedDiagnostic(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 4096 {
		return value[len(value)-4096:]
	}
	return value
}

func (m *Manager) pumpStderr(id string, r io.Reader) {
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 0, 4096), 64<<10)
	for scan.Scan() {
		m.mu.Lock()
		if s := m.sessions[id]; s != nil {
			s.Diagnostic = boundedDiagnostic(s.Diagnostic + "\n" + scan.Text())
		}
		m.mu.Unlock()
	}
}

func (m *Manager) finish(id string, exitErr error) {
	m.mu.Lock()
	s := m.sessions[id]
	if s == nil {
		m.mu.Unlock()
		return
	}
	if s.Error != "" {
		s.State = "error"
	} else if s.stopRequested {
		s.State = "stopped"
	} else {
		s.State = "error"
		if exitErr != nil {
			s.Error = "hook driver exited: " + exitErr.Error()
		} else {
			s.Error = "hook driver exited without a requested detach"
		}
		if !s.Ready {
			s.Error += " (agent was not ready)"
		}
		if s.Diagnostic != "" {
			s.Error = boundedDiagnostic(s.Error + ": " + s.Diagnostic)
		}
	}
	s.Ready = false
	s.Ended = time.Now().UTC()
	if m.history == nil {
		m.history = map[string]*Session{}
	}
	m.history[id] = copySession(s)
	m.historyOrder = append(m.historyOrder, id)
	for len(m.historyOrder) > sessionHistoryLimit {
		delete(m.history, m.historyOrder[0])
		m.historyOrder = m.historyOrder[1:]
	}
	delete(m.sessions, id)
	m.mu.Unlock()
}

func waitSessions(sessions []*Session, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for _, s := range sessions {
		if s.done == nil {
			continue
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("timed out waiting for this manager's hook drivers to exit")
		}
		timer := time.NewTimer(remaining)
		select {
		case <-s.done:
			timer.Stop()
		case <-timer.C:
			return fmt.Errorf("timed out waiting for hook driver %s", s.ID)
		}
	}
	return nil
}

func (m *Manager) stopAll(closeManager bool) error {
	m.launchMu.Lock()
	defer m.launchMu.Unlock()
	m.mu.Lock()
	if closeManager {
		m.closed = true
	}
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		s.stopRequested = true
		s.Ready = false
		s.State = "stopping"
		sessions = append(sessions, s)
	}
	// A worker can have recorded its terminal session while still publishing
	// its final event/removing only its own temp directory. Close waits for it.
	for id, done := range m.workers {
		if m.sessions[id] == nil {
			sessions = append(sessions, &Session{ID: id, done: done})
		}
	}
	m.mu.Unlock()
	for _, s := range sessions {
		if s.cancel != nil {
			s.cancel()
		}
	}
	return waitSessions(sessions, 5*time.Second)
}

func (m *Manager) DetachAll() error { return m.stopAll(false) }
func (m *Manager) StopAll() error   { return m.DetachAll() }
func (m *Manager) Close() error     { return m.stopAll(true) }

// CLI console messages are JSON-lines too. Do not rely on Frida's human REPL
// "message: {...}" formatting to infer script load or readiness.
const cliMessageShim = `(function(){
 var alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
 send=function(payload,data){
  var ev=payload&&typeof payload==='object'?payload:{event:'message',msg:String(payload)};
  if(data){var a=new Uint8Array(data),b='';for(var i=0;i<a.length;i+=3){var x=a[i],y=i+1<a.length?a[i+1]:0,z=i+2<a.length?a[i+2]:0;b+=alphabet[x>>2]+alphabet[((x&3)<<4)|(y>>4)]+(i+1<a.length?alphabet[((y&15)<<2)|(z>>6)]:'=')+(i+2<a.length?alphabet[z&63]:'=');}ev.data_b64=b;}
  console.log(JSON.stringify(ev));
 };
})();
`
