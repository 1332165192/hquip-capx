package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/hquip/capx/internal/hook"
)

// hookBackend reports the hook engine backend ("frida"/"stub"/"disabled").
func (s *Server) hookBackend() string {
	if s.hook == nil {
		return "disabled"
	}
	return s.hook.Backend()
}

func (s *Server) hookStatus(w http.ResponseWriter, r *http.Request) {
	if s.hook == nil {
		writeJSON(w, http.StatusOK, map[string]any{"backend": "disabled", "available": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"backend":   s.hook.Backend(),
		"available": s.hook.Available(),
		"sessions":  s.hook.Sessions(),
		"frida":     s.hook.FridaPath(),
		"version":   s.hook.FridaVersion(),
	})
}

func (s *Server) hookProcs(w http.ResponseWriter, r *http.Request) {
	if s.hook == nil {
		writeErr(w, http.StatusNotImplemented, "hook engine disabled")
		return
	}
	procs, err := s.hook.ListProcesses()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, procs)
}

func (s *Server) hookSessions(w http.ResponseWriter, r *http.Request) {
	if s.hook == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.hook.Sessions())
}

type hookAttachReq struct {
	PID   uint32   `json:"pid"`
	Agent string   `json:"agent"`
	Spawn string   `json:"spawn"` // program path to spawn+hook (captures startup TLS)
	Args  []string `json:"args"`  // arguments for the spawned program
}

func (s *Server) hookAttach(w http.ResponseWriter, r *http.Request) {
	if s.hook == nil {
		writeErr(w, http.StatusNotImplemented, "hook engine disabled")
		return
	}
	var req hookAttachReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	var (
		sess any
		err  error
	)
	switch {
	case req.Spawn != "":
		sess, err = s.hook.AttachSpawn(req.Spawn, req.Args, req.Agent)
	case req.PID != 0:
		sess, err = s.hook.Attach(req.PID, req.Agent)
	default:
		writeErr(w, http.StatusBadRequest, "pid or spawn required")
		return
	}
	if err != nil {
		writeErr(w, http.StatusNotImplemented, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sess)
}

type hookDetachReq struct {
	Session string `json:"session"`
}

func (s *Server) hookDetach(w http.ResponseWriter, r *http.Request) {
	if s.hook == nil {
		writeErr(w, http.StatusNotImplemented, "hook engine disabled")
		return
	}
	var req hookDetachReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := s.hook.Detach(req.Session); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"detached": req.Session})
}

func (s *Server) hookEvents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.st.ListHookEvents())
}

// hookAgentsList returns the available agent names (builtin + uploaded custom).
func (s *Server) hookAgentsList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"agents": hook.ListAgents()})
}

// hookAgentUpload registers a custom Frida JS agent under a name so it can then
// be passed to /api/hook/attach like a builtin. Uploading executable hook code
// is an active operation (gated by the security policy).
func (s *Server) hookAgentUpload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name   string `json:"name"`
		Script string `json:"script"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Script) == "" {
		writeErr(w, http.StatusBadRequest, "name and script required")
		return
	}
	if _, builtin := map[string]bool{"tls": true, "java": true, "android": true, "java_tls": true}[req.Name]; builtin {
		writeErr(w, http.StatusConflict, "name shadows a builtin agent; choose another")
		return
	}
	hook.RegisterAgent(req.Name, []byte(req.Script))
	writeJSON(w, http.StatusOK, map[string]any{"registered": req.Name, "agents": hook.ListAgents()})
}

// hookAgentDelete removes a previously uploaded custom agent.
func (s *Server) hookAgentDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ok := hook.UnregisterAgent(name)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": ok})
}
