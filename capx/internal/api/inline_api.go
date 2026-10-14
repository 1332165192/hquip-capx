package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/hquip/capx/internal/inline"
)

func (s *Server) inlineBackend() string {
	if s.inline == nil {
		return "n/a"
	}
	return s.inline.Backend()
}

func (s *Server) inlineStatus(w http.ResponseWriter, r *http.Request) {
	if s.inline == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "backend": "n/a"})
		return
	}
	running, filter := s.inline.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"available": s.inline.Available(),
		"backend":   s.inline.Backend(),
		"running":   running,
		"filter":    filter,
	})
}

type inlineStartReq struct {
	Filter string `json:"filter"`
}

func (s *Server) inlineStart(w http.ResponseWriter, r *http.Request) {
	if s.inline == nil {
		writeErr(w, http.StatusNotImplemented, "inline not available")
		return
	}
	var req inlineStartReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if err := s.inline.Start(req.Filter); err != nil {
		writeErr(w, http.StatusNotImplemented, err.Error())
		return
	}
	running, filter := s.inline.Status()
	writeJSON(w, http.StatusOK, map[string]any{"running": running, "filter": filter})
}

func (s *Server) inlineStop(w http.ResponseWriter, r *http.Request) {
	if s.inline == nil {
		writeErr(w, http.StatusNotImplemented, "inline not available")
		return
	}
	if err := s.inline.Stop(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"stopped": "ok"})
}

type inlineSendReq struct {
	Packet   string `json:"packet"` // hex
	Outbound bool   `json:"outbound"`
}

func (s *Server) inlineSend(w http.ResponseWriter, r *http.Request) {
	if s.inline == nil {
		writeErr(w, http.StatusNotImplemented, "inline not available")
		return
	}
	var req inlineSendReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if err := s.inline.Send(req.Packet, req.Outbound); err != nil {
		writeErr(w, http.StatusNotImplemented, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"sent": "ok"})
}

func (s *Server) inlineRulesList(w http.ResponseWriter, r *http.Request) {
	if s.inline == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.inline.Engine().List())
}

func (s *Server) inlineRulesAdd(w http.ResponseWriter, r *http.Request) {
	if s.inline == nil {
		writeErr(w, http.StatusNotImplemented, "inline not available")
		return
	}
	var rule inline.PacketRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	rule.Proto = strings.ToLower(strings.TrimSpace(rule.Proto))
	saved, err := s.inline.Engine().Add(&rule)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) inlineRulesDelete(w http.ResponseWriter, r *http.Request) {
	if s.inline == nil {
		writeErr(w, http.StatusNotImplemented, "inline not available")
		return
	}
	id := r.PathValue("id")
	if !s.inline.Engine().Delete(id) {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}
