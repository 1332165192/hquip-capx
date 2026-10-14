package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

func (s *Server) scriptsList(w http.ResponseWriter, r *http.Request) {
	if s.script == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.script.List())
}

type scriptAddReq struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

func (s *Server) scriptsAdd(w http.ResponseWriter, r *http.Request) {
	if s.script == nil {
		writeErr(w, http.StatusNotImplemented, "scripting not available")
		return
	}
	var req scriptAddReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if strings.TrimSpace(req.Source) == "" {
		writeErr(w, http.StatusBadRequest, "empty source")
		return
	}
	if req.Name == "" {
		req.Name = "script"
	}
	sc, err := s.script.Add(req.Name, req.Source)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sc)
}

func (s *Server) scriptsDelete(w http.ResponseWriter, r *http.Request) {
	if s.script == nil {
		writeErr(w, http.StatusNotImplemented, "scripting not available")
		return
	}
	if !s.script.Delete(r.PathValue("id")) {
		writeErr(w, http.StatusNotFound, "script not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": r.PathValue("id")})
}

func (s *Server) scriptsLog(w http.ResponseWriter, r *http.Request) {
	if s.script == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	lines, ok := s.script.Log(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "script not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"log": lines})
}
