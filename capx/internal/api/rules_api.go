package api

import (
	"encoding/json"
	"net/http"

	"github.com/hquip/capx/internal/proxy"
)

// rulesList returns all inline Match&Replace rules.
func (s *Server) rulesList(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.Rules().List())
}

// rulesAdd validates and appends a rule.
func (s *Server) rulesAdd(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var rule proxy.Rule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	saved, err := s.proxy.Rules().Add(&rule)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// rulesDelete removes a rule by path id.
func (s *Server) rulesDelete(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	id := r.PathValue("id")
	if !s.proxy.Rules().Delete(id) {
		writeErr(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

// wsRulesList returns all inline WebSocket Match&Replace rules.
func (s *Server) wsRulesList(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.WSRules().List())
}

// wsRulesAdd validates and appends a WebSocket Match&Replace rule.
func (s *Server) wsRulesAdd(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var rule proxy.WSMatchRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	saved, err := s.proxy.WSRules().Add(&rule)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

// wsRulesDelete removes a WebSocket Match&Replace rule by id.
func (s *Server) wsRulesDelete(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	id := r.PathValue("id")
	if !s.proxy.WSRules().Delete(id) {
		writeErr(w, http.StatusNotFound, "ws rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}
