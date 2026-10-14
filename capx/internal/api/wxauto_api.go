package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/hquip/capx/internal/wxauto"
)

func (s *Server) wxhookCDPCall(w http.ResponseWriter, r *http.Request) {
	if s.wxhook == nil {
		writeErr(w, http.StatusNotImplemented, "wxhook disabled")
		return
	}
	var req struct {
		Method    string         `json:"method"`
		Params    map[string]any `json:"params"`
		TimeoutMS int            `json:"timeout_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Method) == "" {
		writeErr(w, http.StatusBadRequest, "method required")
		return
	}
	if !allowedWxCDPMethod(req.Method) {
		writeErr(w, http.StatusBadRequest, "unsupported CDP domain")
		return
	}
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 10 * time.Second
	}
	result, err := s.wxhook.CDPCall(req.Method, req.Params, timeout)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(result)
}

func allowedWxCDPMethod(method string) bool {
	for _, prefix := range []string{"Runtime.", "DOM.", "Input.", "Page.", "Network.", "Emulation."} {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}
	return false
}

func (s *Server) wxautoSnapshot(w http.ResponseWriter, r *http.Request) {
	if s.wxctrl == nil {
		writeErr(w, http.StatusNotImplemented, "mini-program operator is unavailable")
		return
	}
	snapshot, err := s.wxctrl.Snapshot(queryBool(r, "screenshot"))
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) wxautoScreenshot(w http.ResponseWriter, r *http.Request) {
	if s.wxctrl == nil {
		writeErr(w, http.StatusNotImplemented, "mini-program operator is unavailable")
		return
	}
	encoded, err := s.wxctrl.Screenshot()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "decode screenshot: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) wxautoClick(w http.ResponseWriter, r *http.Request) {
	if s.wxctrl == nil {
		writeErr(w, http.StatusNotImplemented, "mini-program operator is unavailable")
		return
	}
	var req wxauto.Locator
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || locatorEmpty(req) {
		writeErr(w, http.StatusBadRequest, "element_id, selector, or text required")
		return
	}
	result, err := s.wxctrl.Click(req)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) wxautoInput(w http.ResponseWriter, r *http.Request) {
	if s.wxctrl == nil {
		writeErr(w, http.StatusNotImplemented, "mini-program operator is unavailable")
		return
	}
	var req struct {
		wxauto.Locator
		Value string `json:"value"`
		Clear *bool  `json:"clear"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || locatorEmpty(req.Locator) {
		writeErr(w, http.StatusBadRequest, "element_id, selector, or text required")
		return
	}
	clear := true
	if req.Clear != nil {
		clear = *req.Clear
	}
	result, err := s.wxctrl.Input(req.Locator, req.Value, clear)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) wxautoScroll(w http.ResponseWriter, r *http.Request) {
	if s.wxctrl == nil {
		writeErr(w, http.StatusNotImplemented, "mini-program operator is unavailable")
		return
	}
	var req struct {
		DeltaX float64 `json:"delta_x"`
		DeltaY float64 `json:"delta_y"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.DeltaX == 0 && req.DeltaY == 0 {
		req.DeltaY = 560
	}
	if err := s.wxctrl.Scroll(req.DeltaX, req.DeltaY); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"delta_x": req.DeltaX, "delta_y": req.DeltaY})
}

func (s *Server) wxautoBack(w http.ResponseWriter, r *http.Request) {
	if s.wxctrl == nil {
		writeErr(w, http.StatusNotImplemented, "mini-program operator is unavailable")
		return
	}
	if err := s.wxctrl.Back(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"back": "ok"})
}

func (s *Server) wxautoStart(w http.ResponseWriter, r *http.Request) {
	if s.wxauto == nil || s.wxhook == nil {
		writeErr(w, http.StatusNotImplemented, "mini-program automation is unavailable")
		return
	}
	status := s.wxhook.CDPStatus()
	if connected, _ := status["miniapp_connected"].(bool); !connected {
		writeErr(w, http.StatusConflict, "mini-program CDP is not connected")
		return
	}
	var config wxauto.AutoConfig
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&config)
	}
	run, err := s.wxauto.Start(config)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) wxautoStop(w http.ResponseWriter, r *http.Request) {
	if s.wxauto == nil {
		writeErr(w, http.StatusNotImplemented, "mini-program automation is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, s.wxauto.Stop())
}

func (s *Server) wxautoStatus(w http.ResponseWriter, r *http.Request) {
	if s.wxauto == nil {
		writeErr(w, http.StatusNotImplemented, "mini-program automation is unavailable")
		return
	}
	run := s.wxauto.Status()
	if run == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "idle"})
		return
	}
	writeJSON(w, http.StatusOK, run)
}

func locatorEmpty(locator wxauto.Locator) bool {
	return strings.TrimSpace(locator.ElementID) == "" && strings.TrimSpace(locator.Selector) == "" && strings.TrimSpace(locator.Text) == ""
}

func queryBool(r *http.Request, name string) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
