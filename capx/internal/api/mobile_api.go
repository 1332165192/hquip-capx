package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/hquip/capx/internal/mobile"
)

func (s *Server) mobileForRequest(r *http.Request) *mobile.Controller {
	return s.mobile.ForDevice(r.URL.Query().Get("serial"))
}

func (s *Server) mobileCA(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	if s.proxy == nil {
		writeErr(w, http.StatusConflict, "proxy CA unavailable")
		return
	}
	note, err := s.mobileForRequest(r).InstallCA(s.proxy.CA().CertPEM())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ca_note": note})
}

// mobileEnabled guards every handler; the Android controller is optional.
func (s *Server) mobileReady(w http.ResponseWriter) bool {
	if s.mobile == nil {
		writeErr(w, http.StatusNotImplemented, "mobile (Android) capture is unavailable")
		return false
	}
	return true
}

func (s *Server) mobileDevices(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	devs, err := s.mobile.Devices()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devs})
}

func (s *Server) mobileStatus(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	status, err := s.mobileForRequest(r).Status()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	running, port := s.mobileProxyPort()
	status["proxy_running"] = running
	status["wired"] = status["wired"] == true && running && status["proxy"] == "127.0.0.1:"+strconv.Itoa(port)
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) mobileProxyPort() (bool, int) {
	if s.proxy == nil {
		return false, 0
	}
	running, addr := s.proxy.Status()
	_, port, err := parseListenPort(addr)
	return running && err == nil, port
}

func (s *Server) mobileUse(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	var req struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	s.mobile.Use(req.Serial)
	writeJSON(w, http.StatusOK, map[string]string{"serial": strings.TrimSpace(req.Serial)})
}

func (s *Server) mobileCaptureStart(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	var req struct {
		ProxyPort int  `json:"proxy_port"`
		InstallCA bool `json:"install_ca"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.ProxyPort < 0 || req.ProxyPort > 65535 {
		writeErr(w, http.StatusBadRequest, "invalid proxy_port")
		return
	}
	running, port := s.mobileProxyPort()
	if !running {
		writeErr(w, http.StatusConflict, "请先启动当前实例的 MITM 代理")
		return
	}
	if req.ProxyPort == 0 {
		req.ProxyPort = port
	}
	if req.ProxyPort != port {
		writeErr(w, http.StatusConflict, "proxy_port 与当前实例的 MITM 监听端口不一致")
		return
	}
	var caPEM []byte
	if req.InstallCA {
		if s.proxy == nil {
			writeErr(w, http.StatusConflict, "proxy CA unavailable; cannot install certificate")
			return
		}
		caPEM = s.proxy.CA().CertPEM()
	}
	info, err := s.mobileForRequest(r).StartCapture(req.ProxyPort, caPEM)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) mobileCaptureStop(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	var req struct {
		ProxyPort int `json:"proxy_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.ProxyPort < 0 || req.ProxyPort > 65535 {
		writeErr(w, http.StatusBadRequest, "invalid proxy_port")
		return
	}
	if err := s.mobileForRequest(r).StopCapture(req.ProxyPort); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"capture": "stopped"})
}

func (s *Server) mobileSnapshot(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	snapshot, err := s.mobileForRequest(r).SnapshotWithInfo()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) mobileScreenshot(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	png, err := s.mobileForRequest(r).Screenshot()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func (s *Server) mobileTap(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	var req struct {
		mobile.Locator
		X *int `json:"x"`
		Y *int `json:"y"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	// Coordinate tap when x/y are present, else locate-and-tap.
	if (req.X == nil) != (req.Y == nil) {
		writeErr(w, http.StatusBadRequest, "x and y must be supplied together")
		return
	}
	if req.X != nil && req.Y != nil {
		if *req.X < 0 || *req.Y < 0 {
			writeErr(w, http.StatusBadRequest, "invalid coordinates")
			return
		}
		if err := s.mobileForRequest(r).Tap(*req.X, *req.Y); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"x": *req.X, "y": *req.Y})
		return
	}
	if strings.TrimSpace(req.Text) == "" && strings.TrimSpace(req.ResourceID) == "" && strings.TrimSpace(req.Desc) == "" {
		writeErr(w, http.StatusBadRequest, "locator required")
		return
	}
	el, err := s.mobileForRequest(r).Click(req.Locator)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, el)
}

func (s *Server) mobileInput(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.mobileForRequest(r).Input(req.Value); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"input": "ok"})
}

func (s *Server) mobileSwipe(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	var req struct {
		X1         int `json:"x1"`
		Y1         int `json:"y1"`
		X2         int `json:"x2"`
		Y2         int `json:"y2"`
		DurationMS int `json:"duration_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.mobileForRequest(r).Swipe(req.X1, req.Y1, req.X2, req.Y2, req.DurationMS); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"swipe": "ok"})
}

func (s *Server) mobileKey(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	var req struct {
		Keycode string `json:"keycode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.mobileForRequest(r).Key(req.Keycode); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"key": req.Keycode})
}

func (s *Server) mobileBack(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	if err := s.mobileForRequest(r).Back(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"back": "ok"})
}

func (s *Server) mobileLaunch(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	var req struct {
		Package string `json:"package"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.mobileForRequest(r).LaunchApp(req.Package); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"launched": strings.TrimSpace(req.Package)})
}

func (s *Server) mobileForeground(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w) {
		return
	}
	pkg, err := s.mobileForRequest(r).ForegroundApp()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"package": pkg})
}
