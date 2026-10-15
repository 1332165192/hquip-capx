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

type mobileUIController interface {
	SnapshotWithInfo() (mobile.SnapshotInfo, error)
	Screenshot() ([]byte, error)
	Tap(int, int) error
	Click(mobile.Locator) (mobile.Element, error)
	Input(string) error
	Swipe(int, int, int, int, int) error
	Key(string) error
	Back() error
	Home() error
	LaunchApp(string) error
	ForegroundApp() (string, error)
}

func mobileIsIOS(r *http.Request) bool { return r.URL.Query().Get("platform") == "ios" }

func (s *Server) mobileUIForRequest(r *http.Request) mobileUIController {
	if mobileIsIOS(r) {
		return s.ios
	}
	return s.mobileForRequest(r)
}

func (s *Server) mobileIOSConnect(w http.ResponseWriter, r *http.Request) {
	if s.ios == nil {
		writeErr(w, http.StatusNotImplemented, "iOS controller unavailable")
		return
	}
	var req struct {
		Endpoint string `json:"endpoint"`
		Session  string `json:"session_id"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	status, err := s.ios.ConnectContext(r.Context(), req.Endpoint, req.Session)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) mobileIOSDisconnect(w http.ResponseWriter, r *http.Request) {
	if s.ios == nil {
		writeErr(w, http.StatusNotImplemented, "iOS controller unavailable")
		return
	}
	s.ios.Disconnect()
	writeJSON(w, http.StatusOK, map[string]string{"status": "disconnected"})
}

func mobileAndroidOnly(w http.ResponseWriter, r *http.Request) bool {
	if mobileIsIOS(r) {
		writeErr(w, http.StatusConflict, "iPhone 抓包请使用 Wi-Fi 代理入口，并在手机设置中安装 CA、开启完全信任；WDA 不配置网络代理")
		return false
	}
	return true
}

func (s *Server) mobileIOSSetup(w http.ResponseWriter, r *http.Request) {
	if s.iosPrepare == nil {
		writeErr(w, http.StatusNotImplemented, "iOS setup unavailable")
		return
	}
	writeJSON(w, http.StatusOK, s.iosPrepare.Inspect(r.Context()))
}
func (s *Server) mobileIOSPrepareStatus(w http.ResponseWriter, r *http.Request) {
	if s.iosPrepare == nil {
		writeErr(w, http.StatusNotImplemented, "iOS setup unavailable")
		return
	}
	writeJSON(w, http.StatusOK, s.iosPrepare.Status())
}
func (s *Server) mobileIOSPrepare(w http.ResponseWriter, r *http.Request) {
	if s.iosPrepare == nil {
		writeErr(w, http.StatusNotImplemented, "iOS setup unavailable")
		return
	}
	var req mobile.IOSPrepareRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	job, err := s.iosPrepare.Begin(req)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}
func (s *Server) mobileIOSPrepareStop(w http.ResponseWriter, r *http.Request) {
	if s.iosPrepare == nil {
		writeErr(w, http.StatusNotImplemented, "iOS setup unavailable")
		return
	}
	writeJSON(w, http.StatusOK, s.iosPrepare.Stop())
}
func (s *Server) CloseMobileTools() {
	if s.iosPrepare != nil {
		s.iosPrepare.Close()
	}
}

func (s *Server) mobileCA(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) || !mobileAndroidOnly(w, r) {
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
func (s *Server) mobileReady(w http.ResponseWriter, r *http.Request) bool {
	platform := r.URL.Query().Get("platform")
	if platform != "" && platform != "android" && platform != "ios" {
		writeErr(w, http.StatusBadRequest, "platform must be android or ios")
		return false
	}
	if mobileIsIOS(r) {
		if s.ios == nil {
			writeErr(w, http.StatusNotImplemented, "iOS controller unavailable")
			return false
		}
		serial := r.URL.Query().Get("serial")
		if serial != "" && serial != mobile.IOSSerial {
			writeErr(w, http.StatusBadRequest, "unknown iOS device")
			return false
		}
		return true
	}
	if s.mobile == nil {
		writeErr(w, http.StatusNotImplemented, "mobile (Android) capture is unavailable")
		return false
	}
	return true
}

func (s *Server) mobileDevices(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
		return
	}
	var devs []mobile.Device
	var err error
	if mobileIsIOS(r) {
		devs, err = s.ios.Devices()
	} else {
		devs, err = s.mobile.Devices()
	}
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devs})
}

func (s *Server) mobileStatus(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
		return
	}
	if mobileIsIOS(r) {
		status, err := s.ios.Status()
		if err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		running, _ := s.mobileProxyPort()
		status["proxy_running"] = running
		writeJSON(w, http.StatusOK, status)
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
	if !s.mobileReady(w, r) {
		return
	}
	var req struct {
		Serial string `json:"serial"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if mobileIsIOS(r) {
		if req.Serial != "" && req.Serial != mobile.IOSSerial {
			writeErr(w, http.StatusBadRequest, "unknown iOS device")
			return
		}
	} else {
		s.mobile.Use(req.Serial)
	}
	writeJSON(w, http.StatusOK, map[string]string{"serial": strings.TrimSpace(req.Serial)})
}

func (s *Server) mobileCaptureStart(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) || !mobileAndroidOnly(w, r) {
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
	if !s.mobileReady(w, r) || !mobileAndroidOnly(w, r) {
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
	if !s.mobileReady(w, r) {
		return
	}
	snapshot, err := s.mobileUIForRequest(r).SnapshotWithInfo()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) mobileScreenshot(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
		return
	}
	var png []byte
	var err error
	if mobileIsIOS(r) {
		var size mobile.ScreenSize
		png, size, err = s.ios.ScreenshotWithSize()
		if err == nil {
			w.Header().Set("X-Capx-Screen-Width", strconv.FormatFloat(size.Width, 'f', -1, 64))
			w.Header().Set("X-Capx-Screen-Height", strconv.FormatFloat(size.Height, 'f', -1, 64))
			w.Header().Set("X-Capx-Coordinate-Space", "points")
		}
	} else {
		png, err = s.mobileForRequest(r).Screenshot()
	}
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

func (s *Server) mobileTap(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
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
		if err := s.mobileUIForRequest(r).Tap(*req.X, *req.Y); err != nil {
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
	el, err := s.mobileUIForRequest(r).Click(req.Locator)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, el)
}

func (s *Server) mobileInput(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
		return
	}
	var req struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.mobileUIForRequest(r).Input(req.Value); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"input": "ok"})
}

func (s *Server) mobileSwipe(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
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
	if err := s.mobileUIForRequest(r).Swipe(req.X1, req.Y1, req.X2, req.Y2, req.DurationMS); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"swipe": "ok"})
}

func (s *Server) mobileKey(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
		return
	}
	var req struct {
		Keycode string `json:"keycode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.mobileUIForRequest(r).Key(req.Keycode); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"key": req.Keycode})
}

func (s *Server) mobileBack(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
		return
	}
	if err := s.mobileUIForRequest(r).Back(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"back": "ok"})
}

func (s *Server) mobileLaunch(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
		return
	}
	var req struct {
		Package string `json:"package"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.mobileUIForRequest(r).LaunchApp(req.Package); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"launched": strings.TrimSpace(req.Package)})
}

func (s *Server) mobileForeground(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
		return
	}
	pkg, err := s.mobileUIForRequest(r).ForegroundApp()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"package": pkg})
}

func (s *Server) mobileHome(w http.ResponseWriter, r *http.Request) {
	if !s.mobileReady(w, r) {
		return
	}
	if err := s.mobileUIForRequest(r).Home(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"home": "ok"})
}
