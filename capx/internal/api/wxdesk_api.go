package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/hquip/capx/internal/wxdesk"
)

type wxDesktop interface {
	Available() bool
	Environment() wxdesk.Environment
	Prepare(wxdesk.PrepareOptions) (wxdesk.Package, error)
	StartEnvironment() error
	Windows() ([]wxdesk.Window, error)
	Launch() error
	Show(string) error
	Screenshot(string) ([]byte, error)
	Tap(string, int, int, int, int) error
	Input(string, string) error
	Key(string, string) error
	Scroll(string, int) error
}

func (s *Server) SetWxDesktop(controller *wxdesk.Controller) {
	if controller == nil {
		s.wxdesk = nil
		return
	}
	s.wxdesk = controller
}

func (s *Server) wxdeskReady(w http.ResponseWriter) bool {
	if s.wxdesk == nil || !s.wxdesk.Available() {
		writeErr(w, http.StatusConflict, "独立微信环境尚未连接，请先启动微信沙箱；不会操作本机主号窗口")
		return false
	}
	return true
}

func (s *Server) wxdeskEnvironment(w http.ResponseWriter, r *http.Request) {
	if s.wxdesk == nil {
		writeErr(w, http.StatusNotImplemented, "隔离微信控制不可用")
		return
	}
	writeJSON(w, http.StatusOK, s.wxdesk.Environment())
}

func (s *Server) wxdeskPrepare(w http.ResponseWriter, r *http.Request) {
	if s.wxdesk == nil {
		writeErr(w, http.StatusNotImplemented, "隔离微信控制不可用")
		return
	}
	var request wxdesk.PrepareOptions
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&request); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	result, err := s.wxdesk.Prepare(request)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (s *Server) wxdeskStartEnvironment(w http.ResponseWriter, r *http.Request) {
	if s.wxdesk == nil {
		writeErr(w, http.StatusNotImplemented, "隔离微信控制不可用")
		return
	}
	if err := s.wxdesk.StartEnvironment(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"starting": true})
}

func (s *Server) wxdeskWindows(w http.ResponseWriter, r *http.Request) {
	if !s.wxdeskReady(w) {
		return
	}
	windows, err := s.wxdesk.Windows()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"windows": windows, "available": true, "runtime": "isolated-official-desktop-wechat", "login_status": "unknown"})
}

func (s *Server) wxdeskLaunch(w http.ResponseWriter, r *http.Request) {
	if !s.wxdeskReady(w) {
		return
	}
	if err := s.wxdesk.Launch(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"launched": true})
}

func (s *Server) wxdeskScreenshot(w http.ResponseWriter, r *http.Request) {
	if !s.wxdeskReady(w) {
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("window_id"))
	if id == "" {
		writeErr(w, http.StatusBadRequest, "window_id required")
		return
	}
	png, err := s.wxdesk.Screenshot(id)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(png)
}

type wxdeskActionRequest struct {
	WindowID string `json:"window_id"`
	X        *int   `json:"x"`
	Y        *int   `json:"y"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
	Value    string `json:"value"`
	Key      string `json:"key"`
	Delta    int    `json:"delta"`
}

func (s *Server) wxdeskAction(w http.ResponseWriter, r *http.Request) {
	if !s.wxdeskReady(w) {
		return
	}
	var request wxdeskActionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&request); err != nil || strings.TrimSpace(request.WindowID) == "" {
		writeErr(w, http.StatusBadRequest, "valid body and window_id required")
		return
	}
	var err error
	switch r.PathValue("action") {
	case "show":
		err = s.wxdesk.Show(request.WindowID)
	case "tap":
		if request.X == nil || request.Y == nil || request.Width <= 0 || request.Height <= 0 || *request.X < 0 || *request.Y < 0 || *request.X >= request.Width || *request.Y >= request.Height {
			writeErr(w, http.StatusBadRequest, "valid x/y and screenshot width/height required")
			return
		}
		err = s.wxdesk.Tap(request.WindowID, *request.X, *request.Y, request.Width, request.Height)
	case "input":
		err = s.wxdesk.Input(request.WindowID, request.Value)
	case "key":
		err = s.wxdesk.Key(request.WindowID, request.Key)
	case "scroll":
		err = s.wxdesk.Scroll(request.WindowID, request.Delta)
	default:
		writeErr(w, http.StatusNotFound, "unknown desktop action")
		return
	}
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "window_id": request.WindowID, "action": r.PathValue("action")})
}
