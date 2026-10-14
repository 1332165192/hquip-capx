package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/hquip/capx/internal/setup"
	"github.com/hquip/capx/internal/wxhook"
)

// wxhookStatus reports the WeChat mini-program DevTools hook backend + injected pids.
func (s *Server) wxhookStatus(w http.ResponseWriter, r *http.Request) {
	status := map[string]any{"backend": "disabled", "available": false}
	if s.wxhook != nil {
		status = s.wxhook.Status()
	}
	s.wxCaptureMu.Lock()
	if engine := s.wxCaptureController(); engine != nil {
		status["capture"] = engine.CaptureStatus()
	}
	if s.wxCaptureMode == "windivert" && s.inline != nil {
		on, port, _ := s.inline.RedirectStatus()
		status["capture"] = &wxhook.CaptureResult{Enabled: on, Running: on, Port: port, Transport: "windivert"}
	}
	status["capture_transport"] = s.wxCaptureTransportLocked()
	s.wxCaptureMu.Unlock()
	writeJSON(w, http.StatusOK, status)
}

// wxhookProcs lists WeChatAppEx processes (main host flagged, version detected).
func (s *Server) wxhookProcs(w http.ResponseWriter, r *http.Request) {
	if s.wxhook == nil {
		writeErr(w, http.StatusNotImplemented, "wxhook disabled")
		return
	}
	procs, err := s.wxhook.Procs()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, procs)
}

type wxhookEnableReq struct {
	PID uint32 `json:"pid"` // 0 = auto-select the main WMPF host
}

// wxhookEnable injects the version-matched Frida agent to force-open DevTools.
func (s *Server) wxhookEnable(w http.ResponseWriter, r *http.Request) {
	if s.wxhook == nil {
		writeErr(w, http.StatusNotImplemented, "wxhook disabled")
		return
	}
	var req wxhookEnableReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	res, err := s.wxhook.Enable(req.PID)
	if err != nil {
		writeErr(w, http.StatusNotImplemented, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// wxhookDisable detaches all active wxhook sessions.
func (s *Server) wxhookDisable(w http.ResponseWriter, r *http.Request) {
	if s.wxhook == nil {
		writeErr(w, http.StatusNotImplemented, "wxhook disabled")
		return
	}
	if err := s.wxhook.Disable(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"disabled": "ok"})
}

type wxhookCaptureReq struct {
	PID           uint32   `json:"pid"`
	PIDs          []uint32 `json:"pids"`
	Watch         *bool    `json:"watch"`
	UpstreamProxy string   `json:"upstream_proxy"` // auto (default), direct, or a local HTTP URL
}

// Existing-proxy traffic speaks HTTP/CONNECT, not transparent TLS. It gets a
// separate explicit bridge, with its own upstream transport; no OS setting or
// existing explicit proxy is changed by this endpoint.
func (s *Server) wxhookCaptureStart(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "mini-program capture needs the MITM proxy")
		return
	}
	var req wxhookCaptureReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid capture configuration")
		return
	}
	if len(req.PIDs) > 128 {
		writeErr(w, http.StatusBadRequest, "too many process IDs")
		return
	}
	pids := append([]uint32(nil), req.PIDs...)
	if req.PID != 0 {
		pids = append(pids, req.PID)
	}
	watch := req.Watch == nil || *req.Watch
	selection := strings.TrimSpace(req.UpstreamProxy)
	var upstream string
	var err error
	switch strings.ToLower(selection) {
	case "", "auto":
		var cfg setup.SystemProxyConfig
		cfg, err = s.readWXSystemProxy()
		if err == nil {
			upstream, err = captureSystemUpstream(cfg)
		}
	case "direct":
	default:
		upstream, err = normalizeCaptureUpstream(selection)
	}
	if err != nil {
		writeErr(w, http.StatusConflict, "上游代理配置: "+err.Error())
		return
	}
	if upstream != "" {
		_, port, _ := net.SplitHostPort(strings.TrimPrefix(upstream, "http://"))
		if _, apiPort, splitErr := net.SplitHostPort(r.Host); splitErr == nil && port == apiPort {
			writeErr(w, http.StatusConflict, "上游不能指向当前 Capx API 端口")
			return
		}
	}
	s.wxCaptureMu.Lock()
	defer s.wxCaptureMu.Unlock()
	engine := s.wxCaptureController()
	frida := engine != nil && engine.Available()
	if upstream != "" && !frida {
		writeErr(w, http.StatusConflict, "已有代理链需要可用的 Frida 重定向；WinDivert 的 80/443 规则不覆盖本地代理端口")
		return
	}
	if !frida && (s.inline == nil || !s.inline.Available()) {
		writeErr(w, http.StatusConflict, "Frida 不可用，且此构建没有可用的 WinDivert 重定向；未修改系统代理")
		return
	}
	wasEnabled := s.wxCaptureMode != ""
	if engine != nil {
		wasEnabled = wasEnabled || engine.CaptureStatus().Enabled
	}
	if wasEnabled && upstream != s.wxCaptureUpstream {
		writeErr(w, http.StatusConflict, "抓包已启用；请先停止，再切换上游配置")
		return
	}
	transparentOn, transparentAddr := s.proxy.TransparentStatus()
	createdTransparent, createdBridge := false, false
	rollback := func() {
		if createdBridge {
			_ = s.proxy.StopCaptureBridge()
		}
		if createdTransparent {
			_ = s.proxy.StopTransparent()
		}
	}
	if !transparentOn {
		if err := s.proxy.StartTransparent("127.0.0.1:0"); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		createdTransparent = true
		_, transparentAddr = s.proxy.TransparentStatus()
	}
	host, portText, splitErr := net.SplitHostPort(transparentAddr)
	ip := net.ParseIP(host)
	port, portErr := strconv.Atoi(portText)
	if splitErr != nil || portErr != nil || ip == nil || !ip.IsLoopback() || ip.To4() == nil || port <= 0 {
		rollback()
		writeErr(w, http.StatusConflict, "直抓监听必须是 IPv4 回环 TCP 地址")
		return
	}
	bridgeAddr, explicitPort := "", 0
	if upstream != "" {
		bridgeWasOn, _, bridgeUpstream := s.proxy.CaptureBridgeStatus()
		if bridgeWasOn && bridgeUpstream != upstream {
			rollback()
			writeErr(w, http.StatusConflict, "当前抓包桥已使用不同上游，请先停止")
			return
		}
		bridgeAddr, err = s.proxy.StartCaptureBridge(upstream)
		if err != nil {
			rollback()
			writeErr(w, http.StatusConflict, "创建代理链失败: "+err.Error())
			return
		}
		createdBridge = !bridgeWasOn
		_, p, _ := net.SplitHostPort(bridgeAddr)
		explicitPort, _ = strconv.Atoi(p)
	}
	mode := "direct"
	if upstream != "" {
		mode = "proxy-chain"
	}
	var capture *wxhook.CaptureResult
	if frida {
		capture, err = engine.CaptureStartWithOptions(wxhook.CaptureOptions{Port: port, ExplicitPort: explicitPort, UpstreamProxy: upstream}, uniqueUint32(pids), watch)
		if err != nil {
			// Do not tear down a previously working capture for a failed add-PID.
			if !wasEnabled {
				if stopErr := engine.CaptureStop(); stopErr == nil {
					rollback()
				} else {
					s.wxCaptureOwnProxy = s.wxCaptureOwnProxy || createdTransparent
					s.wxCaptureOwnBridge = s.wxCaptureOwnBridge || createdBridge
					s.wxCaptureMode, s.wxCaptureUpstream = mode, upstream
					err = fmt.Errorf("%v; 清理失败，保留监听: %w", err, stopErr)
				}
			}
			message := "直抓未就绪: " + err.Error()
			if capture != nil && len(capture.Errors) != 0 {
				message += fmt.Sprintf("; 按PID错误: %v", capture.Errors)
			}
			writeJSON(w, http.StatusConflict, map[string]any{"error": message, "capture": capture, "capture_transport": s.wxCaptureTransportLocked()})
			return
		}
	} else {
		// Preserve the documented direct-only optional kernel backend, but never
		// silently replace a redirection owned by another feature in this instance.
		on, activePort, _ := s.inline.RedirectStatus()
		if on && activePort != port {
			rollback()
			writeErr(w, http.StatusConflict, "当前实例的内核重定向已由其他监听使用")
			return
		}
		if !on {
			skip := 0
			if _, mitm := s.proxy.Status(); mitm != "" {
				_, skip, _ = parseListenPort(mitm)
			}
			if err := s.inline.StartRedirect(port, skip); err != nil {
				rollback()
				writeErr(w, http.StatusConflict, err.Error())
				return
			}
			s.wxCaptureOwnRedirect = true
		}
		mode = "windivert"
		capture = &wxhook.CaptureResult{Enabled: true, Running: true, Port: port, Transport: "windivert"}
	}
	s.wxCaptureOwnProxy = s.wxCaptureOwnProxy || createdTransparent
	s.wxCaptureOwnBridge = s.wxCaptureOwnBridge || createdBridge
	s.wxCaptureMode, s.wxCaptureUpstream = mode, upstream
	hint := "监测配置已启用；是否可抓取以脚本就绪和实际新连接为准。已有连接不会迁移，不会自动重启微信或修改系统代理。"
	if upstream != "" {
		hint += " 新的原代理连接 → Capx显式桥 " + bridgeAddr + " → " + upstream + "；此桥暂不支持 WebSocket。"
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode, "capture": capture, "transparent_addr": transparentAddr, "bridge_addr": bridgeAddr, "upstream_proxy": upstream, "hint": hint, "capture_transport": s.wxCaptureTransportLocked()})
}

func (s *Server) wxhookCaptureStop(w http.ResponseWriter, r *http.Request) {
	s.wxCaptureMu.Lock()
	defer s.wxCaptureMu.Unlock()
	if err := s.stopWXCaptureLocked(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"stopped": "ok"})
}

func uniqueUint32(values []uint32) []uint32 {
	seen := map[uint32]struct{}{}
	out := make([]uint32, 0, len(values))
	for _, value := range values {
		if value == 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// wxhookCDPStatus reports the DevTools CDP bridge state + devtools URL.
func (s *Server) wxhookCDPStatus(w http.ResponseWriter, r *http.Request) {
	if s.wxhook == nil {
		writeJSON(w, http.StatusOK, map[string]any{"running": false})
		return
	}
	writeJSON(w, http.StatusOK, s.wxhook.CDPStatus())
}

// wxhookCDPStart starts the DevTools CDP bridge (debug server :9421 + CDP proxy).
func (s *Server) wxhookCDPStart(w http.ResponseWriter, r *http.Request) {
	if s.wxhook == nil {
		writeErr(w, http.StatusNotImplemented, "wxhook disabled")
		return
	}
	var req struct {
		Endpoint string `json:"endpoint"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid body")
			return
		}
	}
	res, err := s.wxhook.CDPStart(req.Endpoint)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// wxhookCDPStop stops the DevTools CDP bridge.
func (s *Server) wxhookCDPStop(w http.ResponseWriter, r *http.Request) {
	if s.wxhook == nil {
		writeErr(w, http.StatusNotImplemented, "wxhook disabled")
		return
	}
	_ = s.wxhook.CDPStop()
	writeJSON(w, http.StatusOK, map[string]string{"stopped": "ok"})
}

// wxhookCDPEval runs a JS expression in the connected mini-program (routes /
// cloud function call / jump are built on this).
func (s *Server) wxhookCDPEval(w http.ResponseWriter, r *http.Request) {
	if s.wxhook == nil {
		writeErr(w, http.StatusNotImplemented, "wxhook disabled")
		return
	}
	var req struct {
		Expression string `json:"expression"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Expression) == "" {
		writeErr(w, http.StatusBadRequest, "缺少 expression")
		return
	}
	res, err := s.wxhook.CDPEval(req.Expression)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write([]byte(res))
}
