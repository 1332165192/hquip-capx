package api

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/hquip/capx/internal/setup"
	"github.com/hquip/capx/internal/wxhook"
)

// Kept separate from the DevTools manager so transport lifecycle tests use
// inert controllers, never a real Frida attach or a system proxy change.
type wxCaptureEngine interface {
	Available() bool
	CaptureStartWithOptions(wxhook.CaptureOptions, []uint32, bool) (*wxhook.CaptureResult, error)
	CaptureStatus() *wxhook.CaptureResult
	CaptureStop() error
}

type wxCaptureTransport struct {
	Mode               string `json:"mode"`
	TransparentRunning bool   `json:"transparent_running"`
	TransparentAddr    string `json:"transparent_addr,omitempty"`
	BridgeRunning      bool   `json:"bridge_running"`
	BridgeAddr         string `json:"bridge_addr,omitempty"`
	BridgeWSSupported  bool   `json:"bridge_ws_supported"`
	UpstreamProxy      string `json:"upstream_proxy,omitempty"`
	SystemProxy        string `json:"system_proxy,omitempty"`
	RedirectRunning    bool   `json:"redirect_running"`
	Warning            string `json:"warning,omitempty"`
}

func normalizeCaptureUpstream(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("请填写本地 HTTP 上游代理，例如 http://127.0.0.1:7897")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("当前小程序代理链只支持不含凭证、路径或查询串的本地 HTTP 代理地址")
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !ip.IsLoopback() || strings.Contains(host, ":") {
		return "", errors.New("当前小程序代理链只支持 IPv4 回环 HTTP 代理（127.0.0.1），不自动改写 IPv6/SOCKS/PAC")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("本地 HTTP 上游代理需要有效端口")
	}
	return "http://" + net.JoinHostPort(ip.To4().String(), strconv.Itoa(port)), nil
}

// WinINet can encode a single proxy or per-scheme endpoints. Do not silently
// select just one member of a PAC/SOCKS/mixed configuration for all traffic.
func captureSystemUpstream(cfg setup.SystemProxyConfig) (string, error) {
	if cfg.PAC {
		return "", errors.New("检测到 PAC/自动代理，无法推断小程序实际上游；请手动填写已确认的本地 HTTP 代理")
	}
	if !cfg.Enabled {
		return "", nil
	}
	raw := strings.TrimSpace(cfg.Server)
	if !strings.Contains(raw, "=") {
		return normalizeCaptureUpstream(raw)
	}
	var httpProxy, httpsProxy string
	for _, item := range strings.Split(raw, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(item), "=")
		if !ok {
			return "", errors.New("系统代理格式无法自动解析，请手动填写 HTTP 上游")
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "http":
			httpProxy = strings.TrimSpace(value)
		case "https":
			httpsProxy = strings.TrimSpace(value)
		}
	}
	if httpProxy == "" || httpsProxy == "" {
		return "", errors.New("系统代理没有统一的 HTTP/HTTPS 上游，请手动填写本地 HTTP 代理")
	}
	a, err := normalizeCaptureUpstream(httpProxy)
	if err != nil {
		return "", err
	}
	b, err := normalizeCaptureUpstream(httpsProxy)
	if err != nil {
		return "", err
	}
	if a != b {
		return "", errors.New("HTTP 与 HTTPS 系统代理不同；本入口不自动合并，请选择明确的本地 HTTP 上游")
	}
	return a, nil
}

func (s *Server) readWXSystemProxy() (setup.SystemProxyConfig, error) {
	if s.wxSystemProxy != nil {
		return s.wxSystemProxy()
	}
	return setup.ReadSystemProxyConfig()
}

func (s *Server) wxCaptureController() wxCaptureEngine {
	if s.wxCaptureEngine != nil {
		return s.wxCaptureEngine
	}
	if s.wxhook != nil {
		return s.wxhook
	}
	return nil
}

func (s *Server) wxCaptureTransportLocked() wxCaptureTransport {
	t := wxCaptureTransport{Mode: s.wxCaptureMode, UpstreamProxy: s.wxCaptureUpstream}
	if t.Mode == "" {
		t.Mode = "idle"
	}
	if s.proxy != nil {
		t.TransparentRunning, t.TransparentAddr = s.proxy.TransparentStatus()
		t.BridgeRunning, t.BridgeAddr, _ = s.proxy.CaptureBridgeStatus()
	}
	if s.inline != nil {
		t.RedirectRunning, _, _ = s.inline.RedirectStatus()
	}
	if cfg, err := s.readWXSystemProxy(); err != nil {
		t.Warning = "读取系统代理失败；可手动填写已确认的本地 HTTP 上游"
	} else if upstream, err := captureSystemUpstream(cfg); err != nil {
		t.Warning = err.Error()
	} else {
		t.SystemProxy = upstream
		if upstream != "" && t.UpstreamProxy == "" {
			t.Warning = "系统使用其他本地代理；直连 80/443 规则不会接管它，请选择沿用系统代理。此检测不代表所有小程序连接都使用该代理。"
		} else if upstream != "" && t.UpstreamProxy != upstream {
			t.Warning = "系统代理与当前抓包链上游不同；已有抓包链不会自动改变，请确认后停止并重新开始。"
		}
	}
	return t
}

// Stop agents before closing their destinations, otherwise an orphaned hook
// would continue sending the user's application to a dead local port.
func (s *Server) stopWXCaptureLocked() error {
	if engine := s.wxCaptureController(); engine != nil {
		if err := engine.CaptureStop(); err != nil {
			return fmt.Errorf("停止直抓脚本失败，保留监听避免连接被送往关闭端口: %w", err)
		}
	}
	if s.wxCaptureOwnRedirect && s.inline != nil {
		if err := s.inline.StopRedirect(); err != nil {
			return err
		}
		s.wxCaptureOwnRedirect = false
	}
	if s.wxCaptureOwnBridge && s.proxy != nil {
		if err := s.proxy.StopCaptureBridge(); err != nil {
			return err
		}
		s.wxCaptureOwnBridge = false
	}
	if s.wxCaptureOwnProxy && s.proxy != nil {
		if err := s.proxy.StopTransparent(); err != nil && !strings.Contains(err.Error(), "not running") {
			return err
		}
		s.wxCaptureOwnProxy = false
	}
	s.wxCaptureMode, s.wxCaptureUpstream = "", ""
	return nil
}

// CloseCaptureTools only detaches this server's sessions and listeners. It
// never terminates WeChat or restores/modifies the system proxy.
func (s *Server) CloseCaptureTools() error {
	s.wxCaptureMu.Lock()
	defer s.wxCaptureMu.Unlock()
	if err := s.stopWXCaptureLocked(); err != nil {
		return err
	}
	if s.wxhook != nil {
		return s.wxhook.Close()
	}
	return nil
}
