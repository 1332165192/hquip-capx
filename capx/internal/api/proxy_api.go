package api

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/hquip/capx/internal/inline"
	"github.com/hquip/capx/internal/proxy"
	"github.com/hquip/capx/internal/setup"
)

// proxyStatus reports whether the MITM proxy listener is running and where.
func (s *Server) proxyStatus(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	running, addr := s.proxy.Status()
	h3On, h3Addr := s.proxy.HTTP3Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"available":      true,
		"running":        running,
		"addr":           addr,
		"intercept":      s.proxy.InterceptEnabled(),
		"intercept_resp": s.proxy.InterceptRespEnabled(),
		"intercept_ws":   s.proxy.InterceptWSEnabled(),
		"http2":          s.proxy.HTTP2Enabled(),
		"body_capture":   proxy.MaxBodyCapture(),
		"http3":          h3On,
		"http3_addr":     h3Addr,
		"upstream":       s.proxy.UpstreamConfig(),
	})
}

type http2ToggleReq struct {
	Enabled bool `json:"enabled"`
}

// proxyHTTP2Toggle enables/disables upstream HTTP/2 negotiation.
func (s *Server) proxyHTTP2Toggle(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req http2ToggleReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.proxy.SetHTTP2Enabled(req.Enabled)
	writeJSON(w, http.StatusOK, map[string]bool{"http2": s.proxy.HTTP2Enabled()})
}

type bodyCaptureReq struct {
	Bytes int `json:"bytes"`
}

// proxyBodyCapture sets the HTTP history body capture cap (0 restores 1 MiB, max 16 MiB).
func (s *Server) proxyBodyCapture(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req bodyCaptureReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	proxy.SetMaxBodyCapture(req.Bytes)
	writeJSON(w, http.StatusOK, map[string]int{"body_capture": proxy.MaxBodyCapture()})
}

// proxyTransparentStatus reports the inline (transparent) interception listener.
func (s *Server) proxyTransparentStatus(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	running, addr := s.proxy.TransparentStatus()
	redirOn, redirPort, flows := false, 0, 0
	backend, beAvail := "n/a", false
	if s.inline != nil {
		redirOn, redirPort, flows = s.inline.RedirectStatus()
		backend, beAvail = s.inline.Backend(), s.inline.Available()
	}
	h3On, h3Addr := s.proxy.HTTP3Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"available":        true,
		"running":          running,
		"addr":             addr,
		"redirect":         redirOn,
		"redirect_port":    redirPort,
		"redirect_flows":   flows,
		"redirect_backend": backend,
		"redirect_ready":   beAvail,
		"http3":            h3On,
		"http3_addr":       h3Addr,
	})
}

func (s *Server) proxyTransparentStart(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req proxyStartReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if strings.TrimSpace(req.Addr) == "" {
		req.Addr = ":18081"
	}
	if err := s.proxy.StartTransparent(req.Addr); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	running, addr := s.proxy.TransparentStatus()
	if s.inline != nil && s.inline.UDPOnlyRedirect() {
		_ = s.inline.StopRedirect()
	}
	if s.inline == nil || !s.inline.Available() {
		writeJSON(w, http.StatusOK, map[string]any{
			"running":        running,
			"addr":           addr,
			"redirect":       false,
			"redirect_error": inline.ErrNoBackend.Error(),
			"hint":           "透明监听已开，但本构建没有 WinDivert/iptables 重定向（Windows 需 -tags windivert + 管理员 + WinDivert.dll；Linux 需 -tags nfqueue + root）。不走系统代理的 App 仍抓不到。可用抓包浏览器。",
		})
		return
	}
	_, port, err := parseListenPort(addr)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	skip := 0
	if _, mitm := s.proxy.Status(); mitm != "" {
		if _, p, e := parseListenPort(mitm); e == nil {
			skip = p
		}
	}
	ports := req.Ports
	if len(ports) == 0 {
		ports = []int{80, 443}
	}
	if err := s.inline.StartRedirect(port, skip, ports...); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"running": running, "addr": addr, "redirect": false,
			"redirect_error": err.Error(),
			"hint":           "监听已开，OS 重定向启动失败。检查管理员权限 / WinDivert.dll / iptables。",
		})
		return
	}
	redirOn, redirPort, flows := s.inline.RedirectStatus()
	h3On, h3Addr := s.proxy.HTTP3Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"running": running, "addr": addr, "redirect": redirOn,
		"redirect_port": redirPort, "redirect_flows": flows, "ports": ports,
		"http3": h3On, "http3_addr": h3Addr,
	})
}

func (s *Server) proxyTransparentStop(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	if s.inline != nil {
		_ = s.inline.StopRedirect()
	}
	if err := s.proxy.StopTransparent(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func parseListenPort(addr string) (host string, port int, err error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err = strconv.Atoi(p)
	return host, port, err
}

type proxyStartReq struct {
	Addr  string `json:"addr"`
	Ports []int  `json:"ports,omitempty"`
}

func (s *Server) proxyStart(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req proxyStartReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	if strings.TrimSpace(req.Addr) == "" {
		req.Addr = "127.0.0.1:18080"
	}
	err := s.proxy.Start(req.Addr)
	if err != nil && req.Addr == "127.0.0.1:18080" && isAddrInUse(err) {
		err = s.proxy.Start("127.0.0.1:0")
	}
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.tryUDPRedirectForHTTP3()
	running, addr := s.proxy.Status()
	h3On, h3Addr := s.proxy.HTTP3Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"running": running, "addr": addr,
		"http3": h3On, "http3_addr": h3Addr,
	})
}

func isAddrInUse(err error) bool {
	var op *net.OpError
	if !errors.As(err, &op) {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "only one usage of each socket address")
}

func (s *Server) proxyStop(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	if err := s.proxy.Stop(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	if s.inline != nil && s.inline.UDPOnlyRedirect() {
		_ = s.inline.StopRedirect()
	}
	writeJSON(w, http.StatusOK, map[string]string{"stopped": "ok"})
}

func (s *Server) setupCABytes() ([]byte, error) {
	if s.proxy == nil {
		return nil, errors.New("proxy not available")
	}
	pem := s.proxy.CA().CertPEM()
	if len(pem) == 0 {
		return nil, errors.New("CA certificate is empty")
	}
	return pem, nil
}

func (s *Server) writeSetup(w http.ResponseWriter, extra map[string]any) {
	pem, _ := s.setupCABytes()
	mitmAddr := ""
	mitmRunning := false
	if s.proxy != nil {
		mitmRunning, mitmAddr = s.proxy.Status()
	}
	st := setup.Snapshot(pem, mitmAddr)
	out := map[string]any{
		"os":               st.OS,
		"admin":            st.Admin,
		"ca_installed":     st.CAInstalled,
		"ca_thumbprint":    st.CAThumbprint,
		"ca_subject":       st.CASubject,
		"proxy_set":        st.ProxySet,
		"proxy_owned":      st.ProxyOwned,
		"proxy_server":     st.ProxyServer,
		"proxy_override":   st.ProxyOverride,
		"proxy_backup":     st.ProxyBackup,
		"http3_disabled":   st.HTTP3Disabled,
		"chrome_available": st.ChromeAvailable,
		"chrome_profile":   st.ChromeProfile,
		"hint":             st.Hint,
		"mitm_running":     mitmRunning,
		"mitm_addr":        mitmAddr,
	}
	for k, v := range extra {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	s.writeSetup(w, nil)
}

func (s *Server) setupInstallCA(w http.ResponseWriter, r *http.Request) {
	pem, err := s.setupCABytes()
	if err != nil {
		writeErr(w, http.StatusNotImplemented, err.Error())
		return
	}
	if err := setup.InstallCA(pem); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeSetup(w, map[string]any{"ok": true, "action": "ca_install"})
}

func (s *Server) setupUninstallCA(w http.ResponseWriter, r *http.Request) {
	pem, err := s.setupCABytes()
	if err != nil {
		writeErr(w, http.StatusNotImplemented, err.Error())
		return
	}
	if err := setup.UninstallCA(pem); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeSetup(w, map[string]any{"ok": true, "action": "ca_uninstall"})
}

func (s *Server) setupSysProxyOn(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	running, addr := s.proxy.Status()
	if !running || strings.TrimSpace(addr) == "" {
		writeErr(w, http.StatusConflict, "start the MITM proxy first")
		return
	}
	if err := setup.EnableSystemProxyOwned(s.proxy, addr); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeSetup(w, map[string]any{"ok": true, "action": "sysproxy_on"})
}

func (s *Server) setupSysProxyOff(w http.ResponseWriter, r *http.Request) {
	if err := setup.DisableSystemProxyOwned(s.proxy); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeSetup(w, map[string]any{"ok": true, "action": "sysproxy_off"})
}

func (s *Server) setupDisableHTTP3(w http.ResponseWriter, r *http.Request) {
	if err := setup.DisableHTTP3(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeSetup(w, map[string]any{"ok": true, "action": "http3_off"})
}

type setupBrowserReq struct {
	URL  string `json:"url"`
	Addr string `json:"addr"`
}

func (s *Server) ensureMITM(addr string) (string, error) {
	if s.proxy == nil {
		return "", errors.New("proxy not available")
	}
	running, cur := s.proxy.Status()
	if running && strings.TrimSpace(cur) != "" {
		return cur, nil
	}
	if strings.TrimSpace(addr) == "" {
		addr = "127.0.0.1:18080"
	}
	err := s.proxy.Start(addr)
	if err != nil && strings.Contains(err.Error(), "already running") {
		_, cur = s.proxy.Status()
		if strings.TrimSpace(cur) != "" {
			return cur, nil
		}
	}
	if err != nil && addr == "127.0.0.1:18080" && isAddrInUse(err) {
		err = s.proxy.Start("127.0.0.1:0")
	}
	if err != nil {
		return "", err
	}
	s.tryUDPRedirectForHTTP3()
	_, cur = s.proxy.Status()
	return cur, nil
}

func (s *Server) tryUDPRedirectForHTTP3() {
	if s.proxy == nil || s.inline == nil || !s.inline.Available() {
		return
	}
	if on, _, _ := s.inline.RedirectStatus(); on {
		return
	}
	_, addr := s.proxy.Status()
	if addr == "" {
		return
	}
	_, port, err := parseListenPort(addr)
	if err != nil || port <= 0 {
		return
	}
	skip := 0
	if _, taddr := s.proxy.TransparentStatus(); taddr != "" {
		if _, p, e := parseListenPort(taddr); e == nil {
			skip = p
		}
	}
	_ = s.inline.StartUDPRedirect(port, skip, 443)
}

func (s *Server) setupLaunchBrowser(w http.ResponseWriter, r *http.Request) {
	var req setupBrowserReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	addr, err := s.ensureMITM(req.Addr)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not available") {
			code = http.StatusNotImplemented
		}
		writeErr(w, code, err.Error())
		return
	}
	pem, _ := s.setupCABytes()
	if len(pem) > 0 {
		_ = setup.InstallCA(pem)
	}
	profile, err := setup.LaunchCaptureBrowser(addr, req.URL, pem)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeSetup(w, map[string]any{
		"ok":             true,
		"action":         "launch_browser",
		"chrome_profile": profile,
		"url":            req.URL,
		"hint":           "已打开独立抓包浏览器。代理仅该窗口，不改整机代理。只在这个窗口访问目标站。",
	})
}

func (s *Server) setupRestartBrowsers(w http.ResponseWriter, r *http.Request) {
	n, err := setup.RestartUserBrowsers()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.writeSetup(w, map[string]any{
		"ok":        true,
		"action":    "restart_browsers",
		"restarted": n,
	})
}

type setupPrepareReq struct {
	Addr            string `json:"addr"`
	URL             string `json:"url"`
	RestartBrowsers bool   `json:"restart_browsers"`
	SystemProxy     *bool  `json:"system_proxy"`
}

func (s *Server) setupPrepare(w http.ResponseWriter, r *http.Request) {
	var req setupPrepareReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	useSysProxy := true
	if req.SystemProxy != nil {
		useSysProxy = *req.SystemProxy
	}

	steps := map[string]any{}

	addr, err := s.ensureMITM(req.Addr)
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "not available") {
			code = http.StatusNotImplemented
		}
		writeErr(w, code, err.Error())
		return
	}
	steps["proxy"] = addr

	pem, err := s.setupCABytes()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ca: "+err.Error())
		return
	}
	if err := setup.InstallCA(pem); err != nil {
		writeErr(w, http.StatusInternalServerError, "ca: "+err.Error())
		return
	}
	steps["ca"] = "installed"

	if err := setup.DisableHTTP3(); err != nil {
		steps["http3"] = "skipped: " + err.Error()
	} else if setup.Snapshot(pem, addr).HTTP3Disabled {
		steps["http3"] = "disabled"
	} else {
		steps["http3"] = "attempted (restart browsers; Firefox uses policies.json in the profile)"
	}

	if useSysProxy {
		if err := setup.EnableSystemProxyOwned(s.proxy, addr); err != nil {
			writeErr(w, http.StatusInternalServerError, "sysproxy: "+err.Error())
			return
		}
		steps["sysproxy"] = "on"
	} else {
		steps["sysproxy"] = "skipped"
	}

	restarted := 0
	if req.RestartBrowsers || useSysProxy {
		n, err := setup.RestartUserBrowsers()
		if err != nil {
			steps["restart_browsers"] = err.Error()
		} else {
			restarted = n
			steps["restart_browsers"] = n
		}
	}

	hint := "已安装 CA、关闭 HTTP/3"
	if useSysProxy {
		hint += "并打开系统代理。请用刚重启的浏览器访问目标站。退出 capx 会自动还原系统代理。"
	} else {
		hint += "。未改整机代理。"
	}
	if restarted == 0 && useSysProxy {
		hint = "已安装 CA、关闭 HTTP/3 并打开系统代理。请手动重启浏览器后再访问目标站。退出 capx 会自动还原系统代理。"
	}

	if u := strings.TrimSpace(req.URL); u != "" {
		hint += " 目标站：" + u
	}
	s.writeSetup(w, map[string]any{
		"ok":        true,
		"action":    "prepare",
		"steps":     steps,
		"restarted": restarted,
		"url":       req.URL,
		"hint":      hint,
	})
}

type interceptToggleReq struct {
	Enabled bool   `json:"enabled"`
	Stage   string `json:"stage"` // "request" (default) | "response" | "ws" | "both"
}

func (s *Server) proxyInterceptToggle(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req interceptToggleReq
	_ = json.NewDecoder(r.Body).Decode(&req)
	switch req.Stage {
	case "response":
		s.proxy.SetInterceptRespEnabled(req.Enabled)
	case "ws":
		s.proxy.SetInterceptWSEnabled(req.Enabled)
	case "both":
		s.proxy.SetInterceptEnabled(req.Enabled)
		s.proxy.SetInterceptRespEnabled(req.Enabled)
		s.proxy.SetInterceptWSEnabled(req.Enabled)
	default: // "" or "request"
		s.proxy.SetInterceptEnabled(req.Enabled)
	}
	writeJSON(w, http.StatusOK, map[string]bool{
		"intercept":      s.proxy.InterceptEnabled(),
		"intercept_resp": s.proxy.InterceptRespEnabled(),
		"intercept_ws":   s.proxy.InterceptWSEnabled(),
	})
}

// proxyInterceptRules returns the ordered granular interception conditions.
func (s *Server) proxyInterceptRules(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.InterceptConds())
}

// proxyInterceptRulesSet replaces the ordered granular interception conditions.
func (s *Server) proxyInterceptRulesSet(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var rules []proxy.InterceptCond
	if err := json.NewDecoder(r.Body).Decode(&rules); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	s.proxy.SetInterceptConds(rules)
	writeJSON(w, http.StatusOK, s.proxy.InterceptConds())
}

// proxyWSConns lists live WebSocket connections available for replay.
func (s *Server) proxyWSConns(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.WSConns())
}

type wsReplayReq struct {
	ConnID string `json:"conn_id"`
	Dir    string `json:"dir"`    // "send" (client->server) | "recv" (server->client)
	Opcode string `json:"opcode"` // "text" (default) | "binary"
	Data   string `json:"data"`   // text payload, or base64 when opcode=="binary"
}

// proxyWSReplay injects a (possibly edited) frame onto a live WS connection.
func (s *Server) proxyWSReplay(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req wsReplayReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Opcode == "" {
		req.Opcode = "text"
	}
	if req.Dir == "" {
		req.Dir = "send"
	}
	msg, err := s.proxy.ReplayWS(req.ConnID, req.Dir, req.Opcode, req.Data)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

func (s *Server) proxyInterceptQueue(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.Intercept().Queue())
}

type interceptDecideReq struct {
	ID   string `json:"id"`
	Drop bool   `json:"drop"`
	Raw  string `json:"raw"` // edited request text (empty = forward unchanged)
}

func (s *Server) proxyInterceptDecide(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req interceptDecideReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	ok := s.proxy.Intercept().Decide(req.ID, req.Raw, req.Drop)
	if !ok {
		writeErr(w, http.StatusNotFound, "held request not found (already decided?)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// proxyCA serves the PEM-encoded root certificate for the user to trust.
func (s *Server) proxyCA(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	pem := s.proxy.CA().CertPEM()
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="capx-ca.pem"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(pem)))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(pem)
}

func (s *Server) getScope(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, map[string]any{"include": []any{}, "exclude": []any{}})
		return
	}
	inc, exc := s.proxy.Scope().Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"include": inc, "exclude": exc})
}

type scopeReq struct {
	Include []proxy.ScopeRule `json:"include"`
	Exclude []proxy.ScopeRule `json:"exclude"`
}

func (s *Server) setScope(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req scopeReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	s.proxy.Scope().SetRules(req.Include, req.Exclude)
	inc, exc := s.proxy.Scope().Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{"include": inc, "exclude": exc})
}

type repeaterReq struct {
	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Raw        string `json:"raw"`
	Follow     bool   `json:"follow"`
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
}

func (s *Server) repeaterSend(w http.ResponseWriter, r *http.Request) {
	var req repeaterReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Scheme == "" {
		req.Scheme = "https"
	}
	var cert *tls.Certificate
	if strings.TrimSpace(req.ClientCert) != "" && strings.TrimSpace(req.ClientKey) != "" {
		c, err := tls.X509KeyPair([]byte(req.ClientCert), []byte(req.ClientKey))
		if err != nil {
			writeErr(w, http.StatusBadRequest, "client cert: "+err.Error())
			return
		}
		cert = &c
	}
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	writeJSON(w, http.StatusOK, s.proxy.SendRawTLSContext(r.Context(), req.Scheme, req.Host, req.Raw, req.Follow, cert))
}

func (s *Server) intruderRun(w http.ResponseWriter, r *http.Request) {
	if s.rejectDirectUpstream(w) {
		return
	}
	var cfg proxy.IntruderConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "https"
	}
	results, err := proxy.RunIntruder(cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "count": len(results)})
}

// turboRun executes a Turbo-Intruder-style run: high-concurrency or a
// last-byte-synchronized race "gate".
func (s *Server) turboRun(w http.ResponseWriter, r *http.Request) {
	if s.rejectDirectUpstream(w) {
		return
	}
	var cfg proxy.TurboConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if cfg.Scheme == "" {
		cfg.Scheme = "https"
	}
	results, err := proxy.RunTurbo(cfg)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results, "count": len(results)})
}

// sessionGet returns the configured macros, session rules and live variables.
func (s *Server) sessionGet(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeJSON(w, http.StatusOK, map[string]any{"macros": []any{}, "rules": []any{}, "vars": map[string]string{}})
		return
	}
	se := s.proxy.Session()
	writeJSON(w, http.StatusOK, map[string]any{
		"macros":    se.Macros(),
		"rules":     se.Rules(),
		"ws_macros": se.WSMacros(),
		"ws_rules":  se.WSRules(),
		"vars":      se.Vars(),
	})
}

type sessionConfigReq struct {
	Macros   []proxy.Macro       `json:"macros"`
	Rules    []proxy.SessionRule `json:"rules"`
	WSMacros []proxy.WSMacro     `json:"ws_macros"`
	WSRules  []proxy.WSRule      `json:"ws_rules"`
}

// sessionSet replaces the macros and session rules.
func (s *Server) sessionSet(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req sessionConfigReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	se := s.proxy.Session()
	se.SetMacros(req.Macros)
	se.SetRules(req.Rules)
	se.SetWSMacros(req.WSMacros)
	se.SetWSRules(req.WSRules)
	writeJSON(w, http.StatusOK, map[string]any{
		"macros":    se.Macros(),
		"rules":     se.Rules(),
		"ws_macros": se.WSMacros(),
		"ws_rules":  se.WSRules(),
		"vars":      se.Vars(),
	})
}

type macroRunReq struct {
	Name string `json:"name"`
}

// sessionRunMacro executes a stored macro by name, returning the transcript
// and the resulting variable store.
func (s *Server) sessionRunMacro(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req macroRunReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	run, err := s.proxy.Session().RunMacroByName(req.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

type wsMacroRunReq struct {
	Name   string `json:"name"`
	ConnID string `json:"conn_id"`
}

// sessionRunWSMacro injects a stored WebSocket macro onto a live connection,
// returning the transcript and the resulting variable store.
func (s *Server) sessionRunWSMacro(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "proxy not available")
		return
	}
	var req wsMacroRunReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	run, err := s.proxy.RunWSMacro(req.Name, req.ConnID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

// SiteNode is a host entry in the Target site map, with its observed paths.
type SiteNode struct {
	Host   string   `json:"host"`
	Scheme string   `json:"scheme"`
	Count  int      `json:"count"`
	Paths  []string `json:"paths"`
}

// siteMap aggregates recorded HTTP transactions into a host -> paths tree
// (Burp's Target site map), derived from proxy history.
func (s *Server) siteMap(w http.ResponseWriter, r *http.Request) {
	txs := s.st.ListHTTPTx("")
	type agg struct {
		scheme string
		paths  map[string]struct{}
	}
	hosts := map[string]*agg{}
	for _, tx := range txs {
		a, ok := hosts[tx.Host]
		if !ok {
			a = &agg{scheme: tx.Scheme, paths: map[string]struct{}{}}
			hosts[tx.Host] = a
		}
		a.paths[tx.Path] = struct{}{}
	}
	out := make([]SiteNode, 0, len(hosts))
	for host, a := range hosts {
		paths := make([]string, 0, len(a.paths))
		for p := range a.paths {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		out = append(out, SiteNode{Host: host, Scheme: a.scheme, Count: len(paths), Paths: paths})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	writeJSON(w, http.StatusOK, out)
}
