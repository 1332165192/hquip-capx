package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/hquip/capx/internal/proxy"
)

func (s *Server) proxyUpstream(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusNotImplemented, "capture proxy unavailable")
		return
	}
	if r.Method == http.MethodPost {
		if s.mobileVPN != nil && s.mobileVPN.Status().Running {
			writeErr(w, http.StatusConflict, "stop the mobile VPN before changing the secondary route; existing raw sockets cannot be rerouted")
			return
		}
		var input struct {
			Enabled         bool   `json:"enabled"`
			URL             string `json:"url"`
			Username        string `json:"username"`
			Password        string `json:"password"`
			KeepCredentials bool   `json:"keep_credentials"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid upstream configuration")
			return
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			writeErr(w, http.StatusBadRequest, "invalid trailing upstream configuration")
			return
		}
		if err := s.proxy.SetUpstream(proxy.UpstreamConfig{Enabled: input.Enabled, URL: input.URL, Username: input.Username, Password: input.Password, KeepCredentials: input.KeepCredentials}); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	cfg := s.proxy.UpstreamConfig()
	writeJSON(w, http.StatusOK, map[string]any{
		"upstream": cfg,
		"http":     true, "https": true, "websocket": true, "repeater": true, "session_macros": true,
		"raw_vpn_tcp": !cfg.Enabled, "raw_vpn_udp": !cfg.Enabled, "intruder": !cfg.Enabled, "turbo": !cfg.Enabled,
		"note": "The selected route covers captured HTTP/HTTPS, WebSocket, Repeater and HTTP session macros. Credentials are memory-only. HTTP proxies cannot carry generic VPN UDP; raw VPN traffic and other direct engines are blocked while this route is enabled.",
	})
}

// Direct request engines have separate socket paths. Reject rather than
// bypassing a secondary proxy selected for this capture instance.
func (s *Server) rejectDirectUpstream(w http.ResponseWriter) bool {
	if s.proxy != nil && s.proxy.UpstreamConfig().Enabled {
		writeErr(w, http.StatusNotImplemented, "direct request tools are unavailable while the secondary capture proxy is enabled")
		return true
	}
	return false
}
