package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/hquip/capx/internal/proxy"
)

func (s *Server) proxyLANStatus(w http.ResponseWriter, r *http.Request) {
	addresses, err := proxy.LANAddresses()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	running, addr := false, ""
	if s.proxy != nil {
		running, addr = s.proxy.LANStatus()
	}
	w.Header().Set("Cache-Control", "no-store")
	clients := []string{}
	if s.proxy != nil {
		clients = s.proxy.LANClients()
	}
	writeJSON(w, http.StatusOK, map[string]any{"available": s.proxy != nil, "running": running, "addr": addr, "addresses": addresses, "allowed_clients": clients})
}

func (s *Server) proxyLANStart(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeErr(w, http.StatusConflict, "MITM proxy unavailable")
		return
	}
	var req struct {
		Host           string   `json:"host"`
		Port           int      `json:"port"`
		AllowedClients []string `json:"allowed_clients"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "valid host and port required")
		return
	}
	if req.Port == 0 {
		_, addr := s.proxy.Status()
		_, port, err := parseListenPort(addr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "请填写 Wi-Fi 代理端口")
			return
		}
		req.Port = port
	}
	if req.Port < 1 || req.Port > 65535 {
		writeErr(w, http.StatusBadRequest, "invalid LAN proxy port: "+strconv.Itoa(req.Port))
		return
	}
	if err := s.proxy.StartLANWithClients(req.Host, req.Port, req.AllowedClients); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	s.proxyLANStatus(w, r)
}

func (s *Server) proxyLANStop(w http.ResponseWriter, r *http.Request) {
	if s.proxy != nil {
		if err := s.proxy.StopLAN(); err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
	}
	s.proxyLANStatus(w, r)
}
