package api

import (
	"encoding/json"
	"net/http"

	"github.com/hquip/capx/internal/mobilevpn"
)

func (s *Server) mobileVPNReady(w http.ResponseWriter) bool {
	if s.mobileVPN == nil {
		writeErr(w, http.StatusNotImplemented, "user-space mobile VPN backend unavailable")
		return false
	}
	return true
}
func (s *Server) mobileVPNStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.mobileVPN == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "running": false})
		return
	}
	writeJSON(w, http.StatusOK, s.mobileVPN.Status())
}
func (s *Server) mobileVPNStart(w http.ResponseWriter, r *http.Request) {
	if !s.mobileVPNReady(w) {
		return
	}
	var opts mobilevpn.Options
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	d.DisallowUnknownFields()
	if err := d.Decode(&opts); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid mobile VPN configuration")
		return
	}
	status, err := s.mobileVPN.Start(opts)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, status)
}
func (s *Server) mobileVPNStop(w http.ResponseWriter, r *http.Request) {
	if !s.mobileVPNReady(w) {
		return
	}
	if err := s.mobileVPN.Stop(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.mobileVPN.Status())
}
func (s *Server) mobileVPNConfig(w http.ResponseWriter, r *http.Request) {
	if !s.mobileVPNReady(w) {
		return
	}
	config, err := s.mobileVPN.AndroidConfig()
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/octet-stream")
	// Android WireGuard uses the basename as the tunnel name (max 15 characters).
	w.Header().Set("Content-Disposition", `attachment; filename="capx-phone.conf"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write([]byte(config))
}
