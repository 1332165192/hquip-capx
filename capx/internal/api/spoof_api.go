package api

// ARP spoofing endpoints for LAN MITM positioning. This is an active, intrusive
// capability (raw frame injection, needs a -tags pcap build + admin/root) so it
// is gated by the security policy and only usable on hosts/targets you are
// authorized to test.

import "net/http"

func (s *Server) spoofStatus(w http.ResponseWriter, r *http.Request) {
	if s.spoof == nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	running, iface, target, gateway := s.spoof.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"available": s.spoof.Available(), "running": running,
		"iface": iface, "target": target, "gateway": gateway,
	})
}

func (s *Server) spoofStart(w http.ResponseWriter, r *http.Request) {
	if s.spoof == nil {
		writeErr(w, http.StatusNotImplemented, "spoof engine unavailable")
		return
	}
	var req struct {
		Iface   string `json:"iface"`
		Target  string `json:"target"`
		Gateway string `json:"gateway"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	if req.Iface == "" || req.Target == "" || req.Gateway == "" {
		writeErr(w, http.StatusBadRequest, "iface, target and gateway required")
		return
	}
	if err := s.spoof.Start(req.Iface, req.Target, req.Gateway); err != nil {
		writeErr(w, http.StatusNotImplemented, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "poisoning", "target": req.Target, "gateway": req.Gateway})
}

func (s *Server) spoofStop(w http.ResponseWriter, r *http.Request) {
	if s.spoof == nil {
		writeErr(w, http.StatusNotImplemented, "spoof engine unavailable")
		return
	}
	if err := s.spoof.Stop(); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}
