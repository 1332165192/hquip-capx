package api

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// dnslogStatus reports how the DNSLog OOB client is configured and whether the
// platform is reachable.
func (s *Server) dnslogStatus(w http.ResponseWriter, r *http.Request) {
	if s.dnslog == nil {
		writeErr(w, http.StatusNotImplemented, "dnslog not available")
		return
	}
	writeJSON(w, http.StatusOK, s.dnslog.Status(r.Context()))
}

type dnslogConfigReq struct {
	BaseURL    string `json:"base_url"`
	APIKey     string `json:"api_key"`
	SetDefault bool   `json:"set_default"`
}

// dnslogConfig sets the DNSLog platform base URL and API key, then returns the
// refreshed status (which probes reachability).
func (s *Server) dnslogConfig(w http.ResponseWriter, r *http.Request) {
	if s.dnslog == nil {
		writeErr(w, http.StatusNotImplemented, "dnslog not available")
		return
	}
	var req dnslogConfigReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	configure := s.dnslog.Configure
	if req.SetDefault {
		configure = s.dnslog.ConfigureDefaults
	}
	if err := configure(req.BaseURL, req.APIKey); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.dnslog.Status(r.Context()))
}

func (s *Server) dnslogLogs(w http.ResponseWriter, r *http.Request) {
	if s.dnslog == nil {
		writeErr(w, http.StatusNotImplemented, "dnslog not available")
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("page_size"))
	logs, err := s.dnslog.Logs(r.Context(), page, size, q.Get("subdomain"))
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, logs)
}

// dnslogPayloads lists the tracked OOB subdomains and their hit state.
func (s *Server) dnslogPayloads(w http.ResponseWriter, r *http.Request) {
	if s.dnslog == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	writeJSON(w, http.StatusOK, s.dnslog.Payloads())
}

type dnslogNewReq struct {
	Domain string `json:"domain"`
	Note   string `json:"note"`
}

// dnslogNewPayload requests a fresh unique subdomain from the platform.
func (s *Server) dnslogNewPayload(w http.ResponseWriter, r *http.Request) {
	if s.dnslog == nil {
		writeErr(w, http.StatusNotImplemented, "dnslog not available")
		return
	}
	var req dnslogNewReq
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	p, err := s.dnslog.NewPayload(r.Context(), req.Domain, req.Note)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// dnslogCheck queries whether a subdomain has received a DNS/HTTP callback.
func (s *Server) dnslogCheck(w http.ResponseWriter, r *http.Request) {
	if s.dnslog == nil {
		writeErr(w, http.StatusNotImplemented, "dnslog not available")
		return
	}
	sub := r.URL.Query().Get("subdomain")
	if sub == "" {
		writeErr(w, http.StatusBadRequest, "missing subdomain")
		return
	}
	protocol := r.URL.Query().Get("protocol")
	since, _ := strconv.Atoi(r.URL.Query().Get("since"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	res, err := s.dnslog.Check(r.Context(), sub, protocol, since, limit)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// dnslogPoll checks every tracked payload once and returns the refreshed list.
func (s *Server) dnslogPoll(w http.ResponseWriter, r *http.Request) {
	if s.dnslog == nil {
		writeErr(w, http.StatusNotImplemented, "dnslog not available")
		return
	}
	ps, err := s.dnslog.Poll(r.Context())
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ps)
}

// dnslogForget stops tracking a payload locally (the platform record is kept).
func (s *Server) dnslogForget(w http.ResponseWriter, r *http.Request) {
	if s.dnslog == nil {
		writeErr(w, http.StatusNotImplemented, "dnslog not available")
		return
	}
	sub := r.PathValue("subdomain")
	if !s.dnslog.Forget(sub) {
		writeErr(w, http.StatusNotFound, "payload not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"forgot": sub})
}
