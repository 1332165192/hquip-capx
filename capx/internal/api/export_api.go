package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/hquip/capx/internal/export"
	"github.com/hquip/capx/internal/proxy"
)

// exportHTTPHar streams the captured HTTP history as a HAR 1.2 document. It
// honours the same filter query params as GET /api/http (scheme, host, method,
// mime, status, q), so the export matches whatever the history view shows.
func (s *Server) exportHTTPHar(w http.ResponseWriter, r *http.Request) {
	b, err := export.HAR(s.st.FilterHTTPTx(httpFilterFromQuery(r)))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="capx-history.har"`)
	_, _ = w.Write(b)
}

// exportHTTPCurl returns a "Copy as curl" command line for a single captured
// transaction identified by its numeric id.
func (s *Server) exportHTTPCurl(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad tx id")
		return
	}
	tx, ok := s.st.GetHTTPTx(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "transaction not found")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(export.Curl(tx)))
}

// exportPCAP streams retained raw packets as a libpcap (.pcap) or pcapng
// (.pcapng) file. Query params: capture (filter to one capture id; empty =
// all) and format ("pcap"|"pcapng", default pcap). The link type is taken from
// the capture so Wireshark parses frames correctly.
func (s *Server) exportPCAP(w http.ResponseWriter, r *http.Request) {
	captureID := r.URL.Query().Get("capture")
	packets := s.st.ListPackets(captureID)
	if len(packets) == 0 {
		writeErr(w, http.StatusNotFound, "no packets retained (capture with -tags pcap, or wrong capture id)")
		return
	}
	linkType := s.st.CaptureLinkTypeForExport(captureID)
	if linkType == 0 {
		linkType = export.LinkEthernet
	}

	if r.URL.Query().Get("format") == "pcapng" {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="capx.pcapng"`)
		if err := export.WritePCAPNG(w, packets, linkType); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="capx.pcap"`)
	if err := export.WritePCAP(w, packets, linkType); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

type intruderExportReq struct {
	Results []proxy.IntruderResult `json:"results"`
}

// exportIntruderCSV renders posted Intruder results as a downloadable CSV. The
// client posts the results it already received from /api/intruder/run, so the
// attack is not re-executed.
func (s *Server) exportIntruderCSV(w http.ResponseWriter, r *http.Request) {
	var req intruderExportReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	b, err := export.IntruderCSV(req.Results)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="capx-intruder.csv"`)
	_, _ = w.Write(b)
}
