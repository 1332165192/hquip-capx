package api

// Passive issue detection over captured HTTP history (Burp-style passive scan):
// no traffic is sent, the captured transactions are inspected for missing
// security headers, leaked secrets/PII, permissive CORS, reflected params, and
// insecure cookies.

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/scan"
)

// scanPassive runs the passive scanner over the captured HTTP history (honoring
// the same filter query params as /api/http) and returns findings grouped per
// transaction plus a severity tally.
func (s *Server) scanPassive(w http.ResponseWriter, r *http.Request) {
	txs := s.st.FilterHTTPTx(httpFilterFromQuery(r))
	type result struct {
		ID       uint64         `json:"id"`
		URL      string         `json:"url"`
		Findings []scan.Finding `json:"findings"`
	}
	var results []result
	tally := map[string]int{}
	for _, tx := range txs {
		findings := scan.ScanTx(toScanTx(tx))
		if len(findings) == 0 {
			continue
		}
		for _, f := range findings {
			tally[f.Severity]++
		}
		results = append(results, result{ID: tx.ID, URL: tx.URL, Findings: findings})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scanned": len(txs), "with_findings": len(results), "tally": tally, "results": results,
	})
}

func (s *Server) scanPassiveTx(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	tx, ok := s.st.GetHTTPTx(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "http tx not found")
		return
	}
	findings := scan.ScanTx(toScanTx(tx))
	tally := map[string]int{}
	for _, f := range findings {
		tally[f.Severity]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": tx.ID, "url": tx.URL, "findings": findings, "tally": tally,
	})
}

// toScanTx adapts a captured model.HTTPTx into the scanner's input, splitting
// the response body out of the raw response text.
func toScanTx(tx *model.HTTPTx) scan.Tx {
	rawQuery := ""
	if u, err := url.Parse(tx.URL); err == nil {
		rawQuery = u.RawQuery
	}
	return scan.Tx{
		Scheme:   tx.Scheme,
		Method:   tx.Method,
		Host:     tx.Host,
		URL:      tx.URL,
		Status:   tx.Status,
		MIME:     tx.MIME,
		RawQuery: rawQuery,
		ReqHdr:   tx.ReqHdr,
		RespHdr:  tx.RespHdr,
		RespRaw:  tx.RespRaw,
		RespBody: bodyOf(tx.RespRaw),
	}
}

// bodyOf returns the body portion (after the blank line) of a raw HTTP message.
func bodyOf(raw string) string {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[i+4:]
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[i+2:]
	}
	return raw
}
