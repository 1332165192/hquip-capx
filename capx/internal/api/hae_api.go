package api

// HaE (github.com/gh0stkey/HaE) compatible rule engine endpoints: upload HaE's
// Rules.yml, then highlight/extract over the captured HTTP history using the
// community ruleset. Complements the built-in passive scanner.

import (
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/hquip/capx/internal/hae"
	"github.com/hquip/capx/internal/model"
)

// haeStatus reports the loaded ruleset stats.
func (s *Server) haeStatus(w http.ResponseWriter, r *http.Request) {
	loaded, skipped, groups := s.hae.Stats()
	writeJSON(w, http.StatusOK, map[string]any{
		"loaded": loaded, "skipped": skipped, "groups": groups,
	})
}

// haeRulesUpload loads a HaE Rules.yml (raw text/plain or JSON {"yaml":"..."}).
func (s *Server) haeRulesUpload(w http.ResponseWriter, r *http.Request) {
	var yml []byte
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var req struct {
			YAML string `json:"yaml"`
		}
		if err := decodeBody(r, &req); err != nil || req.YAML == "" {
			writeErr(w, http.StatusBadRequest, "provide yaml")
			return
		}
		yml = []byte(req.YAML)
	} else {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		yml = b
	}
	loaded, skipped, err := s.hae.Load(yml)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"loaded": loaded, "skipped": skipped})
}

// haeRulesList returns the loaded rule metadata.
func (s *Server) haeRulesList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"rules": s.hae.Rules(), "skipped": s.hae.Skipped()})
}

// haeScan applies the HaE ruleset to the captured HTTP history (honoring the
// same filter params as /api/http) and returns per-transaction highlights.
func (s *Server) haeScan(w http.ResponseWriter, r *http.Request) {
	if loaded, _, _ := s.hae.Stats(); loaded == 0 {
		writeErr(w, http.StatusBadRequest, "no HaE rules loaded; POST Rules.yml to /api/hae/rules first")
		return
	}
	txs := s.st.FilterHTTPTx(httpFilterFromQuery(r))
	type result struct {
		ID      uint64      `json:"id"`
		URL     string      `json:"url"`
		Matches []hae.Match `json:"matches"`
	}
	var results []result
	colors := map[string]int{}
	for _, tx := range txs {
		matches := s.hae.Apply(haeMessageFromTx(tx))
		if len(matches) == 0 {
			continue
		}
		for _, m := range matches {
			colors[m.Color]++
		}
		results = append(results, result{ID: tx.ID, URL: tx.URL, Matches: matches})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scanned": len(txs), "with_matches": len(results), "colors": colors, "results": results,
	})
}

// haeTx applies the HaE ruleset to a single captured transaction (by id) and
// returns its matches — powers the response detail "MarkInfo" tab.
func (s *Server) haeTx(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	tx, ok := s.st.GetHTTPTx(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "matches": s.hae.Apply(haeMessageFromTx(tx))})
}

// haeMessageFromTx splits a captured tx's raw request/response into the
// line/header/body parts HaE rule scopes target.
func haeMessageFromTx(tx *model.HTTPTx) hae.Message {
	reqLine, reqHdr, reqBody := splitHTTP(tx.ReqRaw)
	respLine, respHdr, respBody := splitHTTP(tx.RespRaw)
	return hae.Message{
		ReqLine: reqLine, ReqHeader: reqHdr, ReqBody: reqBody,
		RespLine: respLine, RespHeader: respHdr, RespBody: respBody,
	}
}

// splitHTTP splits a raw HTTP message into (start line, headers, body).
func splitHTTP(raw string) (line, header, body string) {
	if raw == "" {
		return "", "", ""
	}
	headEnd := strings.Index(raw, "\r\n\r\n")
	sep := 4
	if headEnd < 0 {
		if headEnd = strings.Index(raw, "\n\n"); headEnd >= 0 {
			sep = 2
		}
	}
	head := raw
	if headEnd >= 0 {
		head = raw[:headEnd]
		body = raw[headEnd+sep:]
	}
	nl := strings.IndexByte(head, '\n')
	if nl < 0 {
		return strings.TrimRight(head, "\r"), "", body
	}
	line = strings.TrimRight(head[:nl], "\r")
	header = head[nl+1:]
	return line, header, body
}
