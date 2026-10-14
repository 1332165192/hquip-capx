package api

// CaA-style collector/analyzer endpoints: dissect the captured HTTP history into
// frequency-ranked parameters / values / cookies / paths / files, and export any
// category as a plain wordlist for fuzzing (feeds Intruder).

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/hquip/capx/internal/collect"
	"github.com/hquip/capx/internal/model"
)

// buildCollector runs the collector over the (optionally filtered) HTTP history.
func (s *Server) buildCollector(r *http.Request) *collect.Collector {
	c := collect.New()
	for _, tx := range s.st.FilterHTTPTx(httpFilterFromQuery(r)) {
		c.Add(collectMsg(tx))
	}
	return c
}

func collectMsg(tx *model.HTTPTx) collect.Msg {
	ct := ""
	if tx.ReqHdr != nil {
		for k, v := range tx.ReqHdr {
			if strings.EqualFold(k, "Content-Type") {
				ct = v
			}
		}
	}
	return collect.Msg{
		Method: tx.Method, URL: tx.URL, ContentType: ct,
		ReqHeaders: tx.ReqHdr, ReqBody: bodyOf(tx.ReqRaw),
	}
}

// collectScan returns frequency-ranked items per category over the history.
func (s *Server) collectScan(w http.ResponseWriter, r *http.Request) {
	c := s.buildCollector(r)
	max := 200
	if q := r.URL.Query().Get("max"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 {
			max = v
		}
	}
	cats := []string{collect.CatParam, collect.CatValue, collect.CatCookie,
		collect.CatPath, collect.CatFile, collect.CatFullPath, collect.CatEndpoint}
	out := map[string]any{}
	for _, cat := range cats {
		out[cat] = c.Top(cat, max)
	}
	writeJSON(w, http.StatusOK, map[string]any{"counts": c.Categories(), "items": out})
}

// collectWordlist exports one category as a newline-delimited wordlist
// (?type=param|value|cookie|path|file|fullpath|endpoint).
func (s *Server) collectWordlist(w http.ResponseWriter, r *http.Request) {
	cat := r.URL.Query().Get("type")
	if cat == "" {
		cat = collect.CatParam
	}
	c := s.buildCollector(r)
	items := c.Top(cat, 0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="capx-`+cat+`.txt"`)
	for _, it := range items {
		_, _ = w.Write([]byte(it.Value + "\n"))
	}
}
