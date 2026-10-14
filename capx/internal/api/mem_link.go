package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hquip/capx/internal/memscan"
	"github.com/hquip/capx/internal/model"
)

type httpMemHit struct {
	ID     uint64 `json:"id"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Method string `json:"method"`
	Score  int    `json:"score"`
	Where  string `json:"where,omitempty"` // url / req / resp
	Needle string `json:"needle,omitempty"`
}

func asciiPreview(b []byte, max int) string {
	if max <= 0 {
		max = 48
	}
	var out strings.Builder
	for _, c := range b {
		if c == 0 {
			if out.Len() >= 8 {
				break
			}
			continue
		}
		if c >= 32 && c < 127 {
			out.WriteByte(c)
		} else {
			out.WriteByte('.')
		}
		if out.Len() >= max {
			break
		}
	}
	return strings.TrimSpace(out.String())
}

func extractNeedles(sample string, extra string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) < 6 {
			return
		}
		if len(s) > 96 {
			s = s[:96]
		}
		key := strings.ToLower(s)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, s)
	}
	if extra != "" {
		add(extra)
	}
	for _, tok := range []string{"https://", "http://", "Bearer ", "token=", "eyJ"} {
		i := 0
		for {
			j := strings.Index(sample[i:], tok)
			if j < 0 {
				break
			}
			j += i
			end := j + 64
			if end > len(sample) {
				end = len(sample)
			}
			frag := sample[j:end]
			if k := strings.IndexAny(frag, " \t\r\n\"'<>"); k > 0 {
				frag = frag[:k]
			}
			add(frag)
			i = j + len(tok)
		}
	}
	for _, n := range longestPrintableRuns(sample, 12, 8) {
		add(n)
	}
	return out
}

func longestPrintableRuns(s string, minLen, maxN int) []string {
	var cur strings.Builder
	var runs []string
	flush := func() {
		t := strings.TrimSpace(cur.String())
		cur.Reset()
		if len(t) >= minLen {
			runs = append(runs, t)
		}
	}
	for _, r := range s {
		if unicode.IsPrint(r) && r != utf8.RuneError && r != 0 {
			cur.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	if len(runs) > maxN {
		runs = runs[:maxN]
	}
	return runs
}

func scoreHTTPMatch(tx *model.HTTPTx, needle string) (int, string) {
	if tx == nil || needle == "" {
		return 0, ""
	}
	n := strings.ToLower(needle)
	if len(n) < 4 {
		return 0, ""
	}
	if strings.Contains(strings.ToLower(tx.URL), n) {
		return 80 + min(20, len(n)/4), "url"
	}
	if strings.Contains(strings.ToLower(tx.Host), n) {
		return 50, "host"
	}
	if tx.ReqRaw != "" && strings.Contains(strings.ToLower(tx.ReqRaw), n) {
		return 70 + min(15, len(n)/6), "req"
	}
	if tx.RespRaw != "" && strings.Contains(strings.ToLower(tx.RespRaw), n) {
		return 65 + min(15, len(n)/6), "resp"
	}
	if tx.Path != "" && strings.Contains(strings.ToLower(tx.Path), n) {
		return 40, "path"
	}
	return 0, ""
}

func (s *Server) matchHTTPAt(sess memscan.Session, addr uint64, width int) (*model.HTTPTx, int) {
	if s.st == nil || sess == nil || width < 16 {
		return nil, 0
	}
	buf := make([]byte, width)
	n, err := sess.Read(addr, buf)
	if err != nil || n < 8 {
		return nil, 0
	}
	needles := extractNeedles(string(buf[:n]), "")
	if len(needles) == 0 {
		return nil, 0
	}
	var best *model.HTTPTx
	bestScore := 0
	for _, tx := range s.st.ListHTTPTx("") {
		for _, needle := range needles {
			sc, _ := scoreHTTPMatch(tx, needle)
			if sc > bestScore {
				bestScore = sc
				best = tx
			}
		}
	}
	if bestScore < 40 {
		return nil, 0
	}
	return best, bestScore
}

func (s *Server) memLinkHTTP(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	sess, ok := s.session(sid)
	if !ok {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}
	e := s.extFor(sid)
	addr, err := parseAddr(r.URL.Query().Get("addr"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "addr required")
		return
	}
	width := 256
	if q := r.URL.Query().Get("len"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 && v <= 4096 {
			width = v
		}
	}
	buf := make([]byte, width)
	n, _ := sess.Read(addr, buf)
	sample := ""
	if n > 0 {
		sample = string(buf[:n])
	}
	extra := strings.TrimSpace(r.URL.Query().Get("q"))
	needles := extractNeedles(sample, extra)
	type hit = httpMemHit
	var hits []hit
	bestScore := 0
	var best *model.HTTPTx
	if len(needles) > 0 {
		for _, tx := range s.st.ListHTTPTx("") {
			localBest := 0
			where := ""
			used := ""
			for _, needle := range needles {
				sc, wch := scoreHTTPMatch(tx, needle)
				if sc > localBest {
					localBest = sc
					where = wch
					used = needle
				}
			}
			if localBest < 40 {
				continue
			}
			hits = append(hits, hit{ID: tx.ID, URL: tx.URL, Host: tx.Host, Method: tx.Method, Score: localBest, Where: where, Needle: used})
			if localBest > bestScore {
				bestScore = localBest
				best = tx
			}
			if len(hits) >= 30 {
				break
			}
		}
	}
	if best != nil && e.pid != 0 {
		s.st.AddMemHit(&model.MemHit{
			PID:    e.pid,
			Addr:   addr,
			Type:   "http_link",
			Value:  best.URL,
			TS:     time.Now().UTC(),
			HTTPID: best.ID,
			Host:   best.Host,
		})
	}
	note := "按内存窗口提取 URL/token/可打印串，对 HTTP 历史打分匹配；最高分命中会写入 MemHit 并进入 /api/correlate。证书固定明文仍走 Frida tls hook。"
	writeJSON(w, http.StatusOK, map[string]any{
		"pid":     e.pid,
		"addr":    formatHex(addr),
		"needles": needles,
		"http":    hits,
		"best": func() any {
			if best == nil {
				return nil
			}
			return map[string]any{"id": best.ID, "url": best.URL, "host": best.Host, "score": bestScore}
		}(),
		"note": note,
	})
}
