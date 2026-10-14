package proxy

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Intruder attack modes (Burp parity).
const (
	IntruderSniper    = "sniper"    // one payload set, vary one position at a time
	IntruderBattering = "battering" // one payload set, same value in all positions
	IntruderPitchfork = "pitchfork" // one set per position, advance in lockstep
	IntruderCluster   = "cluster"   // one set per position, cartesian product
)

const intruderMaxRequests = 5000

// PayloadProcessing transforms a payload before it is inserted into the
// template. Steps apply in order: case-fold, prefix/suffix, then encode.
type PayloadProcessing struct {
	Case   string `json:"case"`   // "" | "upper" | "lower"
	Prefix string `json:"prefix"` // prepend (before encoding)
	Suffix string `json:"suffix"` // append (before encoding)
	Encode string `json:"encode"` // "" | "url" | "urlall" | "base64" | "hex"
}

func (p PayloadProcessing) apply(s string) string {
	switch strings.ToLower(p.Case) {
	case "upper":
		s = strings.ToUpper(s)
	case "lower":
		s = strings.ToLower(s)
	}
	s = p.Prefix + s + p.Suffix
	switch strings.ToLower(p.Encode) {
	case "url":
		s = url.QueryEscape(s)
	case "urlall":
		s = encodeAllPercent(s)
	case "base64":
		s = base64.StdEncoding.EncodeToString([]byte(s))
	case "hex":
		s = hex.EncodeToString([]byte(s))
	}
	return s
}

func encodeAllPercent(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// IntruderConfig is a full attack specification.
type IntruderConfig struct {
	Scheme      string              `json:"scheme"`
	Host        string              `json:"host"`
	Template    string              `json:"template"` // raw request, §...§ marks positions
	Mode        string              `json:"mode"`
	PayloadSets [][]string          `json:"payload_sets"` // per-position sets (Sniper/Battering use set 0)
	Processing  []PayloadProcessing `json:"processing"`   // per-position (index-aligned, optional)
	GrepMatch   []string            `json:"grep_match"`   // substrings flagged in the response
	GrepExtract []string            `json:"grep_extract"` // regexes; first group (or whole match) captured
	Concurrency int                 `json:"concurrency"`
	DelayMs     int                 `json:"delay_ms"`
	Follow      bool                `json:"follow"`
}

// IntruderResult is one request's outcome.
type IntruderResult struct {
	Index    int      `json:"index"`
	Payloads []string `json:"payloads"`
	Status   int      `json:"status"`
	Length   int      `json:"length"`
	Millis   int64    `json:"millis"`
	Matched  bool     `json:"matched"`
	Extracts []string `json:"extracts,omitempty"`
	Error    string   `json:"error,omitempty"`
}

// template is a parsed request with literal segments and the base content of
// each §...§ marker.
type template struct {
	segs  []string // len = markers+1
	bases []string // len = markers
}

var markerRe = regexp.MustCompile(`§([^§]*)§`)

func parseTemplate(s string) template {
	var t template
	last := 0
	for _, m := range markerRe.FindAllStringSubmatchIndex(s, -1) {
		t.segs = append(t.segs, s[last:m[0]])
		t.bases = append(t.bases, s[m[2]:m[3]])
		last = m[1]
	}
	t.segs = append(t.segs, s[last:])
	return t
}

func (t template) markers() int { return len(t.bases) }

// render substitutes values (len == markers) into the template.
func (t template) render(values []string) string {
	var b strings.Builder
	for i, seg := range t.segs {
		b.WriteString(seg)
		if i < len(values) {
			b.WriteString(values[i])
		}
	}
	return b.String()
}

// buildVectors expands the config into the ordered list of per-position value
// vectors (each vector has one entry per marker) for the chosen mode.
func buildVectors(mode string, markers int, sets [][]string, procs []PayloadProcessing) [][]string {
	proc := func(pos int, raw string) string {
		if pos < len(procs) {
			return procs[pos].apply(raw)
		}
		return raw
	}
	set0 := []string{}
	if len(sets) > 0 {
		set0 = sets[0]
	}

	var out [][]string
	switch mode {
	case IntruderBattering:
		for _, p := range set0 {
			v := make([]string, markers)
			for k := range v {
				v[k] = proc(k, p)
			}
			out = append(out, v)
		}
	case IntruderPitchfork:
		n := minSetLen(sets, markers)
		for i := 0; i < n; i++ {
			v := make([]string, markers)
			for k := 0; k < markers; k++ {
				v[k] = proc(k, sets[k][i])
			}
			out = append(out, v)
		}
	case IntruderCluster:
		out = clusterProduct(markers, sets, proc)
	default: // sniper: vary one position at a time; non-target slots filled with
		// the marker base by fillSniperBases afterwards.
		for pos := 0; pos < markers; pos++ {
			for _, p := range set0 {
				v := make([]string, markers)
				v[pos] = proc(pos, p)
				out = append(out, v)
			}
		}
	}
	return out
}

func minSetLen(sets [][]string, markers int) int {
	n := -1
	for i := 0; i < markers; i++ {
		l := 0
		if i < len(sets) {
			l = len(sets[i])
		}
		if n < 0 || l < n {
			n = l
		}
	}
	if n < 0 {
		return 0
	}
	return n
}

func clusterProduct(markers int, sets [][]string, proc func(int, string) string) [][]string {
	out := [][]string{make([]string, markers)}
	for k := 0; k < markers; k++ {
		set := []string{""}
		if k < len(sets) && len(sets[k]) > 0 {
			set = sets[k]
		}
		var next [][]string
		for _, prefix := range out {
			for _, p := range set {
				v := append([]string(nil), prefix...)
				v[k] = proc(k, p)
				next = append(next, v)
			}
		}
		out = next
	}
	return out
}

// RunIntruder executes the attack and returns per-request results in order.
func RunIntruder(cfg IntruderConfig) ([]IntruderResult, error) {
	t := parseTemplate(cfg.Template)
	markers := t.markers()
	if markers == 0 {
		return nil, fmt.Errorf("模板中至少需要一个 §...§ 标记")
	}
	if cfg.Mode == IntruderPitchfork || cfg.Mode == IntruderCluster {
		if len(cfg.PayloadSets) < markers {
			return nil, fmt.Errorf("%s 模式需要为每个标记位(%d)提供一个 payload 集", cfg.Mode, markers)
		}
	}

	vectors := buildVectors(cfg.Mode, markers, cfg.PayloadSets, cfg.Processing)
	// Sniper leaves non-target positions empty; fill them with the marker base.
	if cfg.Mode == "" || cfg.Mode == IntruderSniper {
		fillSniperBases(vectors, t, cfg.PayloadSets, cfg.Processing)
	}
	if len(vectors) == 0 {
		return nil, fmt.Errorf("没有可发送的 payload")
	}
	if len(vectors) > intruderMaxRequests {
		return nil, fmt.Errorf("请求数 %d 超过上限 %d，请缩小 payload 集", len(vectors), intruderMaxRequests)
	}

	matchers := cfg.GrepMatch
	extractors := make([]*regexp.Regexp, 0, len(cfg.GrepExtract))
	for _, e := range cfg.GrepExtract {
		if re, err := regexp.Compile(e); err == nil {
			extractors = append(extractors, re)
		}
	}

	conc := cfg.Concurrency
	if conc < 1 {
		conc = 1
	}
	if conc > 50 {
		conc = 50
	}

	results := make([]IntruderResult, len(vectors))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if cfg.DelayMs > 0 {
					time.Sleep(time.Duration(cfg.DelayMs) * time.Millisecond)
				}
				raw := t.render(vectors[i])
				res := SendRawOpts(cfg.Scheme, cfg.Host, raw, cfg.Follow)
				out := IntruderResult{Index: i, Payloads: vectors[i], Status: res.Status, Length: res.RespLen, Millis: res.Millis}
				if res.Error != "" {
					out.Error = res.Error
				}
				for _, m := range matchers {
					if m != "" && strings.Contains(res.RespRaw, m) {
						out.Matched = true
						break
					}
				}
				for _, re := range extractors {
					if g := re.FindStringSubmatch(res.RespRaw); g != nil {
						if len(g) > 1 {
							out.Extracts = append(out.Extracts, g[1])
						} else {
							out.Extracts = append(out.Extracts, g[0])
						}
					}
				}
				results[i] = out
			}
		}()
	}
	for i := range vectors {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results, nil
}

// fillSniperBases replaces the empty non-target slots produced by buildVectors
// (sniper mode) with each marker's literal base content.
func fillSniperBases(vectors [][]string, t template, sets [][]string, procs []PayloadProcessing) {
	set0 := []string{}
	if len(sets) > 0 {
		set0 = sets[0]
	}
	n := len(set0)
	if n == 0 {
		return
	}
	idx := 0
	for pos := 0; pos < t.markers(); pos++ {
		for p := 0; p < n; p++ {
			for k := 0; k < t.markers(); k++ {
				if k != pos {
					vectors[idx][k] = t.bases[k]
				}
			}
			idx++
		}
	}
}
