// Package collect implements a CaA-compatible (github.com/gh0stkey/CaA)
// collector/analyzer: it passively dissects captured HTTP messages and extracts
// parameters, parameter values, cookies, path segments, files and full paths,
// counting how often each appears. The aggregated, frequency-ranked items make
// practical fuzzing dictionaries (params/paths/files) that feed capx's Intruder.
package collect

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Category names for collected items.
const (
	CatParam    = "param"
	CatValue    = "value"
	CatCookie   = "cookie"
	CatPath     = "path"     // each path segment (per level)
	CatFile     = "file"     // last segment that looks like a file (has a dot)
	CatFullPath = "fullpath" // the complete URL path
	CatEndpoint = "endpoint" // last path segment
)

// Msg is one captured HTTP message to dissect.
type Msg struct {
	Method      string
	URL         string
	ContentType string
	ReqHeaders  map[string]string // for Cookie extraction
	ReqBody     string
}

// Item is one collected token with its occurrence count.
type Item struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// Collector aggregates extracted tokens with frequency counts. Not safe for
// concurrent use; callers build one per scan.
type Collector struct {
	cats map[string]map[string]int
}

// New returns an empty collector.
func New() *Collector {
	return &Collector{cats: map[string]map[string]int{}}
}

func (c *Collector) bump(cat, val string) {
	val = strings.TrimSpace(val)
	if val == "" || len(val) > 256 {
		return
	}
	m := c.cats[cat]
	if m == nil {
		m = map[string]int{}
		c.cats[cat] = m
	}
	m[val]++
}

// Add dissects one message into the collector.
func (c *Collector) Add(m Msg) {
	u, err := url.Parse(m.URL)
	if err == nil {
		c.addPath(u.Path)
		for k, vs := range u.Query() {
			c.bump(CatParam, k)
			for _, v := range vs {
				c.bump(CatValue, v)
			}
		}
	}
	c.addCookies(m.ReqHeaders)
	c.addBody(m.ContentType, m.ReqBody)
}

func (c *Collector) addPath(p string) {
	if p == "" {
		return
	}
	c.bump(CatFullPath, p)
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for _, s := range segs {
		if s != "" {
			c.bump(CatPath, s)
		}
	}
	if last := segs[len(segs)-1]; last != "" {
		c.bump(CatEndpoint, last)
		if strings.Contains(last, ".") {
			c.bump(CatFile, last)
		}
	}
}

func (c *Collector) addCookies(h map[string]string) {
	for k, v := range h {
		if !strings.EqualFold(k, "Cookie") {
			continue
		}
		for _, pair := range strings.Split(v, ";") {
			if eq := strings.IndexByte(pair, '='); eq >= 0 {
				c.bump(CatCookie, strings.TrimSpace(pair[:eq]))
				c.bump(CatValue, strings.TrimSpace(pair[eq+1:]))
			}
		}
	}
}

var multipartName = regexp.MustCompile(`name="([^"]+)"`)
var xmlTag = regexp.MustCompile(`<([A-Za-z_][\w\-.]*)[\s>]`)

func (c *Collector) addBody(ct, body string) {
	if body == "" {
		return
	}
	lc := strings.ToLower(ct)
	switch {
	case strings.Contains(lc, "application/json"):
		var v any
		if json.Unmarshal([]byte(body), &v) == nil {
			c.walkJSON(v)
		}
	case strings.Contains(lc, "multipart/form-data"):
		for _, m := range multipartName.FindAllStringSubmatch(body, -1) {
			c.bump(CatParam, m[1])
		}
	case strings.Contains(lc, "xml"):
		for _, m := range xmlTag.FindAllStringSubmatch(body, -1) {
			c.bump(CatParam, m[1])
		}
	default:
		// Default to URL-encoded form (k=v&k2=v2).
		if vals, err := url.ParseQuery(body); err == nil {
			for k, vs := range vals {
				c.bump(CatParam, k)
				for _, v := range vs {
					c.bump(CatValue, v)
				}
			}
		}
	}
}

// walkJSON collects object keys as params and scalar values as values.
func (c *Collector) walkJSON(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			c.bump(CatParam, k)
			c.walkJSON(val)
		}
	case []any:
		for _, e := range t {
			c.walkJSON(e)
		}
	case string:
		c.bump(CatValue, t)
	}
}

// Top returns the items in a category ranked by descending frequency (ties
// broken alphabetically), capped at n (n<=0 = all).
func (c *Collector) Top(cat string, n int) []Item {
	m := c.cats[cat]
	out := make([]Item, 0, len(m))
	for v, cnt := range m {
		out = append(out, Item{Value: v, Count: cnt})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Categories returns the per-category unique-token counts.
func (c *Collector) Categories() map[string]int {
	out := map[string]int{}
	for cat, m := range c.cats {
		out[cat] = len(m)
	}
	return out
}
