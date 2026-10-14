// Package dnslog is capx's out-of-band (OOB) interaction client, a
// Collaborator-style integration with the DNSLog platform
// (github.com/hquip/dnslog). It lets capx request unique throwaway subdomains,
// embed them in proxied/repeated/Intruder requests, and poll the platform to
// detect when a target performs an out-of-band DNS or HTTP callback — the
// canonical way to find blind/no-echo vulnerabilities (SSRF, XXE, JNDI,
// blind command injection, ...).
//
// The client talks to the DNSLog REST API (/api/v1) authenticating with an
// X-API-Key header, so it works fully headless. Hits discovered by the
// background poller are published onto the capx event bus (Source "dnslog",
// kind "dnslog_hit") so they surface in the live SSE stream and the console's
// log view alongside captured traffic.
package dnslog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

// defaultTimeout bounds every call to the DNSLog platform so a slow or
// unreachable server never blocks the poller or an API handler indefinitely.
const defaultTimeout = 15 * time.Second

// Payload is one requested OOB subdomain plus the latest hit state observed for
// it. It is what the console lists and what the user copies into a target
// request (use FullDomain, e.g. as an SSRF URL host or an XXE SYSTEM entity).
type Payload struct {
	Subdomain  string    `json:"subdomain"`
	Domain     string    `json:"domain"`
	FullDomain string    `json:"full_domain"`
	ExpiresAt  string    `json:"expires_at,omitempty"`
	Note       string    `json:"note,omitempty"`
	Created    time.Time `json:"created"`

	Received  bool      `json:"received"`
	DNSCount  int64     `json:"dns_count"`
	HTTPCount int64     `json:"http_count"`
	LastCheck time.Time `json:"last_check,omitempty"`
	LastHit   time.Time `json:"last_hit,omitempty"`
}

// CheckResult mirrors the DNSLog platform's GET /api/v1/dnslog/check response.
type CheckResult struct {
	Subdomain string `json:"subdomain"`
	Received  bool   `json:"received"`
	DNSCount  int64  `json:"dns_count"`
	HTTPCount int64  `json:"http_count"`
	Total     int64  `json:"total"`
	DNSLogs   []any  `json:"dns_logs"`
	HTTPLogs  []any  `json:"http_logs"`
}

// Status is a console-facing summary of how the client is configured and
// whether the platform is reachable. APIKey is intentionally never returned;
// only APIKeySet indicates whether one is stored.
type Status struct {
	Configured   bool   `json:"configured"`
	BaseURL      string `json:"base_url"`
	APIKeySet    bool   `json:"api_key_set"`
	Reachable    bool   `json:"reachable"`
	Error        string `json:"error,omitempty"`
	PayloadCount int    `json:"payload_count"`
	Polling      bool   `json:"polling"`
	PollSeconds  int    `json:"poll_seconds"`
	UseDefaults  bool   `json:"use_defaults"`
}

// Client is the DNSLog OOB integration. It is safe for concurrent use.
type Client struct {
	st          *store.Store
	persistPath string
	http        *http.Client

	mu           sync.RWMutex
	baseURL      string
	apiKey       string
	defaultsPath string
	useDefaults  bool
	payloads     map[string]*Payload // keyed by Subdomain
	order        []string            // subdomains in insertion order

	pollEvery time.Duration
	polling   bool
}

// New builds a DNSLog client publishing hits onto st. persistPath, if
// non-empty, is a JSON file the config + tracked payloads are loaded from at
// startup and written back to on every change (a missing file is fine).
func New(st *store.Store, persistPath string) *Client {
	c := &Client{
		st:          st,
		persistPath: persistPath,
		http: &http.Client{Timeout: defaultTimeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 0 && (req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host) {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("too many DNSLog redirects")
			}
			return nil
		}},
		payloads:    make(map[string]*Payload),
		pollEvery:   15 * time.Second,
		baseURL:     DefaultBaseURL,
		useDefaults: true,
	}
	c.load()
	return c
}

// Configure sets (or clears) the DNSLog platform base URL and API key, then
// persists. A bare host without scheme is assumed to be https. An empty baseURL
// clears the configuration.
func (c *Client) Configure(baseURL, apiKey string) error {
	baseURL = normalizeBaseURL(baseURL)
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" && baseURL != "" {
		oldBase, oldKey, err := c.connectionSettings()
		if err == nil && oldBase == baseURL {
			apiKey = oldKey
		}
	}
	if err := validateSettings(baseURL, apiKey); err != nil {
		return err
	}
	c.mu.Lock()
	c.baseURL = baseURL
	c.apiKey = apiKey
	c.useDefaults = false
	c.mu.Unlock()
	c.persist()
	return nil
}

func validateSettings(base, key string) error {
	if strings.ContainsAny(key, "\r\n\x00") {
		return errors.New("invalid API Key")
	}
	if base == "" {
		return nil
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("base_url must be an HTTP(S) origin without credentials or query")
	}
	return nil
}

// normalizeBaseURL trims whitespace and a trailing slash and defaults a
// scheme-less value to https so "example.com" and "example.com/" both work.
func normalizeBaseURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	return strings.TrimRight(s, "/")
}

func (c *Client) configured() bool {
	base, key, err := c.connectionSettings()
	return err == nil && base != "" && key != ""
}

// Status reports configuration and, when configured, probes reachability via
// the platform's summary endpoint.
func (c *Client) Status(ctx context.Context) Status {
	base, key, configErr := c.connectionSettings()
	c.mu.RLock()
	st := Status{
		Configured:   configErr == nil && base != "" && key != "",
		BaseURL:      base,
		APIKeySet:    key != "",
		PayloadCount: len(c.payloads),
		Polling:      c.polling,
		PollSeconds:  int(c.pollEvery / time.Second),
		UseDefaults:  c.useDefaults,
	}
	c.mu.RUnlock()
	if configErr != nil {
		st.Error = configErr.Error()
		return st
	}
	if st.Configured {
		probeContext, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		if _, err := c.Logs(probeContext, 1, 1, ""); err != nil {
			st.Error = err.Error()
		} else {
			st.Reachable = true
		}
	}
	return st
}

// Logs reads the documented paginated DNS log endpoint. It does not create,
// clear or rotate provider records or credentials.
func (c *Client) Logs(ctx context.Context, page, pageSize int, subdomain string) (map[string]any, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}
	q := url.Values{"page": {strconv.Itoa(page)}, "page_size": {strconv.Itoa(pageSize)}}
	if subdomain = strings.TrimSpace(subdomain); subdomain != "" {
		q.Set("subdomain", subdomain)
	}
	var result map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/dnslog/logs", q, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Summary fetches the platform's overview stats (GET /api/v1/summary). It
// doubles as a lightweight connectivity/credentials check.
func (c *Client) Summary(ctx context.Context) (map[string]any, error) {
	var out map[string]any
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/summary", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// NewPayload requests a fresh unique subdomain from the platform
// (GET /api/v1/dnslog/subdomain), tracks it locally, and returns it. domain is
// optional (selects which configured root domain to use); note is a free-form
// label the user can attach to remember what the payload is for.
func (c *Client) NewPayload(ctx context.Context, domain, note string) (*Payload, error) {
	q := url.Values{}
	if domain = strings.TrimSpace(domain); domain != "" {
		q.Set("domain", domain)
	}
	var resp struct {
		Subdomain  string `json:"subdomain"`
		Domain     string `json:"domain"`
		FullDomain string `json:"full_domain"`
		ExpiresAt  string `json:"expires_at"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/dnslog/subdomain", q, &resp); err != nil {
		return nil, err
	}
	if resp.Subdomain == "" {
		return nil, errors.New("platform returned an empty subdomain")
	}
	p := &Payload{
		Subdomain:  resp.Subdomain,
		Domain:     resp.Domain,
		FullDomain: resp.FullDomain,
		ExpiresAt:  resp.ExpiresAt,
		Note:       strings.TrimSpace(note),
		Created:    time.Now().UTC(),
	}
	c.mu.Lock()
	if _, ok := c.payloads[p.Subdomain]; !ok {
		c.order = append(c.order, p.Subdomain)
	}
	c.payloads[p.Subdomain] = p
	c.mu.Unlock()
	c.persist()
	return p, nil
}

// Check queries whether subdomain has received any DNS/HTTP callback
// (GET /api/v1/dnslog/check). protocol is "dns"|"http"|"all"; since limits to
// the last N seconds (0 = no limit); limit caps returned log rows. If the
// subdomain is tracked, its hit state is updated and a "dnslog_hit" event is
// published on a newly observed hit.
func (c *Client) Check(ctx context.Context, subdomain, protocol string, since, limit int) (*CheckResult, error) {
	subdomain = strings.TrimSpace(subdomain)
	if subdomain == "" {
		return nil, errors.New("subdomain is required")
	}
	q := url.Values{}
	q.Set("subdomain", subdomain)
	if protocol != "" {
		q.Set("protocol", protocol)
	}
	if since > 0 {
		q.Set("since", strconv.Itoa(since))
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var res CheckResult
	if err := c.doJSON(ctx, http.MethodGet, "/api/v1/dnslog/check", q, &res); err != nil {
		return nil, err
	}
	c.applyCheck(subdomain, &res)
	return &res, nil
}

// applyCheck folds a check result into the tracked payload (if any) and emits a
// hit event the first time, or whenever the DNS/HTTP counts increase.
func (c *Client) applyCheck(subdomain string, res *CheckResult) {
	c.mu.Lock()
	p, ok := c.payloads[subdomain]
	if !ok {
		c.mu.Unlock()
		return
	}
	now := time.Now().UTC()
	newHit := res.Received && (!p.Received || res.DNSCount > p.DNSCount || res.HTTPCount > p.HTTPCount)
	p.Received = res.Received
	p.DNSCount = res.DNSCount
	p.HTTPCount = res.HTTPCount
	p.LastCheck = now
	if newHit {
		p.LastHit = now
	}
	full := p.FullDomain
	note := p.Note
	c.mu.Unlock()
	c.persist()

	if newHit && c.st != nil {
		c.st.Publish(model.Event{
			Source: model.SourceDNSLog,
			Kind:   "dnslog_hit",
			Data: map[string]any{
				"subdomain":   subdomain,
				"full_domain": full,
				"note":        note,
				"dns_count":   res.DNSCount,
				"http_count":  res.HTTPCount,
				"total":       res.Total,
			},
		})
	}
}

// Poll checks every tracked payload once and returns the refreshed list. It is
// the manual equivalent of one background poller tick.
func (c *Client) Poll(ctx context.Context) ([]*Payload, error) {
	if !c.configured() {
		return nil, errors.New("dnslog not configured")
	}
	for _, sub := range c.subdomains() {
		if _, err := c.Check(ctx, sub, "all", 0, 20); err != nil {
			return nil, err
		}
	}
	return c.Payloads(), nil
}

// Payloads returns a copy of the tracked payloads, newest first.
func (c *Client) Payloads() []*Payload {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*Payload, 0, len(c.order))
	for _, sub := range c.order {
		if p, ok := c.payloads[sub]; ok {
			cp := *p
			out = append(out, &cp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// Forget stops tracking a payload locally (the platform record is untouched).
func (c *Client) Forget(subdomain string) bool {
	c.mu.Lock()
	_, ok := c.payloads[subdomain]
	if ok {
		delete(c.payloads, subdomain)
		for i, s := range c.order {
			if s == subdomain {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
	}
	c.mu.Unlock()
	if ok {
		c.persist()
	}
	return ok
}

func (c *Client) subdomains() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]string, len(c.order))
	copy(out, c.order)
	return out
}

// StartPoller runs a background loop that polls outstanding (not-yet-hit)
// payloads every pollEvery until ctx is cancelled. It is a no-op-friendly
// goroutine: ticks do nothing while the client is unconfigured or has no
// pending payloads, so it is always safe to start at daemon boot.
func (c *Client) StartPoller(ctx context.Context) {
	c.mu.Lock()
	if c.polling {
		c.mu.Unlock()
		return
	}
	c.polling = true
	every := c.pollEvery
	c.mu.Unlock()

	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				c.pollPending(ctx)
			}
		}
	}()
}

// pollPending checks only payloads that have not yet registered a hit, to keep
// per-tick load proportional to outstanding work rather than total history.
func (c *Client) pollPending(ctx context.Context) {
	if !c.configured() {
		return
	}
	c.mu.RLock()
	pending := make([]string, 0, len(c.order))
	for _, sub := range c.order {
		if p, ok := c.payloads[sub]; ok && !p.Received {
			pending = append(pending, sub)
		}
	}
	c.mu.RUnlock()
	for _, sub := range pending {
		cctx, cancel := context.WithTimeout(ctx, defaultTimeout)
		_, _ = c.Check(cctx, sub, "all", 0, 20)
		cancel()
	}
}

// doJSON performs an authenticated request to path (with optional query) and
// decodes a JSON response into out. Non-2xx responses surface the platform's
// error message when present.
func (c *Client) doJSON(ctx context.Context, method, path string, q url.Values, out any) error {
	base, key, configErr := c.connectionSettings()
	if configErr != nil {
		return configErr
	}
	if base == "" || key == "" {
		return errors.New("dnslog not configured: set base_url and api_key first")
	}
	full := base + path
	if len(q) > 0 {
		full += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, full, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if msg := extractError(body); msg != "" {
			return fmt.Errorf("dnslog %s: %s", resp.Status, strings.ReplaceAll(msg, key, "[redacted]"))
		}
		return fmt.Errorf("dnslog %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// extractError pulls the "error" field out of a JSON error body, falling back
// to the trimmed raw body so callers always get something actionable.
func extractError(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		return e.Error
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
