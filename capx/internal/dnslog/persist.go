package dnslog

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// persistVersion is the schema version of the on-disk DNSLog config. Bump it on
// a backward-incompatible layout change so stale files are ignored, not
// mis-parsed.
const persistVersion = 1

// DefaultPersistPath returns the standard location for the DNSLog config
// (~/.capx/dnslog.json), reusing the same data directory the MITM proxy uses.
// On failure (no home dir) it returns "" so persistence is simply disabled.
func DefaultPersistPath() string {
	if dir := strings.TrimSpace(os.Getenv("CAPX_DATA_DIR")); dir != "" {
		return filepath.Join(dir, "dnslog.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".capx", "dnslog.json")
}

// persisted is the on-disk snapshot: connection settings plus the tracked
// payloads (so generated subdomains and their last-known hit state survive a
// daemon restart). Legacy plaintext keys can be read; new writes protect the
// key on Windows and omit it entirely when the instance inherits defaults.
type persisted struct {
	Version      int        `json:"version"`
	BaseURL      string     `json:"base_url"`
	APIKey       string     `json:"api_key"`
	ProtectedKey string     `json:"api_key_protected,omitempty"`
	UseDefaults  *bool      `json:"use_defaults,omitempty"`
	Payloads     []*Payload `json:"payloads"`
}

// load reads and applies the persisted config from c.persistPath. A missing
// file is not an error (fresh install); a malformed or version-mismatched file
// is logged and ignored so a corrupt file never prevents startup.
func (c *Client) load() {
	if c.persistPath == "" {
		return
	}
	b, err := os.ReadFile(c.persistPath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("capx: could not read dnslog config %s: %v", c.persistPath, err)
		}
		return
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		log.Printf("capx: ignoring malformed dnslog config %s: %v", c.persistPath, err)
		return
	}
	if p.Version != persistVersion {
		log.Printf("capx: ignoring dnslog config %s with unsupported version %d", c.persistPath, p.Version)
		return
	}
	c.mu.Lock()
	c.baseURL = p.BaseURL
	c.apiKey = p.APIKey
	if p.ProtectedKey != "" {
		encoded, err := base64.StdEncoding.DecodeString(p.ProtectedKey)
		if err == nil {
			if data, err := unprotectKey(encoded); err == nil {
				c.apiKey = string(data)
			}
		}
	}
	if p.UseDefaults != nil {
		c.useDefaults = *p.UseDefaults
	} else {
		c.useDefaults = p.BaseURL == "" && c.apiKey == ""
	}
	for _, pl := range p.Payloads {
		if pl == nil || pl.Subdomain == "" {
			continue
		}
		if _, ok := c.payloads[pl.Subdomain]; !ok {
			c.order = append(c.order, pl.Subdomain)
		}
		c.payloads[pl.Subdomain] = pl
	}
	c.mu.Unlock()
}

// persist atomically writes the current config + payloads to c.persistPath.
// Failures are logged but never fatal.
func (c *Client) persist() {
	if c.persistPath == "" {
		return
	}
	c.mu.RLock()
	p := persisted{
		Version:  persistVersion,
		BaseURL:  c.baseURL,
		APIKey:   c.apiKey,
		Payloads: make([]*Payload, 0, len(c.order)),
	}
	for _, sub := range c.order {
		if pl, ok := c.payloads[sub]; ok {
			p.Payloads = append(p.Payloads, pl)
		}
	}
	inherit := c.useDefaults
	c.mu.RUnlock()
	p.UseDefaults = &inherit
	if inherit {
		p.BaseURL, p.APIKey = "", ""
	}
	if p.APIKey != "" {
		protected, err := protectKey([]byte(p.APIKey))
		if err != nil {
			log.Printf("capx: could not protect DNSLog credential")
			return
		}
		p.ProtectedKey = base64.StdEncoding.EncodeToString(protected)
		p.APIKey = ""
	}

	if err := writeJSONAtomic(c.persistPath, p); err != nil {
		log.Printf("capx: could not persist dnslog config: %v", err)
	}
}

// writeJSONAtomicshals v and writes it to path via a temp file + rename so
// a concurrent reader never observes a partially written file.
func writeJSONAtomic(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".dnslog-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
