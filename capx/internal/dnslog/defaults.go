package dnslog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const DefaultBaseURL = "https://dns.baishax.xyz"

// DefaultSettingsPath is shared by this user's instances. Payload histories
// remain in each instance's existing persistence file.
func DefaultSettingsPath() string {
	if path := strings.TrimSpace(os.Getenv("CAPX_DNSLOG_DEFAULTS_FILE")); path != "" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".capx", "dnslog-defaults.json")
}

type defaultSettings struct {
	Version int    `json:"version"`
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key_protected"`
}

func (c *Client) UseDefaults(path string) {
	c.mu.Lock()
	c.defaultsPath = path
	c.mu.Unlock()
}

func (c *Client) connectionSettings() (base, key string, err error) {
	c.mu.RLock()
	base, key, path, inherit := c.baseURL, c.apiKey, c.defaultsPath, c.useDefaults
	c.mu.RUnlock()
	if !inherit || path == "" {
		return base, key, nil
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return DefaultBaseURL, "", nil
	}
	if err != nil {
		return DefaultBaseURL, "", errors.New("cannot read local DNSLog defaults")
	}
	var settings defaultSettings
	if json.Unmarshal(data, &settings) != nil || settings.Version != 1 {
		return DefaultBaseURL, "", errors.New("invalid local DNSLog defaults")
	}
	if err := validateSettings(settings.BaseURL, ""); err != nil {
		return DefaultBaseURL, "", errors.New("invalid default DNSLog URL")
	}
	encoded, err := base64.StdEncoding.DecodeString(settings.APIKey)
	if err != nil {
		return settings.BaseURL, "", errors.New("invalid protected DNSLog credential")
	}
	secret, err := unprotectKey(encoded)
	if err != nil {
		return settings.BaseURL, "", errors.New("cannot unlock local DNSLog credential for this user")
	}
	return settings.BaseURL, string(secret), nil
}

// ConfigureDefaults updates this user's shared defaults without copying the key
// into per-instance payload history files or exposing it through status.
func (c *Client) ConfigureDefaults(base, key string) error {
	base, key = normalizeBaseURL(base), strings.TrimSpace(key)
	if base == "" {
		base = DefaultBaseURL
	}
	if key == "" {
		oldBase, oldKey, err := c.connectionSettings()
		if err == nil && base == oldBase {
			key = oldKey
		}
	}
	if key == "" {
		return errors.New("default DNSLog API Key is required")
	}
	if err := validateSettings(base, key); err != nil {
		return err
	}
	c.mu.RLock()
	path := c.defaultsPath
	c.mu.RUnlock()
	if path == "" {
		return errors.New("shared DNSLog defaults path is unavailable")
	}
	protected, err := protectKey([]byte(key))
	if err != nil {
		return errors.New("cannot protect DNSLog credential")
	}
	settings := defaultSettings{Version: 1, BaseURL: base, APIKey: base64.StdEncoding.EncodeToString(protected)}
	if err := writeJSONAtomic(path, settings); err != nil {
		return errors.New("cannot save local DNSLog defaults")
	}
	c.mu.Lock()
	c.useDefaults, c.baseURL, c.apiKey = true, DefaultBaseURL, ""
	c.mu.Unlock()
	c.persist()
	return nil
}
