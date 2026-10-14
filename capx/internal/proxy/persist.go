package proxy

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
)

// persistVersion is the schema version of the on-disk config. It is bumped if
// the layout changes in a backward-incompatible way so old files can be
// detected and ignored rather than mis-parsed.
const persistVersion = 1

// PersistedConfig is the on-disk snapshot of the user-configured proxy state
// that must survive daemon restarts: target scope, granular interception
// conditions, inline Match&Replace ("repack") rules, and session-handling
// macros + rules (both HTTP and WebSocket). Runtime-only state — the intercept
// hold queue, live session variables, captured HTTP/WS history — is
// intentionally excluded.
//
// WSMacros / WSRules are additive optional fields: an older config without them
// loads fine (they default to empty), so persistVersion stays at 1.
type PersistedConfig struct {
	Version       int             `json:"version"`
	Upstream      UpstreamConfig  `json:"upstream,omitempty"`
	ScopeInclude  []ScopeRule     `json:"scope_include"`
	ScopeExclude  []ScopeRule     `json:"scope_exclude"`
	InterceptCond []InterceptCond `json:"intercept_conds"`
	Rules         []*Rule         `json:"rules"`
	WSMatchRules  []*WSMatchRule  `json:"ws_match_rules,omitempty"`
	Macros        []Macro         `json:"macros"`
	SessionRules  []SessionRule   `json:"session_rules"`
	WSMacros      []WSMacro       `json:"ws_macros,omitempty"`
	WSRules       []WSRule        `json:"ws_rules,omitempty"`
}

// configPath returns the path of the persisted proxy config (~/.capx/config.json),
// reusing the same data directory the CA is stored in.
func configPath() (string, error) {
	dir, err := dataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

// ExportConfig returns the current persistent proxy configuration (scope,
// interception conditions, match&replace rules, session macros/rules) for a
// project bundle.
func (p *Proxy) ExportConfig() PersistedConfig { return p.snapshotConfig() }

// ImportConfig loads a configuration into the live engines and persists it.
func (p *Proxy) ImportConfig(cfg PersistedConfig) {
	p.applyConfig(cfg)
	p.persist()
}

// snapshotConfig reads the current state of every persistent engine into a
// PersistedConfig value safe to serialize.
func (p *Proxy) snapshotConfig() PersistedConfig {
	inc, exc := p.scope.Snapshot()
	return PersistedConfig{
		Version:       persistVersion,
		Upstream:      p.UpstreamConfig(),
		ScopeInclude:  inc,
		ScopeExclude:  exc,
		InterceptCond: p.conds.snapshot(),
		Rules:         p.rules.List(),
		WSMatchRules:  p.wsRules.List(),
		Macros:        p.session.Macros(),
		SessionRules:  p.session.Rules(),
		WSMacros:      p.session.WSMacros(),
		WSRules:       p.session.WSRules(),
	}
}

// applyConfig loads a PersistedConfig into the live engines. It is called once
// at startup, before the onChange callbacks are wired, so it does not trigger
// a redundant write-back.
func (p *Proxy) applyConfig(cfg PersistedConfig) {
	if route, err := p.parseUpstream(cfg.Upstream); err == nil {
		p.installUpstream(route)
	} else {
		// Do not expose the rejected value; it may contain imported credentials.
		p.installUpstream(&upstreamRoute{})
		log.Printf("capx: invalid saved upstream route ignored")
	}
	p.scope.SetRules(cfg.ScopeInclude, cfg.ScopeExclude)
	p.conds.set(cfg.InterceptCond)
	p.rules.restore(cfg.Rules)
	p.wsRules.restore(cfg.WSMatchRules)
	p.session.setMacros(cfg.Macros)
	p.session.setRules(cfg.SessionRules)
	p.session.setWSMacros(cfg.WSMacros)
	p.session.setWSRules(cfg.WSRules)
}

// loadConfig reads and applies the persisted config from path. A missing file
// is not an error (fresh install); a malformed file is logged and ignored so a
// corrupt config never prevents the proxy from starting.
func (p *Proxy) loadConfig(path string) {
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("capx: could not read proxy config %s: %v", path, err)
		}
		return
	}
	var cfg PersistedConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Printf("capx: ignoring malformed proxy config %s: %v", path, err)
		return
	}
	if cfg.Version != persistVersion {
		log.Printf("capx: ignoring proxy config %s with unsupported version %d", path, cfg.Version)
		return
	}
	p.applyConfig(cfg)
}

// persist serializes the current config and atomically writes it to
// p.persistPath. Writes are serialized by persistMu and never fatal: a failure
// is logged but does not disturb live traffic.
func (p *Proxy) persist() {
	if p.persistPath == "" {
		return
	}
	p.persistMu.Lock()
	defer p.persistMu.Unlock()
	cfg := p.snapshotConfig()
	if err := writeConfigAtomic(p.persistPath, cfg); err != nil {
		log.Printf("capx: could not persist proxy config: %v", err)
	}
}

// writeConfigAtomicshals cfg and writes it to path via a temp file + rename
// so a concurrent reader never observes a partially written file.
func writeConfigAtomic(path string, cfg PersistedConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
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

// wirePersistence sets persistPath, loads any existing config, then installs
// the onChange callbacks so subsequent edits are written back to disk. Wiring
// the callbacks after the load avoids a redundant save of the just-read state.
func (p *Proxy) wirePersistence(path string) {
	p.persistPath = path
	p.loadConfig(path)
	p.scope.onChange = p.persist
	p.conds.onChange = p.persist
	p.rules.onChange = p.persist
	p.wsRules.onChange = p.persist
	p.session.onChange = p.persist
}

// UseConfigPath switches the proxy's persisted user configuration to path and
// replaces the live config with that file's contents. If the file does not
// exist, the live scope/rules/macros are reset to an empty per-instance config.
// This is used by desktop multi-instance mode so each REST/proxy port has an
// isolated Target Scope and rule set while the shared MITM CA can still live in
// ~/.capx.
func (p *Proxy) UseConfigPath(path string) {
	p.scope.onChange = nil
	p.conds.onChange = nil
	p.rules.onChange = nil
	p.wsRules.onChange = nil
	p.session.onChange = nil

	p.persistPath = path
	p.applyConfig(PersistedConfig{Version: persistVersion})
	p.loadConfig(path)

	p.scope.onChange = p.persist
	p.conds.onChange = p.persist
	p.rules.onChange = p.persist
	p.wsRules.onChange = p.persist
	p.session.onChange = p.persist
	p.persist()
}
