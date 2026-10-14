package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

// testProxy builds a proxy with only the persistence-relevant engines wired,
// skipping the CA/transport setup that proxy.New does, so persistence can be
// unit-tested against a temp config path.
func testProxy(path string) *Proxy {
	p := &Proxy{
		scope:   newScope(),
		rules:   newRuleSet(),
		wsRules: newWSRuleSet(),
		conds:   newCondSet(),
		session: newSessionEngine(),
	}
	p.wirePersistence(path)
	return p
}

func TestPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	p1 := testProxy(path)
	p1.scope.SetRules(
		[]ScopeRule{{Enabled: true, Host: "example.com", Subtree: true}},
		[]ScopeRule{{Enabled: true, Prefix: "https://example.com/logout"}},
	)
	p1.SetInterceptConds([]InterceptCond{
		{Enabled: true, Action: "forward", FileExt: "js,css,png"},
		{Enabled: true, Action: "intercept", Host: "api.example.com"},
	})
	if _, err := p1.rules.Add(&Rule{
		Name: "strip-csp", Target: "response", Where: "header",
		Header: "Content-Security-Policy", Match: ".*", Replace: "", Action: "replace",
	}); err != nil {
		t.Fatalf("rule add: %v", err)
	}
	if _, err := p1.wsRules.Add(&WSMatchRule{
		Name: "role", Enabled: true, Dir: "send", Opcode: "text", Match: `"role":"user"`, Replace: `"role":"admin"`,
	}); err != nil {
		t.Fatalf("ws rule add: %v", err)
	}
	p1.session.SetMacros([]Macro{{
		Name:  "login",
		Steps: []MacroStep{{Scheme: "https", Host: "example.com", Raw: "GET /login HTTP/1.1\r\n\r\n"}},
	}})
	p1.session.SetRules([]SessionRule{{Enabled: true, Host: "example.com", Macro: "login"}})
	p1.session.SetWSMacros([]WSMacro{{
		Name:  "subscribe",
		Steps: []WSMacroStep{{Dir: "send", Opcode: "text", Data: `{"op":"sub","ch":"{{room}}"}`}},
	}})
	p1.session.SetWSRules([]WSRule{{
		Enabled: true, Name: "heartbeat", URL: "chat.example", OnDir: "recv",
		When: `"type":"ping"`, SendDir: "send", Data: `{"type":"pong"}`, MinIntervalMs: 250,
	}})

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected config file written: %v", err)
	}

	// Fresh proxy reading the same path must reconstruct every collection.
	p2 := testProxy(path)

	inc, exc := p2.scope.Snapshot()
	if len(inc) != 1 || inc[0].Host != "example.com" || !inc[0].Subtree {
		t.Fatalf("scope include not restored: %+v", inc)
	}
	if len(exc) != 1 || exc[0].Prefix != "https://example.com/logout" {
		t.Fatalf("scope exclude not restored: %+v", exc)
	}

	conds := p2.conds.snapshot()
	if len(conds) != 2 || conds[0].FileExt != "js,css,png" || conds[1].Host != "api.example.com" {
		t.Fatalf("intercept conds not restored: %+v", conds)
	}

	rules := p2.rules.List()
	if len(rules) != 1 || rules[0].Header != "Content-Security-Policy" || rules[0].ID != "rule-1" {
		t.Fatalf("rules not restored: %+v", rules)
	}
	if rules[0].re == nil {
		t.Fatalf("restored rule regexp not recompiled")
	}
	wmrs := p2.wsRules.List()
	if len(wmrs) != 1 || wmrs[0].ID != "wsrule-1" || wmrs[0].Match != `"role":"user"` || wmrs[0].re == nil {
		t.Fatalf("ws match rules not restored: %+v", wmrs)
	}

	macros := p2.session.Macros()
	if len(macros) != 1 || macros[0].Name != "login" || len(macros[0].Steps) != 1 {
		t.Fatalf("macros not restored: %+v", macros)
	}
	sr := p2.session.Rules()
	if len(sr) != 1 || sr[0].Macro != "login" {
		t.Fatalf("session rules not restored: %+v", sr)
	}

	wsm := p2.session.WSMacros()
	if len(wsm) != 1 || wsm[0].Name != "subscribe" || len(wsm[0].Steps) != 1 || wsm[0].Steps[0].Data != `{"op":"sub","ch":"{{room}}"}` {
		t.Fatalf("ws macros not restored: %+v", wsm)
	}
	wsr := p2.session.WSRules()
	if len(wsr) != 1 || wsr[0].Name != "heartbeat" || wsr[0].When != `"type":"ping"` || wsr[0].MinIntervalMs != 250 {
		t.Fatalf("ws rules not restored: %+v", wsr)
	}

	// The id sequence must advance past restored ids so new rules don't collide.
	added, err := p2.rules.Add(&Rule{Target: "request", Where: "url", Match: "x", Action: "replace"})
	if err != nil {
		t.Fatalf("rule add after restore: %v", err)
	}
	if added.ID != "rule-2" {
		t.Fatalf("expected next rule id rule-2, got %q", added.ID)
	}
}

func TestLoadConfigMissingAndMalformed(t *testing.T) {
	dir := t.TempDir()

	// Missing file: no panic, empty state, persistence still wired.
	missing := filepath.Join(dir, "nope.json")
	p := testProxy(missing)
	if rules := p.rules.List(); len(rules) != 0 {
		t.Fatalf("expected empty rules for missing config, got %d", len(rules))
	}

	// Malformed file: ignored, leaving empty state rather than failing.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	p2 := testProxy(bad)
	if conds := p2.conds.snapshot(); len(conds) != 0 {
		t.Fatalf("expected empty conds for malformed config, got %d", len(conds))
	}
}

func TestPersistDisabledWhenPathEmpty(t *testing.T) {
	p := &Proxy{scope: newScope(), rules: newRuleSet(), wsRules: newWSRuleSet(), conds: newCondSet(), session: newSessionEngine()}
	// No persistPath set and no callbacks wired: mutations must not panic.
	p.scope.AddInclude(ScopeRule{Enabled: true, Host: "x"})
	p.persist() // explicit call is a no-op without a path
}
