package hae

import (
	"strings"
	"testing"
)

const sampleRules = `
rules:
- group: Fingerprint
  rule:
  - name: Shiro
    loaded: true
    f_regex: (rememberMe=)
    s_regex: ''
    format: '{0}'
    color: green
    scope: any header
    engine: dfa
    sensitive: true
  - name: JSON Web Token
    loaded: true
    f_regex: (eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9._-]{5,}\.[A-Za-z0-9._-]{5,})
    s_regex: ''
    format: '{0}'
    color: green
    scope: any
    engine: nfa
    sensitive: true
- group: Info
  rule:
  - name: Email
    loaded: true
    f_regex: ([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})
    s_regex: ''
    format: '{0}'
    color: yellow
    scope: response body
    engine: dfa
    sensitive: false
  - name: Disabled
    loaded: false
    f_regex: (never)
    color: red
    scope: any
- group: Bad
  rule:
  - name: BackrefUnsupported
    loaded: true
    f_regex: (\w+)\1
    s_regex: ''
    format: '{0}'
    color: red
    scope: any
    engine: nfa
    sensitive: true
`

func loadEngine(t *testing.T) *Engine {
	t.Helper()
	e := New()
	loaded, skipped, err := e.Load([]byte(sampleRules))
	if err != nil {
		t.Fatal(err)
	}
	// 3 valid+loaded rules (Shiro, JWT, Email); Disabled skipped (loaded:false);
	// Backref rule skipped (RE2 can't compile it).
	if loaded != 3 {
		t.Fatalf("loaded = %d, want 3", loaded)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "BackrefUnsupported") {
		t.Fatalf("skipped = %v, want the backref rule", skipped)
	}
	return e
}

func TestHaEApply(t *testing.T) {
	e := loadEngine(t)
	m := Message{
		ReqHeader:  "Cookie: rememberMe=deleteMe; sid=1",
		RespBody:   "contact alice@example.com or read token eyJabcde.eyJpayload.sigsigsig",
		RespHeader: "Content-Type: text/html",
	}
	matches := e.Apply(m)

	hit := map[string]Match{}
	for _, mt := range matches {
		hit[mt.Name] = mt
	}
	if _, ok := hit["Shiro"]; !ok {
		t.Error("expected Shiro (rememberMe in header)")
	}
	if mt, ok := hit["Email"]; !ok || mt.Extract[0] != "alice@example.com" {
		t.Errorf("expected Email match, got %+v", mt)
	}
	if _, ok := hit["JSON Web Token"]; !ok {
		t.Error("expected JWT match in response body (scope any)")
	}
}

func TestHaEScopeIsolation(t *testing.T) {
	e := loadEngine(t)
	// Email rule is response-body-only; an email only in the request body must
	// NOT match it.
	m := Message{ReqBody: "alice@example.com"}
	for _, mt := range e.Apply(m) {
		if mt.Name == "Email" {
			t.Fatal("Email rule should not match request body (scope=response body)")
		}
	}
}

func TestHaECaseInsensitive(t *testing.T) {
	e := loadEngine(t)
	// Email is sensitive:false => case-insensitive; uppercase should still match.
	m := Message{RespBody: "ALICE@EXAMPLE.COM"}
	found := false
	for _, mt := range e.Apply(m) {
		if mt.Name == "Email" {
			found = true
		}
	}
	if !found {
		t.Fatal("case-insensitive Email rule should match uppercase")
	}
}
