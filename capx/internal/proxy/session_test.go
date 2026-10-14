package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestApplyVars(t *testing.T) {
	vars := map[string]string{"csrf": "ABC123", "id": "42"}
	got := applyVars("token={{csrf}}&u={{ id }}&keep={{missing}}", vars)
	want := "token=ABC123&u=42&keep={{missing}}"
	if got != want {
		t.Fatalf("applyVars = %q, want %q", got, want)
	}
}

func TestExtractValues(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Set-Cookie: SESSION=zzz9; Path=/; HttpOnly\r\n" +
		"X-Token: hdr-tok\r\n" +
		"\r\n" +
		`<input name="csrf" value="TOK-55">`
	exs := []Extractor{
		{Name: "csrf", Source: "body", Expr: `name="csrf" value="([^"]+)"`},
		{Name: "tok", Source: "header", Expr: "X-Token"},
		{Name: "sess", Source: "setcookie", Expr: "SESSION"},
	}
	got := extractValues(raw, exs)
	if got["csrf"] != "TOK-55" || got["tok"] != "hdr-tok" || got["sess"] != "zzz9" {
		t.Fatalf("extractValues = %#v", got)
	}
}

func TestRunMacroChaining(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			fmt.Fprint(w, `<input name="csrf" value="TOK-77">`)
		case "/do":
			// echo the csrf the client supplied
			fmt.Fprintf(w, "csrf=%s", r.URL.Query().Get("csrf"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	m := Macro{Name: "login", Steps: []MacroStep{
		{Scheme: "http", Host: host, Raw: fmt.Sprintf("GET /login HTTP/1.1\r\nHost: %s\r\n\r\n", host),
			Extract: []Extractor{{Name: "csrf", Source: "body", Expr: `value="([^"]+)"`}}},
		{Scheme: "http", Host: host, Raw: fmt.Sprintf("GET /do?csrf={{csrf}} HTTP/1.1\r\nHost: %s\r\n\r\n", host)},
	}}
	store := newSessionVars()
	run := RunMacro(m, store)
	if len(run.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(run.Steps))
	}
	if run.Vars["csrf"] != "TOK-77" {
		t.Fatalf("csrf var = %q, want TOK-77", run.Vars["csrf"])
	}
	if run.Steps[1].Status != http.StatusOK {
		t.Fatalf("step 2 status = %d", run.Steps[1].Status)
	}
	// The second step must have sent the substituted csrf.
	if v, _ := store.Get("csrf"); v != "TOK-77" {
		t.Fatalf("store csrf = %q", v)
	}
}

func TestApplyToRequest(t *testing.T) {
	e := newSessionEngine()
	e.vars.Set("csrf", "XYZ")
	e.SetRules([]SessionRule{{
		Enabled:    true,
		Host:       "example.com",
		SetHeaders: []HeaderInject{{Name: "X-CSRF", Var: "csrf"}},
		SubstBody:  true,
	}})
	req, _ := http.NewRequest("POST", "http://example.com/form", strings.NewReader("token={{csrf}}&x=1"))
	req.Host = "example.com"
	changed, err := e.applyToRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected applyToRequest to report a change")
	}
	if req.Header.Get("X-CSRF") != "XYZ" {
		t.Fatalf("header X-CSRF = %q, want XYZ", req.Header.Get("X-CSRF"))
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "token=XYZ&x=1" {
		t.Fatalf("body = %q, want token=XYZ&x=1", string(body))
	}
	// Non-matching host is left untouched.
	req2, _ := http.NewRequest("GET", "http://other.test/", nil)
	req2.Host = "other.test"
	if changed, err := e.applyToRequest(req2); err != nil || changed {
		t.Fatal("non-matching host should not change")
	}
}

func TestMaybeRelogin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `value="FRESH"`)
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	e := newSessionEngine()
	e.SetMacros([]Macro{{Name: "relogin", Steps: []MacroStep{
		{Scheme: "http", Host: host, Raw: fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host),
			Extract: []Extractor{{Name: "csrf", Source: "body", Expr: `value="([^"]+)"`}}},
	}}})
	e.SetRules([]SessionRule{{Enabled: true, Host: host, Macro: "relogin", ReloginWhen: "Please log in"}})

	// Non-matching response: no relogin.
	if name := e.maybeRelogin(host, "HTTP/1.1 200 OK\r\n\r\nwelcome"); name != "" {
		t.Fatalf("unexpected relogin %q", name)
	}
	if _, ok := e.vars.Get("csrf"); ok {
		t.Fatal("csrf should not be set yet")
	}
	// Matching response triggers the macro, which sets csrf.
	if name := e.maybeRelogin(host, "HTTP/1.1 403 Forbidden\r\n\r\nPlease log in again"); name != "relogin" {
		t.Fatalf("relogin name = %q, want relogin", name)
	}
	if v, _ := e.vars.Get("csrf"); v != "FRESH" {
		t.Fatalf("csrf after relogin = %q, want FRESH", v)
	}
}
