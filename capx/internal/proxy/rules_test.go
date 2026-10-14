package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func mustAdd(t *testing.T, rs *RuleSet, r *Rule) *Rule {
	t.Helper()
	got, err := rs.Add(r)
	if err != nil {
		t.Fatalf("Add(%+v): %v", r, err)
	}
	return got
}

// MaR-style conditional rule: replace only fires when the condition holds.
func TestConditionalReplace(t *testing.T) {
	rs := newRuleSet()
	// Replace "secret" with "REDACTED" only when the URL contains "/admin".
	mustAdd(t, rs, &Rule{Enabled: true, Target: "response", Where: "body",
		Match: "secret", Replace: "REDACTED", Action: "replace",
		CondWhere: "any", CondMatch: "ADMIN-MARKER"})

	// Condition NOT met (marker absent) => no replacement.
	resp := &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("the secret"))}
	rs.applyResponse(resp)
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "the secret" {
		t.Fatalf("cond not met should not replace, got %q", b)
	}

	// Condition met (marker present in body) => replacement applies.
	resp = &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ADMIN-MARKER the secret"))}
	rs.applyResponse(resp)
	b, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "REDACTED") {
		t.Fatalf("cond met should replace, got %q", b)
	}
}

// Negated condition ("does not match") fires when theker is absent.
func TestConditionalNegate(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "request", Where: "header", Header: "X-Test",
		Match: ".*", Replace: "tagged", Action: "replace",
		CondWhere: "header", CondHeader: "Authorization", CondMatch: "Bearer", CondNegate: true})

	// No Authorization => negated condition true => header rewritten.
	req, _ := http.NewRequest("GET", "http://x/", nil)
	req.Header.Set("X-Test", "orig")
	rs.applyRequest(req)
	if req.Header.Get("X-Test") != "tagged" {
		t.Fatalf("negate(no auth) should rewrite, got %q", req.Header.Get("X-Test"))
	}

	// With Authorization: Bearer => condition matches => negate false => skip.
	req2, _ := http.NewRequest("GET", "http://x/", nil)
	req2.Header.Set("X-Test", "orig")
	req2.Header.Set("Authorization", "Bearer abc")
	rs.applyRequest(req2)
	if req2.Header.Get("X-Test") != "orig" {
		t.Fatalf("negate(with auth) should skip, got %q", req2.Header.Get("X-Test"))
	}
}

func TestRequestBodyReplace(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "request", Where: "body", Match: "foo", Replace: "bar", Action: "replace"})

	req, _ := http.NewRequest("POST", "http://x/", strings.NewReader("xx foo yy foo"))
	if blocked, err := rs.applyRequest(req); err != nil || blocked {
		t.Fatal("unexpected block")
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "xx bar yy bar" {
		t.Fatalf("body = %q", body)
	}
	if req.ContentLength != int64(len("xx bar yy bar")) {
		t.Fatalf("content-length = %d", req.ContentLength)
	}
}

func TestRequestHeaderReplaceAndRegex(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "request", Where: "header", Header: "User-Agent", Match: "^.*$", Replace: "capx/1.0"})

	req, _ := http.NewRequest("GET", "http://x/", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	rs.applyRequest(req)
	if got := req.Header.Get("User-Agent"); got != "capx/1.0" {
		t.Fatalf("ua = %q", got)
	}
}

func TestRequestURLReplace(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "request", Where: "url", Match: "/old/", Replace: "/new/"})

	req, _ := http.NewRequest("GET", "http://x/old/page?q=1", nil)
	rs.applyRequest(req)
	if req.URL.Path != "/new/page" {
		t.Fatalf("path = %q", req.URL.Path)
	}
	if req.URL.RawQuery != "q=1" {
		t.Fatalf("query = %q", req.URL.RawQuery)
	}
}

func TestRequestBlock(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "request", Where: "url", Match: "/admin", Action: "block"})

	req, _ := http.NewRequest("GET", "http://x/admin/secret", nil)
	if blocked, err := rs.applyRequest(req); err != nil || !blocked {
		t.Fatal("expected block")
	}
}

func TestResponseBodyReplaceFixesLength(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "response", Where: "body", Match: "secret", Replace: "REDACTED"})

	resp := &http.Response{
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader("a secret value")),
	}
	resp.Header.Set("Content-Length", "14")
	rs.applyResponse(resp)
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "a REDACTED value" {
		t.Fatalf("body = %q", body)
	}
	if resp.Header.Get("Content-Length") != "16" {
		t.Fatalf("content-length = %q", resp.Header.Get("Content-Length"))
	}
}

func TestResponseStatusReplace(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "response", Where: "status", Match: "^200$", Replace: "404"})

	resp := &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("ok")),
	}
	rs.applyResponse(resp)
	if resp.StatusCode != 404 {
		t.Fatalf("status code = %d, want 404", resp.StatusCode)
	}
	if resp.Status != "404 Not Found" {
		t.Fatalf("status = %q, want %q", resp.Status, "404 Not Found")
	}
}

func TestResponseStatusReplaceIgnoresInvalid(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "response", Where: "status", Match: "200", Replace: "999999"})
	resp := &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{}, Body: io.NopCloser(strings.NewReader(""))}
	rs.applyResponse(resp)
	if resp.StatusCode != 200 {
		t.Fatalf("out-of-range replacement must be ignored, got %d", resp.StatusCode)
	}
}

func TestDisabledRuleSkipped(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: false, Target: "request", Where: "url", Match: "/x", Action: "block"})
	req, _ := http.NewRequest("GET", "http://x/x", nil)
	if blocked, err := rs.applyRequest(req); err != nil || blocked {
		t.Fatal("disabled rule should not block")
	}
}

func TestAddValidation(t *testing.T) {
	rs := newRuleSet()
	bad := []*Rule{
		{Target: "bogus", Where: "body", Match: "x"},
		{Target: "request", Where: "bogus", Match: "x"},
		{Target: "request", Where: "header", Match: "x"}, // missing header name
		{Target: "response", Where: "url", Match: "x"},   // url only for request
		{Target: "response", Where: "body", Match: "x", Action: "block"},
		{Target: "request", Where: "status", Match: "200"}, // status only for response
		{Target: "request", Where: "body", Match: "("},     // bad regexp
	}
	for i, r := range bad {
		if _, err := rs.Add(r); err == nil {
			t.Fatalf("case %d: expected error for %+v", i, r)
		}
	}
}

func TestDeleteRule(t *testing.T) {
	rs := newRuleSet()
	r := mustAdd(t, rs, &Rule{Enabled: true, Target: "request", Where: "url", Match: "/x"})
	if !rs.Delete(r.ID) {
		t.Fatal("delete should succeed")
	}
	if rs.Delete(r.ID) {
		t.Fatal("second delete should fail")
	}
}
