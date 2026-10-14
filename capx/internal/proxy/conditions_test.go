package proxy

import "testing"

func TestCondEmptySetInterceptsAll(t *testing.T) {
	c := newCondSet()
	if !c.shouldIntercept("GET", "x.com", "/a", "") {
		t.Fatal("empty rule set must intercept by default")
	}
}

func TestCondAutoForwardStaticAssets(t *testing.T) {
	c := newCondSet()
	c.set([]InterceptCond{
		{Enabled: true, Action: "forward", FileExt: "js,css,png,woff2"},
	})
	if c.shouldIntercept("GET", "x.com", "/app.js", "") {
		t.Fatal(".js should be auto-forwarded (not intercepted)")
	}
	if c.shouldIntercept("GET", "x.com", "/style.CSS", "") {
		t.Fatal(".CSS should be auto-forwarded (case-insensitive)")
	}
	if !c.shouldIntercept("GET", "x.com", "/api/users", "") {
		t.Fatal("non-static path should still be intercepted")
	}
}

func TestCondInterceptOnlyMatching(t *testing.T) {
	c := newCondSet()
	// Intercept only POSTs to api.example with a query string; forward the rest.
	c.set([]InterceptCond{
		{Enabled: true, Action: "intercept", Host: "api.example", Method: "POST", HasParams: "yes"},
		{Enabled: true, Action: "forward"}, // catch-all
	})
	if !c.shouldIntercept("POST", "api.example.com:443", "/login", "next=1") {
		t.Fatal("matching POST with params must be intercepted")
	}
	if c.shouldIntercept("GET", "api.example.com", "/login", "next=1") {
		t.Fatal("GET should fall through to forward")
	}
	if c.shouldIntercept("POST", "api.example.com", "/login", "") {
		t.Fatal("POST without params should fall through to forward")
	}
	if c.shouldIntercept("POST", "other.com", "/login", "x=1") {
		t.Fatal("different host should fall through to forward")
	}
}

func TestCondDisabledRuleSkipped(t *testing.T) {
	c := newCondSet()
	c.set([]InterceptCond{
		{Enabled: false, Action: "forward"}, // disabled catch-all
	})
	if !c.shouldIntercept("GET", "x.com", "/a.js", "") {
		t.Fatal("disabled rule must be ignored, default intercept applies")
	}
}

func TestCondHasParamsNo(t *testing.T) {
	c := newCondSet()
	c.set([]InterceptCond{
		{Enabled: true, Action: "intercept", HasParams: "no"},
		{Enabled: true, Action: "forward"},
	})
	if !c.shouldIntercept("GET", "x.com", "/a", "") {
		t.Fatal("no-params request should be intercepted")
	}
	if c.shouldIntercept("GET", "x.com", "/a", "q=1") {
		t.Fatal("request with params should be forwarded")
	}
}
