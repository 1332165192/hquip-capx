package collect

import "testing"

func top1(c *Collector, cat string) string {
	t := c.Top(cat, 1)
	if len(t) == 0 {
		return ""
	}
	return t[0].Value
}

func has(c *Collector, cat, val string) bool {
	for _, it := range c.Top(cat, 0) {
		if it.Value == val {
			return true
		}
	}
	return false
}

func TestCollectQueryAndPath(t *testing.T) {
	c := New()
	c.Add(Msg{Method: "GET", URL: "https://x.com/api/v1/users.json?id=5&name=bob"})
	if !has(c, CatParam, "id") || !has(c, CatParam, "name") {
		t.Fatal("expected id/name params")
	}
	if !has(c, CatValue, "5") || !has(c, CatValue, "bob") {
		t.Fatal("expected values 5/bob")
	}
	if !has(c, CatPath, "api") || !has(c, CatPath, "v1") {
		t.Fatal("expected path segments api/v1")
	}
	if !has(c, CatFile, "users.json") {
		t.Fatal("expected file users.json")
	}
	if !has(c, CatFullPath, "/api/v1/users.json") {
		t.Fatal("expected full path")
	}
	if !has(c, CatEndpoint, "users.json") {
		t.Fatal("expected endpoint")
	}
}

func TestCollectJSONBody(t *testing.T) {
	c := New()
	c.Add(Msg{Method: "POST", URL: "https://x.com/login", ContentType: "application/json",
		ReqBody: `{"username":"admin","nested":{"token":"abc"},"list":["x"]}`})
	for _, p := range []string{"username", "nested", "token", "list"} {
		if !has(c, CatParam, p) {
			t.Errorf("expected JSON param %q", p)
		}
	}
	if !has(c, CatValue, "admin") || !has(c, CatValue, "abc") {
		t.Error("expected JSON scalar values")
	}
}

func TestCollectFormAndCookie(t *testing.T) {
	c := New()
	c.Add(Msg{Method: "POST", URL: "https://x.com/f", ContentType: "application/x-www-form-urlencoded",
		ReqBody: "user=alice&pass=secret", ReqHeaders: map[string]string{"Cookie": "sid=xyz; theme=dark"}})
	if !has(c, CatParam, "user") || !has(c, CatParam, "pass") {
		t.Error("expected form params")
	}
	if !has(c, CatCookie, "sid") || !has(c, CatCookie, "theme") {
		t.Error("expected cookies")
	}
}

func TestCollectFrequencyRanking(t *testing.T) {
	c := New()
	for i := 0; i < 3; i++ {
		c.Add(Msg{URL: "https://x.com/a?id=1"})
	}
	c.Add(Msg{URL: "https://x.com/a?page=1"})
	// "id" appears 3x, "page" 1x => id ranks first.
	if top1(c, CatParam) != "id" {
		t.Fatalf("top param = %q, want id", top1(c, CatParam))
	}
	if c.Categories()[CatParam] != 2 {
		t.Fatalf("unique params = %d, want 2", c.Categories()[CatParam])
	}
}
