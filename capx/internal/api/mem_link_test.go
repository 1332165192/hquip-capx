package api

import (
	"testing"

	"github.com/hquip/capx/internal/model"
)

func TestExtractNeedles(t *testing.T) {
	got := extractNeedles("xxhttps://api.example.com/v1/login?x=1 extra Bearer abcdefghijklmnop", "")
	if len(got) == 0 {
		t.Fatal("expected needles")
	}
	foundURL := false
	for _, n := range got {
		if n == "https://api.example.com/v1/login?x=1" {
			foundURL = true
		}
	}
	if !foundURL {
		t.Fatalf("missing url needle: %v", got)
	}
}

func TestScoreHTTPMatch(t *testing.T) {
	tx := &model.HTTPTx{
		URL:    "https://api.example.com/v1/login",
		Host:   "api.example.com",
		ReqRaw: "POST /v1/login HTTP/1.1\r\nAuthorization: Bearer abcdefghijklmnop\r\n\r\n",
	}
	sc, where := scoreHTTPMatch(tx, "https://api.example.com/v1/login")
	if sc < 80 || where != "url" {
		t.Fatalf("url score=%d where=%s", sc, where)
	}
	sc, where = scoreHTTPMatch(tx, "Bearer abcdefghijklmnop")
	if sc < 70 || where != "req" {
		t.Fatalf("req score=%d where=%s", sc, where)
	}
}
