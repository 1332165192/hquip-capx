package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/proxy"
)

func sampleTx() *model.HTTPTx {
	return &model.HTTPTx{
		ID:     7,
		TS:     time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Scheme: "https",
		Method: "POST",
		Host:   "api.example.com",
		Path:   "/v1/login?next=/home",
		URL:    "https://api.example.com/v1/login?next=/home",
		Status: 200,
		Proto:  "HTTP/2.0",
		MIME:   "application/json",
		ReqHdr: map[string]string{"Content-Type": "application/json", "Host": "api.example.com"},
		ReqRaw: "POST /v1/login?next=/home HTTP/1.1\r\nHost: api.example.com\r\n" +
			"Content-Type: application/json\r\nContent-Length: 19\r\n\r\n{\"u\":\"a\",\"p\":\"b\"}",
		RespRaw: "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}",
	}
}

func TestHARRoundTrip(t *testing.T) {
	b, err := HAR([]*model.HTTPTx{sampleTx()})
	if err != nil {
		t.Fatalf("HAR: %v", err)
	}
	var doc har
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("HAR is not valid json: %v", err)
	}
	if doc.Log.Version != "1.2" || len(doc.Log.Entries) != 1 {
		t.Fatalf("unexpected log: %+v", doc.Log)
	}
	e := doc.Log.Entries[0]
	if e.Request.Method != "POST" || e.Request.URL != "https://api.example.com/v1/login?next=/home" {
		t.Fatalf("request not mapped: %+v", e.Request)
	}
	if e.Request.HTTPVersion != "HTTP/1.1" {
		t.Fatalf("request httpVersion = %q", e.Request.HTTPVersion)
	}
	if e.Request.PostData == nil || e.Request.PostData.Text != `{"u":"a","p":"b"}` {
		t.Fatalf("post data not mapped: %+v", e.Request.PostData)
	}
	if got := headerValue(e.Request.Headers, "Content-Type"); got != "application/json" {
		t.Fatalf("request header Content-Type = %q", got)
	}
	if len(e.Request.QueryString) != 1 || e.Request.QueryString[0].Name != "next" {
		t.Fatalf("query string not parsed: %+v", e.Request.QueryString)
	}
	if e.Response.Status != 200 || e.Response.StatusText != "OK" || e.Response.HTTPVersion != "HTTP/2.0" {
		t.Fatalf("response not mapped: %+v", e.Response)
	}
	if e.Response.Content.Text != `{"ok":true}` || e.Response.Content.MimeType != "application/json" {
		t.Fatalf("response content not mapped: %+v", e.Response.Content)
	}
	if e.StartedDateTime != "2024-01-02T03:04:05Z" {
		t.Fatalf("startedDateTime = %q", e.StartedDateTime)
	}
}

func TestHARBinaryBodyBase64(t *testing.T) {
	tx := &model.HTTPTx{
		URL: "https://x/y", Status: 200,
		RespRaw: "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n\xff\xfe\x00binary",
	}
	b, err := HAR([]*model.HTTPTx{tx})
	if err != nil {
		t.Fatal(err)
	}
	var doc har
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	c := doc.Log.Entries[0].Response.Content
	if c.Encoding != "base64" {
		t.Fatalf("expected base64 encoding for binary body, got %q (text=%q)", c.Encoding, c.Text)
	}
}

func TestCurl(t *testing.T) {
	got := Curl(sampleTx())
	// Host + Content-Length are dropped; method, url, content-type and body kept.
	for _, want := range []string{
		"curl -i -X 'POST'",
		"'https://api.example.com/v1/login?next=/home'",
		"-H 'Content-Type: application/json'",
		`--data-raw '{"u":"a","p":"b"}'`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("curl output missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "-H 'Host:") || strings.Contains(got, "Content-Length") {
		t.Fatalf("curl should drop Host/Content-Length headers:\n%s", got)
	}
}

func TestCurlQuoteEscaping(t *testing.T) {
	tx := &model.HTTPTx{
		Method: "GET", URL: "https://x/'; rm -rf /",
		ReqRaw: "GET / HTTP/1.1\r\n\r\n",
	}
	got := Curl(tx)
	if !strings.Contains(got, `'https://x/'\''; rm -rf /'`) {
		t.Fatalf("single quote not escaped POSIX-style:\n%s", got)
	}
}

func TestIntruderCSV(t *testing.T) {
	results := []proxy.IntruderResult{
		{Index: 0, Payloads: []string{"admin", "123"}, Status: 200, Length: 12, Millis: 5, Matched: true, Extracts: []string{"tokenA", "tokenB"}},
		{Index: 1, Payloads: []string{"x,y"}, Status: 403, Length: 0, Millis: 9, Error: "timeout"},
	}
	b, err := IntruderCSV(results)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected header + 2 rows, got %d:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "index,payloads,status,length,millis,matched,extracts,error") {
		t.Fatalf("bad header: %q", lines[0])
	}
	if !strings.Contains(lines[1], "admin | 123") || !strings.Contains(lines[1], "tokenA | tokenB") || !strings.Contains(lines[1], "true") {
		t.Fatalf("row 0 wrong: %q", lines[1])
	}
	// A payload containing a comma must be CSV-quoted, not split into columns.
	if !strings.Contains(lines[2], `"x,y"`) || !strings.Contains(lines[2], "timeout") {
		t.Fatalf("row 1 wrong (comma not quoted?): %q", lines[2])
	}
}
