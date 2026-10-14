package proxy

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
)

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func zlibBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zlib.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func brBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	w := brotli.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestDecompressRoundTrip(t *testing.T) {
	const plain = "the quick brown fox jumps over the lazy dog"
	cases := []struct {
		enc  string
		data []byte
	}{
		{"gzip", gzipBytes(t, plain)},
		{"deflate", zlibBytes(t, plain)},
		{"br", brBytes(t, plain)},
	}
	for _, c := range cases {
		got, ok := decompress(c.enc, c.data)
		if !ok {
			t.Fatalf("%s: decompress failed", c.enc)
		}
		if string(got) != plain {
			t.Fatalf("%s: got %q want %q", c.enc, got, plain)
		}
		// compress then decompress should reproduce the input.
		enc, ok := compress(c.enc, []byte(plain))
		if !ok {
			t.Fatalf("%s: compress failed", c.enc)
		}
		back, ok := decompress(c.enc, enc)
		if !ok || string(back) != plain {
			t.Fatalf("%s: round-trip got %q ok=%v", c.enc, back, ok)
		}
	}
}

func TestDecodableEncoding(t *testing.T) {
	h := http.Header{}
	if decodableEncoding(h) != "" {
		t.Fatal("identity should be undecodable")
	}
	h.Set("Content-Encoding", "GZIP")
	if decodableEncoding(h) != "gzip" {
		t.Fatal("gzip not detected (case-insensitive)")
	}
	h.Set("Content-Encoding", "br, gzip")
	if decodableEncoding(h) != "" {
		t.Fatal("encoding chains must be left untouched")
	}
}

// A gzip response body should be transparently decompressed for matching and
// recompressed on the way out so the client still gets valid gzip.
func TestResponseGzipBodyReplace(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "response", Where: "body", Match: "secret", Replace: "REDACTED"})

	enc := gzipBytes(t, "a secret value")
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(enc))}
	resp.Header.Set("Content-Encoding", "gzip")
	resp.Header.Set("Content-Length", strconv.Itoa(len(enc)))

	rs.applyResponse(resp)

	out, _ := io.ReadAll(resp.Body)
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("Content-Encoding dropped: %q", resp.Header.Get("Content-Encoding"))
	}
	dec, ok := decompress("gzip", out)
	if !ok {
		t.Fatalf("output not valid gzip")
	}
	if string(dec) != "a REDACTED value" {
		t.Fatalf("decoded body = %q", dec)
	}
	if resp.Header.Get("Content-Length") != strconv.Itoa(len(out)) {
		t.Fatalf("content-length %q != %d", resp.Header.Get("Content-Length"), len(out))
	}
}

// When no body rule matches, the original compressed bytes must be re-emitted
// unchanged (no needless re-encoding).
func TestResponseGzipBodyUnmodified(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "response", Where: "body", Match: "nope", Replace: "x"})

	enc := gzipBytes(t, "hello world")
	resp := &http.Response{Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(enc))}
	resp.Header.Set("Content-Encoding", "gzip")

	rs.applyResponse(resp)
	out, _ := io.ReadAll(resp.Body)
	if !bytes.Equal(out, enc) {
		t.Fatalf("unmodified gzip body should be byte-identical")
	}
}

func TestRequestGzipBodyReplace(t *testing.T) {
	rs := newRuleSet()
	mustAdd(t, rs, &Rule{Enabled: true, Target: "request", Where: "body", Match: "foo", Replace: "bar"})

	enc := gzipBytes(t, "foo foo")
	req, _ := http.NewRequest("POST", "http://x/", bytes.NewReader(enc))
	req.Header.Set("Content-Encoding", "gzip")

	if blocked, err := rs.applyRequest(req); err != nil || blocked {
		t.Fatal("unexpected block")
	}
	out, _ := io.ReadAll(req.Body)
	dec, ok := decompress("gzip", out)
	if !ok || string(dec) != "bar bar" {
		t.Fatalf("decoded req body = %q ok=%v", dec, ok)
	}
}

// dumpResponse should render a decompressed, editable body and parseEditedResponse
// should recompress an edit back to the wire encoding.
func TestInterceptGzipResponseEditRoundTrip(t *testing.T) {
	enc := gzipBytes(t, "original body")
	resp := &http.Response{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewReader(enc)),
	}
	resp.Header.Set("Content-Encoding", "gzip")
	resp.Header.Set("Content-Length", strconv.Itoa(len(enc)))

	raw, _, err := dumpResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "original body") {
		t.Fatalf("dump did not decompress body:\n%s", raw)
	}
	// The shown Content-Length must match the decompressed length so the raw
	// text parses cleanly.
	if !strings.Contains(raw, "Content-Length: "+strconv.Itoa(len("original body"))) {
		t.Fatalf("dump Content-Length not adjusted:\n%s", raw)
	}

	edited := strings.Replace(raw, "original body", "edited body!!", 1)
	if !parseEditedResponse(edited, resp) {
		t.Fatal("parseEditedResponse failed")
	}
	out, _ := io.ReadAll(resp.Body)
	dec, ok := decompress("gzip", out)
	if !ok || string(dec) != "edited body!!" {
		t.Fatalf("edited decoded body = %q ok=%v", dec, ok)
	}
	if resp.Header.Get("Content-Length") != strconv.Itoa(len(out)) {
		t.Fatalf("content-length %q != %d", resp.Header.Get("Content-Length"), len(out))
	}
}
