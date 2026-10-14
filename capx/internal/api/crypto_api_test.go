package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

func TestCryptoCodecAESCBCRoundTrip(t *testing.T) {
	ts := newTestServer(t)
	body := map[string]any{
		"algorithm":  "aes",
		"op":         "encrypt",
		"mode":       "CBC",
		"padding":    "pkcs7",
		"input":      "hello capx",
		"input_enc":  "utf8",
		"output_enc": "base64",
		"key":        "1234567890abcdef",
		"iv":         "abcdef1234567890",
	}
	code, raw := postJSON(t, ts.URL+"/api/crypto/codec", body)
	if code != http.StatusOK {
		t.Fatalf("encrypt = %d %s", code, raw)
	}
	var enc struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(raw, &enc); err != nil {
		t.Fatal(err)
	}
	body["op"] = "decrypt"
	body["input"] = enc.Output
	body["input_enc"] = "base64"
	body["output_enc"] = "utf8"
	code, raw = postJSON(t, ts.URL+"/api/crypto/codec", body)
	if code != http.StatusOK {
		t.Fatalf("decrypt = %d %s", code, raw)
	}
	if !bytes.Contains(raw, []byte(`"output":"hello capx"`)) {
		t.Fatalf("bad round trip: %s", raw)
	}
}

func TestCryptoDigest(t *testing.T) {
	ts := newTestServer(t)
	code, raw := postJSON(t, ts.URL+"/api/crypto/digest", map[string]any{
		"algorithm": "md5",
		"input":     "abc",
		"input_enc": "utf8",
	})
	if code != http.StatusOK {
		t.Fatalf("digest = %d %s", code, raw)
	}
	if !bytes.Contains(raw, []byte(`900150983cd24fb0d6963f7d28e17f72`)) {
		t.Fatalf("bad digest: %s", raw)
	}
}
