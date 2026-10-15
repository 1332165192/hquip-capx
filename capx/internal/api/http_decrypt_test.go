package api

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

func TestRecordedBusinessDecryptionUnwrapsGzipJSONAndAuthenticatesGCM(t *testing.T) {
	key, iv := "1234567890abcdef", "123456789012"
	t.Setenv("CAPX_APP_FIXTURE_KEY", key)
	plain := `{"name":"小米","fixture":true}`
	ciphertext, err := cryptoSymmetric(cryptoCodecReq{Algorithm: "aes", Op: "encrypt", Mode: "gcm", Input: plain, InputEnc: "utf8", Key: key, IV: iv})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"data": map[string]any{"ciphertext": base64.StdEncoding.EncodeToString(ciphertext)}})
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	writer.Write(payload)
	writer.Close()
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", compressed.Len()) + compressed.String()
	st := store.New(10)
	st.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "GET", Host: "fixture.test", Path: "/encrypted", Status: 200, RespRaw: raw, Decrypted: true})
	id := st.SnapshotHTTPTx()[0].ID
	s := &Server{st: st}
	request := func(keyEnv string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"algorithm": "aes", "mode": "gcm", "key_env": keyEnv, "iv": iv, "side": "response", "json_pointer": "/data/ciphertext"})
		r := httptest.NewRequest(http.MethodPost, "/api/http/1/decrypt", bytes.NewReader(body))
		r.SetPathValue("id", strconv.FormatUint(id, 10))
		w := httptest.NewRecorder()
		s.httpDecrypt(w, r)
		return w
	}
	w := request("CAPX_APP_FIXTURE_KEY")
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var result struct {
		Output    string `json:"output"`
		Integrity bool   `json:"integrity_verified"`
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Output != plain || !result.Integrity {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), key) {
		t.Fatal("decryption response leaked key")
	}
	stored, _ := st.GetHTTPTx(id)
	if stored.RespRaw != raw {
		t.Fatal("original captured response was modified")
	}
	t.Setenv("CAPX_APP_FIXTURE_KEY", "abcdefghijklmnop")
	w = request("CAPX_APP_FIXTURE_KEY")
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "小米") {
		t.Fatal("invalid GCM authentication produced plaintext", w.Code, w.Body.String())
	}
}

func TestBusinessDecryptRejectsTruncatedCapturesAndUnscopedSecrets(t *testing.T) {
	st := store.New(10)
	st.AddHTTPTx(&model.HTTPTx{Method: "GET", Host: "fixture.test", Path: "/truncated", RespRaw: "partial", BodyTruncated: true})
	id := st.SnapshotHTTPTx()[0].ID
	r := httptest.NewRequest(http.MethodPost, "/api/http/1/decrypt", strings.NewReader(`{}`))
	r.SetPathValue("id", strconv.FormatUint(id, 10))
	w := httptest.NewRecorder()
	(&Server{st: st}).httpDecrypt(w, r)
	if w.Code != http.StatusConflict {
		t.Fatal("truncated ciphertext was accepted", w.Code)
	}
	t.Setenv("UNRELATED_SECRET", "fixture-private-value")
	if _, err := businessSecret("", "UNRELATED_SECRET"); err == nil {
		t.Fatal("read an environment secret outside CAPX_APP_ scope")
	}
	if _, err := businessSecret("direct", "CAPX_APP_FIXTURE"); err == nil {
		t.Fatal("ambiguous key sources accepted")
	}
}

func TestCiphertextJSONPointerEscapesAndArrayIndices(t *testing.T) {
	body := []byte(`{"items":[{"cipher/text":"value","~key":"second"}]}`)
	if value, err := ciphertextAt(body, "/items/0/cipher~1text"); err != nil || value != "value" {
		t.Fatal(value, err)
	}
	if value, err := ciphertextAt(body, "/items/0/~0key"); err != nil || value != "second" {
		t.Fatal(value, err)
	}
	for _, pointer := range []string{"items/0", "/items/01", "/items/+0", "/items/-1", "/items/1", "/items/0/cipher~2text", "/items/0"} {
		if _, err := ciphertextAt(body, pointer); err == nil {
			t.Fatal("invalid pointer accepted", pointer)
		}
	}
}
