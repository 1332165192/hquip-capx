package api

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"hash"
	"io"
	"net/http"
	"strings"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/ripemd160"
)

type cryptoCodecReq struct {
	Algorithm string `json:"algorithm"`
	Op        string `json:"op"`
	Mode      string `json:"mode"`
	Padding   string `json:"padding"`
	Input     string `json:"input"`
	InputEnc  string `json:"input_enc"`
	OutputEnc string `json:"output_enc"`
	Key       string `json:"key"`
	IV        string `json:"iv"`
	AAD       string `json:"aad"`
	PublicKey string `json:"public_key"`
	PrivKey   string `json:"private_key"`
}

func (s *Server) cryptoCodec(w http.ResponseWriter, r *http.Request) {
	var req cryptoCodecReq
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	req.Algorithm = strings.ToLower(strings.TrimSpace(req.Algorithm))
	req.Op = strings.ToLower(strings.TrimSpace(req.Op))
	if req.Op == "" {
		req.Op = "encrypt"
	}
	if req.OutputEnc == "" {
		req.OutputEnc = "base64"
		if req.Op == "decrypt" {
			req.OutputEnc = "utf8"
		}
	}
	var (
		out []byte
		err error
	)
	switch req.Algorithm {
	case "aes", "des", "3des", "tripledes", "rc4":
		out, err = cryptoSymmetric(req)
	case "rsa":
		out, err = cryptoRSA(req)
	default:
		writeErr(w, http.StatusBadRequest, "unsupported algorithm")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"output": formatCryptoBytes(out, req.OutputEnc),
		"bytes":  len(out),
	})
}

func (s *Server) cryptoDigest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Algorithm string `json:"algorithm"`
		Input     string `json:"input"`
		InputEnc  string `json:"input_enc"`
		Key       string `json:"key"`
		KeyEnc    string `json:"key_enc"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json")
		return
	}
	data, err := parseCryptoBytes(req.Input, req.InputEnc)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	algo := strings.ToLower(strings.TrimSpace(req.Algorithm))
	mac := false
	if strings.HasPrefix(algo, "hmac-") {
		mac = true
		algo = strings.TrimPrefix(algo, "hmac-")
	}
	h, err := hashByName(algo)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if mac {
		key, err := parseCryptoBytes(req.Key, firstNonEmpty(req.KeyEnc, "auto"))
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		m := hmac.New(h, key)
		_, _ = m.Write(data)
		writeJSON(w, http.StatusOK, map[string]any{"hex": hex.EncodeToString(m.Sum(nil))})
		return
	}
	hh := h()
	_, _ = hh.Write(data)
	writeJSON(w, http.StatusOK, map[string]any{"hex": hex.EncodeToString(hh.Sum(nil))})
}

func hashByName(name string) (func() hash.Hash, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "md4":
		return md4.New, nil
	case "md5":
		return md5.New, nil
	case "sha1", "sha-1":
		return sha1.New, nil
	case "sha224", "sha-224":
		return sha256.New224, nil
	case "sha256", "sha-256":
		return sha256.New, nil
	case "sha384", "sha-384":
		return sha512.New384, nil
	case "sha512", "sha-512":
		return sha512.New, nil
	case "ripemd160", "ripemd-160":
		return ripemd160.New, nil
	}
	return nil, errCrypto("unsupported hash")
}

func cryptoSymmetric(req cryptoCodecReq) ([]byte, error) {
	algo := req.Algorithm
	if algo == "tripledes" {
		algo = "3des"
	}
	op := req.Op
	inputEnc := req.InputEnc
	if inputEnc == "" {
		inputEnc = "utf8"
		if op == "decrypt" {
			inputEnc = "base64"
		}
	}
	outputEnc := req.OutputEnc
	if outputEnc == "" {
		outputEnc = "base64"
		if op == "decrypt" {
			outputEnc = "utf8"
		}
	}
	req.OutputEnc = outputEnc
	in, err := parseCryptoBytes(req.Input, inputEnc)
	if err != nil {
		return nil, err
	}
	if algo == "rc4" {
		key, err := parseAutoBytesFor(req.Key, func(n int) bool { return n >= 1 && n <= 256 })
		if err != nil {
			return nil, err
		}
		c, err := newRC4(key)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(in))
		c.XORKeyStream(out, in)
		return out, nil
	}
	key, err := parseSymmetricKey(algo, req.Key)
	if err != nil {
		return nil, err
	}
	block, err := blockByAlgo(algo, key)
	if err != nil {
		return nil, err
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = "cbc"
	}
	padding := strings.ToLower(strings.TrimSpace(req.Padding))
	if padding == "" {
		padding = "pkcs7"
	}
	iv, err := parseIV(req.IV, block.BlockSize(), mode)
	if err != nil {
		return nil, err
	}
	if mode != "ecb" && mode != "gcm" && len(iv) != block.BlockSize() {
		return nil, errCrypto("iv length must equal block size")
	}
	switch mode {
	case "ecb":
		return cryptECB(block, op, in, padding)
	case "cbc":
		return cryptCBC(block, op, in, iv, padding)
	case "cfb":
		return cryptStream(block, op, in, iv, "cfb")
	case "ofb":
		return cryptStream(block, op, in, iv, "ofb")
	case "ctr":
		return cryptStream(block, op, in, iv, "ctr")
	case "gcm":
		if algo != "aes" {
			return nil, errCrypto("gcm only supports aes")
		}
		return cryptGCM(block, op, in, iv, []byte(req.AAD))
	default:
		return nil, errCrypto("unsupported mode")
	}
}

func parseSymmetricKey(algo, raw string) ([]byte, error) {
	switch algo {
	case "aes":
		return parseAutoBytesFor(raw, func(n int) bool { return n == 16 || n == 24 || n == 32 })
	case "des":
		return parseAutoBytesFor(raw, func(n int) bool { return n == 8 })
	case "3des":
		return parseAutoBytesFor(raw, func(n int) bool { return n == 24 })
	}
	return parseCryptoBytes(raw, "auto")
}

func parseIV(raw string, blockSize int, mode string) ([]byte, error) {
	if strings.EqualFold(mode, "ecb") {
		return nil, nil
	}
	if strings.EqualFold(mode, "gcm") {
		return parseAutoBytesFor(raw, func(n int) bool { return n == 12 || n == 16 })
	}
	return parseAutoBytesFor(raw, func(n int) bool { return n == blockSize })
}

func parseAutoBytesFor(raw string, validLen func(int) bool) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		if validLen(0) {
			return nil, nil
		}
		return nil, errCrypto("value is empty or length is invalid")
	}
	if b, ok := tryHex(raw); ok && validLen(len(b)) {
		return b, nil
	}
	if b, ok := tryBase64(raw); ok && validLen(len(b)) {
		return b, nil
	}
	b := []byte(raw)
	if validLen(len(b)) {
		return b, nil
	}
	return nil, errCrypto("decoded length is invalid")
}

func blockByAlgo(algo string, key []byte) (cipher.Block, error) {
	switch algo {
	case "aes":
		return aes.NewCipher(key)
	case "des":
		return des.NewCipher(key)
	case "3des":
		return des.NewTripleDESCipher(key)
	}
	return nil, errCrypto("unsupported block algorithm")
}

func cryptECB(block cipher.Block, op string, in []byte, padding string) ([]byte, error) {
	bs := block.BlockSize()
	data := in
	if op == "encrypt" {
		var err error
		data, err = applyPadding(data, bs, padding)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(data))
		for i := 0; i < len(data); i += bs {
			block.Encrypt(out[i:i+bs], data[i:i+bs])
		}
		return out, nil
	}
	if len(data)%bs != 0 {
		return nil, errCrypto("ciphertext length must be block size multiple")
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		block.Decrypt(out[i:i+bs], data[i:i+bs])
	}
	return removePadding(out, bs, padding)
}

func cryptCBC(block cipher.Block, op string, in, iv []byte, padding string) ([]byte, error) {
	bs := block.BlockSize()
	if op == "encrypt" {
		data, err := applyPadding(in, bs, padding)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(data))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
		return out, nil
	}
	if len(in)%bs != 0 {
		return nil, errCrypto("ciphertext length must be block size multiple")
	}
	out := make([]byte, len(in))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, in)
	return removePadding(out, bs, padding)
}

func cryptStream(block cipher.Block, op string, in, iv []byte, mode string) ([]byte, error) {
	out := make([]byte, len(in))
	var s cipher.Stream
	switch mode {
	case "cfb":
		if op == "encrypt" {
			s = cipher.NewCFBEncrypter(block, iv)
		} else {
			s = cipher.NewCFBDecrypter(block, iv)
		}
	case "ofb":
		s = cipher.NewOFB(block, iv)
	case "ctr":
		s = cipher.NewCTR(block, iv)
	default:
		return nil, errCrypto("unsupported stream mode")
	}
	s.XORKeyStream(out, in)
	return out, nil
}

func cryptGCM(block cipher.Block, op string, in, iv, aad []byte) ([]byte, error) {
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(iv) == 0 {
		return nil, errCrypto("gcm nonce/iv is required")
	}
	if op == "encrypt" {
		return g.Seal(nil, iv, in, aad), nil
	}
	return g.Open(nil, iv, in, aad)
}

func applyPadding(in []byte, bs int, padding string) ([]byte, error) {
	switch padding {
	case "pkcs7", "pkcs5", "":
		pad := bs - len(in)%bs
		if pad == 0 {
			pad = bs
		}
		return append(append([]byte(nil), in...), bytes.Repeat([]byte{byte(pad)}, pad)...), nil
	case "zero":
		pad := bs - len(in)%bs
		if pad == bs {
			return append([]byte(nil), in...), nil
		}
		return append(append([]byte(nil), in...), bytes.Repeat([]byte{0}, pad)...), nil
	case "none", "nopadding":
		if len(in)%bs != 0 {
			return nil, errCrypto("NoPadding requires block-size multiple input")
		}
		return append([]byte(nil), in...), nil
	}
	return nil, errCrypto("unsupported padding")
}

func removePadding(in []byte, bs int, padding string) ([]byte, error) {
	switch padding {
	case "pkcs7", "pkcs5", "":
		if len(in) == 0 {
			return in, nil
		}
		pad := int(in[len(in)-1])
		if pad <= 0 || pad > bs || pad > len(in) {
			return nil, errCrypto("invalid pkcs7 padding")
		}
		for _, b := range in[len(in)-pad:] {
			if int(b) != pad {
				return nil, errCrypto("invalid pkcs7 padding")
			}
		}
		return in[:len(in)-pad], nil
	case "zero":
		return bytes.TrimRight(in, "\x00"), nil
	case "none", "nopadding":
		return in, nil
	}
	return nil, errCrypto("unsupported padding")
}

func cryptoRSA(req cryptoCodecReq) ([]byte, error) {
	in, err := parseCryptoBytes(req.Input, firstNonEmpty(req.InputEnc, "utf8"))
	if err != nil {
		return nil, err
	}
	padding := strings.ToLower(strings.TrimSpace(req.Padding))
	if padding == "" {
		padding = "pkcs1v15"
	}
	if req.Op == "encrypt" {
		pub, err := parseRSAPublicKey(req.PublicKey)
		if err != nil {
			return nil, err
		}
		switch padding {
		case "pkcs1", "pkcs1v15":
			return rsa.EncryptPKCS1v15(rand.Reader, pub, in)
		case "oaep", "oaep-sha1":
			return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, in, nil)
		case "oaep-sha256":
			return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, in, nil)
		}
		return nil, errCrypto("unsupported rsa padding")
	}
	priv, err := parseRSAPrivateKey(req.PrivKey)
	if err != nil {
		return nil, err
	}
	switch padding {
	case "pkcs1", "pkcs1v15":
		return rsa.DecryptPKCS1v15(rand.Reader, priv, in)
	case "oaep", "oaep-sha1":
		return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, in, nil)
	case "oaep-sha256":
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, in, nil)
	}
	return nil, errCrypto("unsupported rsa padding")
}

func parseRSAPublicKey(raw string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil {
		return nil, errCrypto("bad public key pem")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rpub, ok := pub.(*rsa.PublicKey); ok {
			return rpub, nil
		}
	}
	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	return nil, errCrypto("unsupported rsa public key")
}

func parseRSAPrivateKey(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(raw)))
	if block == nil {
		return nil, errCrypto("bad private key pem")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rkey, ok := key.(*rsa.PrivateKey); ok {
			return rkey, nil
		}
	}
	return nil, errCrypto("unsupported rsa private key")
}

func parseCryptoBytes(s, enc string) ([]byte, error) {
	raw := strings.TrimSpace(s)
	enc = strings.ToLower(strings.TrimSpace(enc))
	if enc == "" || enc == "auto" {
		if b, ok := tryHex(raw); ok {
			return b, nil
		}
		if b, ok := tryBase64(raw); ok {
			return b, nil
		}
		return []byte(s), nil
	}
	switch enc {
	case "utf8", "text", "string":
		return []byte(s), nil
	case "hex":
		b, err := hex.DecodeString(strings.ReplaceAll(raw, " ", ""))
		if err != nil {
			return nil, err
		}
		return b, nil
	case "base64", "b64":
		return base64.StdEncoding.DecodeString(removeSpace(raw))
	}
	return nil, errCrypto("unsupported encoding")
}

func formatCryptoBytes(b []byte, enc string) string {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "hex":
		return hex.EncodeToString(b)
	case "utf8", "text", "string":
		return string(b)
	default:
		return base64.StdEncoding.EncodeToString(b)
	}
}

func tryHex(s string) ([]byte, bool) {
	x := strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	if x == "" || len(x)%2 != 0 {
		return nil, false
	}
	for _, c := range x {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return nil, false
		}
	}
	b, err := hex.DecodeString(x)
	return b, err == nil
}

func tryBase64(s string) ([]byte, bool) {
	x := removeSpace(s)
	if x == "" || len(x)%4 != 0 {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(x)
	if err != nil {
		return nil, false
	}
	return b, true
}

func removeSpace(s string) string {
	return strings.Join(strings.Fields(s), "")
}

func firstNonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

type errCrypto string

func (e errCrypto) Error() string { return string(e) }

type rc4Cipher struct {
	s [256]byte
	i byte
	j byte
}

func newRC4(key []byte) (*rc4Cipher, error) {
	if len(key) == 0 || len(key) > 256 {
		return nil, errCrypto("rc4 key length must be 1..256 bytes")
	}
	c := &rc4Cipher{}
	for i := 0; i < 256; i++ {
		c.s[i] = byte(i)
	}
	var j byte
	for i := 0; i < 256; i++ {
		j += c.s[i] + key[i%len(key)]
		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
	return c, nil
}

func (c *rc4Cipher) XORKeyStream(dst, src []byte) {
	for k, v := range src {
		c.i++
		c.j += c.s[c.i]
		c.s[c.i], c.s[c.j] = c.s[c.j], c.s[c.i]
		t := c.s[c.i] + c.s[c.j]
		dst[k] = v ^ c.s[t]
	}
}

var _ io.Reader = rand.Reader
