package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/hquip/capx/internal/proxy"
)

type httpDecryptRequest struct {
	cryptoCodecReq
	Side          string `json:"side"`
	Pointer       string `json:"json_pointer"`
	KeyEnv        string `json:"key_env"`
	IVEnv         string `json:"iv_env"`
	PrivateKeyEnv string `json:"private_key_env"`
}

func capturedHTTPBody(raw, side string) ([]byte, error) {
	var body io.ReadCloser
	var header http.Header
	if side == "request" {
		request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
		if err != nil {
			return nil, errors.New("请求记录不是完整 HTTP 报文")
		}
		body, header = request.Body, request.Header
	} else {
		response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
		if err != nil {
			return nil, errors.New("响应记录不是完整 HTTP 报文")
		}
		body, header = response.Body, response.Header
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, (8<<20)+1))
	if err != nil || len(data) > 8<<20 {
		return nil, errors.New("报文正文读取失败或超过 8 MiB")
	}
	data, err = proxy.DecodeCapturedBody(header, data)
	if err != nil || len(data) > 8<<20 {
		return nil, errors.New("报文压缩格式无效、不支持或解压后超过 8 MiB")
	}
	return data, nil
}

// JSON Pointer follows RFC 6901; only string-valued ciphertext is accepted.
func ciphertextAt(body []byte, pointer string) (string, error) {
	if pointer == "" {
		return string(body), nil
	}
	if !strings.HasPrefix(pointer, "/") || len(pointer) > 4096 {
		return "", errors.New("字段路径需使用 JSON Pointer，例如 /data/ciphertext")
	}
	parts := strings.Split(pointer[1:], "/")
	if len(parts) > 64 {
		return "", errors.New("JSON Pointer 深度超过限制")
	}
	var value any
	if json.Unmarshal(body, &value) != nil {
		return "", errors.New("所选报文正文不是有效 JSON")
	}
	for _, part := range parts {
		for i := 0; i < len(part); i++ {
			if part[i] == '~' {
				if i+1 >= len(part) || (part[i+1] != '0' && part[i+1] != '1') {
					return "", errors.New("JSON Pointer 转义无效")
				}
				i++
			}
		}
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		switch node := value.(type) {
		case map[string]any:
			var ok bool
			value, ok = node[part]
			if !ok {
				return "", errors.New("JSON 中没有指定的密文字段")
			}
		case []any:
			for _, c := range part {
				if c < '0' || c > '9' {
					return "", errors.New("JSON Pointer 数组索引无效")
				}
			}
			index, err := strconv.Atoi(part)
			if err != nil || index < 0 || index >= len(node) || (len(part) > 1 && part[0] == '0') {
				return "", errors.New("JSON Pointer 数组索引无效")
			}
			value = node[index]
		default:
			return "", errors.New("JSON Pointer 路径不是对象或数组")
		}
	}
	text, ok := value.(string)
	if !ok {
		return "", errors.New("密文字段必须是字符串")
	}
	return text, nil
}

func businessSecret(direct, name string) (string, error) {
	if name == "" {
		return direct, nil
	}
	if direct != "" {
		return "", errors.New("直接密钥和环境变量引用只能选择一种")
	}
	if !strings.HasPrefix(name, "CAPX_APP_") || len(name) > 128 {
		return "", errors.New("业务密钥环境变量须以 CAPX_APP_ 开头")
	}
	for _, c := range name {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return "", errors.New("无效的密钥环境变量名")
		}
	}
	value := os.Getenv(name)
	if value == "" {
		return "", errors.New("指定的业务密钥环境变量尚未配置")
	}
	return value, nil
}

func (s *Server) httpDecrypt(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad tx id")
		return
	}
	tx, ok := s.st.GetHTTPTx(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "transaction not found")
		return
	}
	if tx.BodyTruncated {
		writeErr(w, http.StatusConflict, "抓包正文已截断，无法可靠执行业务解密")
		return
	}
	var req httpDecryptRequest
	if decodeBody(r, &req) != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Side == "" {
		req.Side = "response"
	}
	if req.Side != "response" && req.Side != "request" {
		writeErr(w, http.StatusBadRequest, "side must be request or response")
		return
	}
	raw := tx.RespRaw
	if req.Side == "request" {
		raw = tx.ReqRaw
	}
	body, err := capturedHTTPBody(raw, req.Side)
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	req.Input, err = ciphertextAt(body, req.Pointer)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Key, err = businessSecret(req.Key, req.KeyEnv); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.IV, err = businessSecret(req.IV, req.IVEnv); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.PrivKey, err = businessSecret(req.PrivKey, req.PrivateKeyEnv); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Op = "decrypt"
	req.Algorithm = strings.ToLower(strings.TrimSpace(req.Algorithm))
	if req.Algorithm == "" {
		req.Algorithm = "aes"
	}
	if req.InputEnc == "" {
		req.InputEnc = "base64"
	}
	if req.OutputEnc == "" {
		req.OutputEnc = "utf8"
	}
	if req.OutputEnc != "utf8" && req.OutputEnc != "base64" && req.OutputEnc != "hex" {
		writeErr(w, http.StatusBadRequest, "unsupported output encoding")
		return
	}
	var plain []byte
	switch req.Algorithm {
	case "aes", "des", "3des", "tripledes", "rc4":
		plain, err = cryptoSymmetric(req.cryptoCodecReq)
	case "rsa":
		plain, err = cryptoRSA(req.cryptoCodecReq)
	default:
		writeErr(w, http.StatusBadRequest, "unsupported algorithm")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "业务解密失败，请核对算法、密钥、IV、填充及认证标签；原始抓包记录保持不变")
		return
	}
	result := map[string]any{"id": id, "side": req.Side, "json_pointer": req.Pointer, "algorithm": req.Algorithm, "output": formatCryptoBytes(plain, req.OutputEnc), "output_enc": req.OutputEnc, "bytes": len(plain), "integrity_verified": req.Algorithm == "aes" && strings.EqualFold(strings.TrimSpace(req.Mode), "gcm")}
	var structured any
	if json.Unmarshal(plain, &structured) == nil {
		result["json"] = structured
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}
