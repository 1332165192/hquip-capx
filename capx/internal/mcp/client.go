package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type apiClient struct {
	base           string
	token          string
	tokenFile      string
	http           *http.Client
	active         bool
	isolatedWeChat bool
}

func newAPIClient() *apiClient {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("CAPX_API")), "/")
	if base == "" {
		base = "http://127.0.0.1:19091"
	}
	token := strings.TrimSpace(os.Getenv("CAPX_TOKEN"))
	tokenFile := ""
	if token == "" {
		tokenFile = strings.TrimSpace(os.Getenv("CAPX_TOKEN_FILE"))
	}
	if token == "" && tokenFile == "" {
		if home, err := os.UserHomeDir(); err == nil {
			if b, err := os.ReadFile(filepath.Join(home, ".capx", "token")); err == nil {
				token = strings.TrimSpace(string(b))
			}
		}
	}
	return &apiClient{
		base:           base,
		token:          token,
		tokenFile:      tokenFile,
		http:           &http.Client{Timeout: 30 * time.Second},
		active:         envTruthy(os.Getenv("CAPX_MCP_ACTIVE")),
		isolatedWeChat: envTruthy(os.Getenv("CAPX_MCP_ISOLATED_WECHAT")),
	}
}

func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func (c *apiClient) do(method, path string, query url.Values, body any) (int, []byte, error) {
	token := c.token
	if c.tokenFile != "" {
		data, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return 0, nil, fmt.Errorf("read CAPX_TOKEN_FILE: %w", err)
		}
		token = strings.TrimSpace(string(data))
		if token == "" || strings.ContainsAny(token, "\r\n\x00") {
			return 0, nil, fmt.Errorf("CAPX_TOKEN_FILE contains an empty or invalid token")
		}
	}
	u := c.base + path
	if query != nil {
		u += "?" + query.Encode()
	}
	timeout := 30 * time.Second
	if strings.HasPrefix(path, "/api/stream") {
		timeout = 3 * time.Second
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rdr)
	if err != nil {
		return 0, nil, err
	}
	if timeout != 30*time.Second {
		ctx, cancel := context.WithTimeout(req.Context(), timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Capx-Token", token)
	}
	if strings.HasPrefix(path, "/api/stream") {
		req.Header.Set("Accept", "text/event-stream")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("capx API %s: %w (is captured running at %s?)", u, err, c.base)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(b) > 8<<20 {
		return resp.StatusCode, nil, fmt.Errorf("capx API response exceeds 8 MiB")
	}
	return resp.StatusCode, b, nil
}

func (c *apiClient) getJSON(path string, query url.Values) (any, error) {
	code, b, err := c.do(http.MethodGet, path, query, nil)
	if err != nil {
		return nil, err
	}
	if code >= 400 {
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", path, code, strings.TrimSpace(string(b)))
	}
	if http.DetectContentType(b) == "image/png" {
		return imageContent{Type: "image", MIMEType: "image/png", Data: base64.StdEncoding.EncodeToString(b)}, nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b), nil
	}
	return v, nil
}

func (c *apiClient) postJSON(path string, body any) (any, error) {
	code, b, err := c.do(http.MethodPost, path, nil, body)
	if err != nil {
		return nil, err
	}
	if code >= 400 {
		return nil, fmt.Errorf("POST %s: HTTP %d: %s", path, code, strings.TrimSpace(string(b)))
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return map[string]any{"ok": true}, nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b), nil
	}
	return v, nil
}

func (c *apiClient) deleteJSON(path string) (any, error) {
	code, b, err := c.do(http.MethodDelete, path, nil, nil)
	if err != nil {
		return nil, err
	}
	if code >= 400 {
		return nil, fmt.Errorf("DELETE %s: HTTP %d: %s", path, code, strings.TrimSpace(string(b)))
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return map[string]any{"ok": true}, nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b), nil
	}
	return v, nil
}
