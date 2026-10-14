package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type ConsoleResponse struct {
	Status      int               `json:"status"`
	ContentType string            `json:"content_type"`
	Data        string            `json:"data"` // base64 preserves binary screenshots.
	Headers     map[string]string `json:"headers"`
}

func consolePathAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" || strings.ContainsAny(u.Path, "\\\x00") {
		return false
	}
	return path.Clean(u.Path) == u.Path && (u.Path == "/health" || strings.HasPrefix(u.Path, "/api/")) && u.Path != "/api/stream"
}

// ApiRequest serves only the selected backend's API. Credentials remain in
// Go; embedded WebView documents do not need third-party authentication cookies.
func (a *App) ApiRequest(method, apiPath, body string) (ConsoleResponse, error) {
	method = strings.ToUpper(method)
	if !consolePathAllowed(apiPath) || (method != "GET" && method != "HEAD" && method != "POST" && method != "DELETE" && method != "PUT" && method != "PATCH") {
		return ConsoleResponse{}, fmt.Errorf("unsupported console API request")
	}
	for attempt := 0; attempt < 2; attempt++ {
		base, token := a.connection()
		ctx := a.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, cancel := context.WithTimeout(ctx, 110*time.Second)
		req, err := http.NewRequestWithContext(ctx, method, base+apiPath, strings.NewReader(body))
		if err != nil {
			cancel()
			return ConsoleResponse{}, err
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		client := *a.hc
		client.Timeout = 110 * time.Second
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		response, err := client.Do(req)
		if err != nil {
			cancel()
			return ConsoleResponse{}, err
		}
		data, err := io.ReadAll(io.LimitReader(response.Body, (32<<20)+1))
		response.Body.Close()
		cancel()
		if err != nil {
			return ConsoleResponse{}, err
		}
		if len(data) > 32<<20 {
			return ConsoleResponse{}, fmt.Errorf("console API response exceeds 32 MiB")
		}
		if response.StatusCode == http.StatusUnauthorized && attempt == 0 {
			a.refreshToken()
			continue
		}
		mime := response.Header.Get("Content-Type")
		if mime == "" {
			mime = http.DetectContentType(data)
		}
		headers := map[string]string{}
		for _, name := range []string{"Content-Type", "X-Total-Count", "Content-Disposition", "Cache-Control"} {
			if value := response.Header.Get(name); value != "" {
				headers[name] = value
			}
		}
		return ConsoleResponse{Status: response.StatusCode, ContentType: mime, Headers: headers, Data: base64.StdEncoding.EncodeToString(data)}, nil
	}
	return ConsoleResponse{}, fmt.Errorf("console credentials unavailable")
}

func (a *App) StreamStatus() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.streamConnected }
func (a *App) setStreamStatus(connected bool) {
	a.mu.Lock()
	a.streamConnected = connected
	a.mu.Unlock()
}
