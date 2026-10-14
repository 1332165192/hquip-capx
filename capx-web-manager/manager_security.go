package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var managerPostOnlyPaths = map[string]struct{}{
	"/api/start":            {},
	"/api/stop":             {},
	"/api/stop-all":         {},
	"/api/open":             {},
	"/api/browser":          {},
	"/api/ghost":            {},
	"/api/ghost-stop":       {},
	"/api/adb":              {},
	"/api/adb-stop":         {},
	"/api/open-dir":         {},
	"/api/copy":             {},
	"/api/src-template":     {},
	"/api/select-directory": {},
	"/api/exit":             {},
}

var managerJSONPaths = map[string]struct{}{
	"/api/config":           {},
	"/api/start":            {},
	"/api/stop":             {},
	"/api/src-template":     {},
	"/api/select-directory": {},
}

func managerRequestGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setManagerSecurityHeaders(w)
		if !managerLoopbackHost(r.Host) {
			writeManagerHTTPError(w, http.StatusForbidden, "loopback Host header required")
			return
		}
		if _, postOnly := managerPostOnlyPaths[r.URL.Path]; postOnly && r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeManagerHTTPError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !managerSameOrigin(r) {
			writeManagerHTTPError(w, http.StatusForbidden, "cross-origin manager request rejected")
			return
		}
		if _, expectsJSON := managerJSONPaths[r.URL.Path]; expectsJSON && r.Method == http.MethodPost {
			contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
			if contentType != "application/json" {
				writeManagerHTTPError(w, http.StatusUnsupportedMediaType, "application/json is required")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func setManagerSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func managerLoopbackHost(hostPort string) bool {
	host := strings.TrimSpace(hostPort)
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	} else {
		host = strings.Trim(host, "[]")
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

func managerSameOrigin(r *http.Request) bool {
	site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	if site == "cross-site" || site == "same-site" {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host) && managerLoopbackHost(parsed.Host)
}

func writeManagerHTTPError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiResp{OK: false, Error: message})
}
