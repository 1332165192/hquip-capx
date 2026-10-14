package setup

import (
	"net/url"
	"regexp"
	"strings"
)

var userDataDirRe = regexp.MustCompile(`(?i)--user-data-dir(?:=|\s+)(?:"([^"]+)"|(\S+))`)

func sanitizeStartURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "https://example.com"
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || strings.TrimSpace(u.Host) == "" {
		return "https://example.com"
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u.String()
	default:
		return "https://example.com"
	}
}

func shouldSkipBrowserRestart(cmd string) bool {
	low := strings.ToLower(cmd)
	switch {
	case strings.Contains(low, "chrome-capture-profile"),
		strings.Contains(low, "capx-desktop"),
		strings.Contains(low, "--app="):
		return true
	}
	return false
}

func extractUserDataDir(cmd string) string {
	m := userDataDirRe.FindStringSubmatch(cmd)
	if len(m) < 3 {
		return ""
	}
	if m[1] != "" {
		return strings.TrimSpace(m[1])
	}
	return strings.TrimRight(strings.TrimSpace(m[2]), `"'`)
}
