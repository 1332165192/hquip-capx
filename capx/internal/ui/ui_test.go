package ui

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestWorkspaceAssetsAreEmbedded(t *testing.T) {
	for _, asset := range []struct {
		path, contentType, marker string
	}{
		{"/", "text/html", `id="workspace"`},
		{"/console.css", "text/css", "body.embed .content"},
		{"/console-shell.js", "javascript", "capx:viewchange"},
		{"/mobile.js", "javascript", "/api/mobile/capture/start"},
		{"/mobile.css", "text/css", ".mobile-grid"},
		{"/disclaimer.html", "text/html", "仅用于获得授权的环境"},
		{"/wxdesk.js", "javascript", "/api/wxdesk/"},
		{"/wxdesk.css", "text/css", ".wxb-layout"},
		{"/desktop-bridge.js", "javascript", "capx:api-request"},
	} {
		t.Run(asset.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, asset.path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d", response.Code)
			}
			if !strings.Contains(response.Header().Get("Content-Type"), asset.contentType) {
				t.Fatalf("content type = %q", response.Header().Get("Content-Type"))
			}
			if !strings.Contains(response.Body.String(), asset.marker) {
				t.Fatalf("embedded asset missing %q", asset.marker)
			}
			if cache := response.Header().Get("Cache-Control"); cache != "no-store, max-age=0" {
				t.Fatalf("stale UI assets could be cached: %q", cache)
			}
		})
	}
}

func TestWorkspaceKeepsCaptureNavigation(t *testing.T) {
	data, err := assets.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(data)
	for _, view := range []string{
		"dashboard", "target", "proxy", "client", "mobile", "wxdesk", "intruder", "turbo", "repeater",
		"session", "decoder", "comparer", "hook", "memory", "rules", "correlate",
		"script", "dnslog", "wxhook", "wxapkg", "enhance", "logger", "settings",
	} {
		if strings.Count(page, `data-v="`+view+`"`) != 1 {
			t.Errorf("view %q must have exactly one navigation control", view)
		}
		if strings.Count(page, `id="v_`+view+`"`) != 1 {
			t.Errorf("view %q must retain its panel", view)
		}
	}
	// Validate only the static markup; the main script contains dynamic templates.
	markup := strings.Split(page, "//=========================== helpers")[0]
	seen := map[string]bool{}
	for _, match := range regexp.MustCompile(`\bid="([^"]+)"`).FindAllStringSubmatch(markup, -1) {
		if seen[match[1]] {
			t.Errorf("duplicate static DOM ID: %s", match[1])
		}
		seen[match[1]] = true
	}
	for _, id := range []string{"d_proxyaddr", "d_proxystart", "d_proxystop", "d_setup_url", "d_setup_go", "d_setup_browser", "d_setup_http3", "d_setup_proxy_off", "hh_listwrap", "hh_detail", "rp_req", "t_state"} {
		if !seen[id] {
			t.Errorf("capture control %q was removed", id)
		}
	}
}
