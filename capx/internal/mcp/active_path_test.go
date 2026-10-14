package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGenericAPIGatesDecodedPathsAndQuery(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("active operation reached backend") }))
	defer backend.Close()
	s := &Server{api: &apiClient{base: backend.URL, http: backend.Client(), active: false}}
	for _, route := range []string{"/api/wxapkg/unpack", "/api/wxapkg/unpack?reconstruct=1", "/api/%77xapkg/unpack", "/api/proxy/lan/start", "/api/proxy/lan/start?mode=wifi"} {
		if _, err := s.callGenericAPI(map[string]any{"method": "POST", "path": route}); err == nil || !strings.Contains(err.Error(), "CAPX_MCP_ACTIVE") {
			t.Fatal("missing active gate", route, err)
		}
	}
	for _, route := range []string{"/api/%2e%2e/health", "http://example.com/api/proxy/lan/start"} {
		if _, err := s.callGenericAPI(map[string]any{"method": "POST", "path": route}); err == nil {
			t.Fatal("accepted invalid path", route)
		}
	}
}
