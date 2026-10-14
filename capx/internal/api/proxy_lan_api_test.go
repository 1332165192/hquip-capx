package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLANAPIRejectsInvalidConfig(t *testing.T) {
	s, _ := captureTransportServer(t)
	for _, body := range []string{`{"host":"127.0.0.1","port":18080}`, `{"host":"0.0.0.0","port":18080}`, `{"host":"203.0.113.5","port":18080}`, `{"host":"192.168.1.2","port":-1}`, `{"host":"192.168.1.2","port":70000}`, `{"host":"192.168.1.2","port":18080,"unknown":true}`} {
		rr := httptest.NewRecorder()
		s.proxyLANStart(rr, httptest.NewRequest(http.MethodPost, "/api/proxy/lan/start", strings.NewReader(body)))
		if rr.Code < 400 {
			t.Fatalf("invalid LAN configuration accepted: %s", body)
		}
	}
	if running, _ := s.proxy.LANStatus(); running {
		t.Fatal("validation created a listener")
	}
}
