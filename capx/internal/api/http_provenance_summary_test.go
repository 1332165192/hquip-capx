package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

func TestHTTPListPreservesTransportProvenanceAcrossBackends(t *testing.T) {
	for _, disk := range []bool{false, true} {
		t.Run(fmt.Sprintf("sqlite=%v", disk), func(t *testing.T) {
			st := store.New(10)
			if disk {
				if err := st.EnableHTTPDisk(filepath.Join(t.TempDir(), "history.sqlite")); err != nil {
					t.Fatal(err)
				}
				defer st.CloseHTTPDisk()
			}
			st.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "GET", Host: "local.test", Path: "/nonce", Status: 200, Decrypted: true,
				CaptureMode: "mobile-vpn", ClientAddr: "10.77.0.2:43210", CapturePeer: "wg-fixture",
				ReqHdr: map[string]string{"X-Capture-Mode": "forged-web"}, ReqRaw: "private request content", RespRaw: "private response content"})
			w := httptest.NewRecorder()
			(&Server{st: st}).listHTTP(w, httptest.NewRequest(http.MethodGet, "/api/http?limit=1", nil))
			var rows []map[string]any
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &rows) != nil || len(rows) != 1 {
				t.Fatal("HTTP summary unavailable")
			}
			row := rows[0]
			if row["capture_mode"] != "mobile-vpn" || row["client_addr"] != "10.77.0.2:43210" || row["capture_peer"] != "wg-fixture" || row["decrypted"] != true {
				t.Fatal("HTTP summary lost transport-owned provenance")
			}
			if _, ok := row["req_raw"]; ok {
				t.Fatal("summary exposed request body")
			}
			if _, ok := row["resp_raw"]; ok {
				t.Fatal("summary exposed response body")
			}
		})
	}
}
