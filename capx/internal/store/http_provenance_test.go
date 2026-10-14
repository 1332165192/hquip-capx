package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
)

func TestHTTPDiskPreservesTransportProvenanceAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.sqlite")
	disk, err := OpenHTTPDisk(path)
	if err != nil {
		t.Fatal(err)
	}
	tx := &model.HTTPTx{ID: 1, TS: time.Now(), Scheme: "http", Method: "GET", Host: "fixture", URL: "http://fixture/", CaptureMode: "mobile-vpn", ClientAddr: "10.77.0.2:1234", CapturePeer: "wg-1234567890abcdef", ReqRaw: "GET / HTTP/1.1\r\n\r\n"}
	if err = disk.Upsert(tx); err != nil {
		disk.Close()
		t.Fatal(err)
	}
	disk.Close()
	disk, err = OpenHTTPDisk(path)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	rows, err := disk.Query(HTTPQuery{Summary: true})
	if err != nil || len(rows) != 1 {
		t.Fatalf("query %v %v", rows, err)
	}
	if rows[0].CaptureMode != tx.CaptureMode || rows[0].ClientAddr != tx.ClientAddr || rows[0].CapturePeer != tx.CapturePeer || rows[0].ReqRaw != "" {
		t.Fatalf("summary lost provenance %#v", rows[0])
	}
	full, err := disk.Get(1)
	if err != nil || full.CaptureMode != tx.CaptureMode || full.ReqRaw != tx.ReqRaw {
		t.Fatal("detail lost provenance")
	}
}
