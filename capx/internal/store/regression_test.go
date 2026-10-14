package store

import (
	"fmt"
	"github.com/hquip/capx/internal/model"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

func TestRegressionClearDiskHistory(t *testing.T) {
	s := New(20)
	if err := s.EnableHTTPDisk(filepath.Join(t.TempDir(), "http.sqlite")); err != nil {
		t.Fatal(err)
	}
	defer s.CloseHTTPDisk()
	first := s.AddHTTPTx(&model.HTTPTx{Scheme: "http", Method: "GET", Host: "before.local", Path: "/before", URL: "http://before.local/before", Status: 200, ReqRaw: "GET /before HTTP/1.1\r\nHost: before.local\r\n\r\n"})
	s.ClearHistory()
	rows, enabled, err := s.QueryHTTPTx(HTTPQuery{Limit: 20})
	if err != nil || !enabled {
		t.Fatalf("query: enabled=%v err=%v", enabled, err)
	}
	if len(rows) != 0 {
		t.Errorf("clear retained %d disk rows (id=%d host=%s)", len(rows), rows[0].ID, rows[0].Host)
	}
	next := s.AddHTTPTx(&model.HTTPTx{Scheme: "http", Method: "POST", Host: "after.local", Path: "/after", URL: "http://after.local/after", Status: 201, ReqRaw: "POST /after HTTP/1.1\r\nHost: after.local\r\n\r\nnew"})
	rows, _, err = s.QueryHTTPTx(HTTPQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("old_id=%d new_id=%d rows=%d result=%+v", first.ID, next.ID, len(rows), rows[0])
	if rows[0].Host != next.Host || rows[0].Path != next.Path || rows[0].Method != next.Method {
		t.Errorf("new raw body stored under old metadata host=%s path=%s method=%s", rows[0].Host, rows[0].Path, rows[0].Method)
	}
}

func TestRegressionDedupHeaderDifferences(t *testing.T) {
	s := New(20)
	makeTx := func(who string) *model.HTTPTx {
		return &model.HTTPTx{Scheme: "https", Method: "GET", Host: "fixture.local", Path: "/", Status: 200, RespLen: 2, ReqRaw: "GET / HTTP/1.1\r\nCookie: account=" + who + "\r\n\r\n", RespRaw: "HTTP/1.1 200 OK\r\nSet-Cookie: session=" + who + "\r\n\r\nOK"}
	}
	a := s.AddHTTPTx(makeTx("A"))
	b := s.AddHTTPTx(makeTx("B"))
	rows := s.ListHTTPTx("")
	t.Logf("ids=%d,%d count=%d repeats=%d raw=%q", a.ID, b.ID, len(rows), b.RepeatCnt, b.ReqRaw)
	if a.ID == b.ID {
		t.Error("distinct Cookie / Set-Cookie exchanges merged and second credentials lost")
	}
}

func TestRegressionPublishUnsubscribe(t *testing.T) {
	old := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(old)
	s := New(20)
	start := make(chan struct{})
	errs := make(chan string, 8)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errs <- fmt.Sprint(r)
				}
			}()
			<-start
			for j := 0; j < 30000; j++ {
				s.Publish(model.Event{Kind: "test"})
			}
		}()
	}
	close(start)
	for j := 0; j < 30000; j++ {
		_, unsub := s.Subscribe(1)
		runtime.Gosched()
		unsub()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Errorf("concurrent subscriber disconnect panicked: %s", e)
	}
}
func TestRegressionRestoreCompleteness(t *testing.T) {
	dir := t.TempDir()
	s := New(20)
	s.Publish(model.Event{Kind: "evidence", Data: "retained event"})
	s.AddKeylogLine("CLIENT_RANDOM fixture evidence")
	s.AddPacket(model.Packet{CaptureID: "capture1", Raw: []byte{1, 2, 3}})
	stop, err := s.EnablePersistence(PersistConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	s2 := New(20)
	stop2, err := s2.EnablePersistence(PersistConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer stop2()
	t.Logf("after restart events=%d packets=%d keylog=%d", len(s2.Recent()), len(s2.ListPackets("")), len(s2.Keylog()))
	if len(s2.Recent()) != 1 {
		t.Error("serialized events never restored")
	}
	if len(s2.ListPackets("")) != 1 {
		t.Error("raw packets not persisted, export cannot reproduce previous capture")
	}
}
func TestRegressionDedupAuthorizationDisk(t *testing.T) {
	s := New(20)
	if err := s.EnableHTTPDisk(filepath.Join(t.TempDir(), "history.sqlite")); err != nil {
		t.Fatal(err)
	}
	defer s.CloseHTTPDisk()
	for _, who := range []string{"A", "B"} {
		s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "GET", Host: "fixture.local", Path: "/profile", URL: "https://fixture.local/profile", Status: 200, RespLen: 2, ReqHdr: map[string]string{"Authorization": "Bearer " + who, "Cookie": "account=" + who}, RespHdr: map[string]string{"Set-Cookie": "session=" + who}, ReqRaw: "GET /profile HTTP/1.1\r\nAuthorization: Bearer " + who + "\r\nCookie: account=" + who + "\r\n\r\n", RespRaw: "HTTP/1.1 200 OK\r\nSet-Cookie: session=" + who + "\r\n\r\nOK"})
	}
	rows, _, err := s.QueryHTTPTx(HTTPQuery{Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SQLite rows=%d repeat=%d Authorization=%q Cookie=%q Set-Cookie=%q", len(rows), rows[0].RepeatCnt, rows[0].ReqHdr["Authorization"], rows[0].ReqHdr["Cookie"], rows[0].RespHdr["Set-Cookie"])
	if len(rows) != 2 {
		t.Error("second Authorization/Cookie/Set-Cookie evidence lost before SQLite write; UI dedup cannot recover it")
	}
}
