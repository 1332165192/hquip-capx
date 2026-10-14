package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
)

func TestClearHistoryPersistsBeforeAcknowledgement(t *testing.T) {
	dir := t.TempDir()
	s := New(32)
	stop, err := s.EnablePersistence(PersistConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := s.EnableHTTPDisk(filepath.Join(dir, "history.sqlite")); err != nil {
		t.Fatal(err)
	}
	defer s.CloseHTTPDisk()
	old := s.AddHTTPTx(&model.HTTPTx{Host: "old.test", ReqRaw: "old"})
	s.AddPacket(model.Packet{Raw: []byte{1, 2}})
	if _, err := s.ClearHistoryAndNotify(); err != nil {
		t.Fatal(err)
	}
	// Read the snapshot before the timer or shutdown has a chance to save it.
	fresh := New(32)
	p := &persister{st: fresh, dir: dir}
	if err := p.load(); err != nil {
		t.Fatal(err)
	}
	if len(fresh.ListHTTPTx("")) != 0 || len(fresh.ListPackets("")) != 0 {
		t.Fatal("clear acknowledged before snapshot removal")
	}
	if next := fresh.AddHTTPTx(&model.HTTPTx{Host: "new.test"}); next.ID <= old.ID {
		t.Fatal("snapshot reused a cleared HTTP ID")
	}
}

func TestDiskClearGenerationRejectsStaleSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "history.sqlite")
	s := New(32)
	stop, err := s.EnablePersistence(PersistConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnableHTTPDisk(path); err != nil {
		t.Fatal(err)
	}
	old := s.AddHTTPTx(&model.HTTPTx{Host: "old.test", ReqRaw: "old"})
	s.AddPacket(model.Packet{Raw: []byte{1}})
	stop()
	stale, err := os.ReadFile(filepath.Join(dir, "capx_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClearHistoryAndNotify(); err != nil {
		t.Fatal(err)
	}
	s.CloseHTTPDisk()
	// Simulate a crash between the SQLite delete commit and snapshot rename.
	if err := os.WriteFile(filepath.Join(dir, "capx_state.json"), stale, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := New(32)
	stopFresh, err := fresh.EnablePersistence(PersistConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer stopFresh()
	if err := fresh.EnableHTTPDisk(path); err != nil {
		t.Fatal(err)
	}
	defer fresh.CloseHTTPDisk()
	if len(fresh.ListHTTPTx("")) != 0 || len(fresh.ListPackets("")) != 0 {
		t.Fatal("stale snapshot resurrected cleared traffic")
	}
	if next := fresh.AddHTTPTx(&model.HTTPTx{Host: "new.test"}); next.ID <= old.ID {
		t.Fatal("disk highwater reused an ID")
	}
}

func TestClearFailureLeavesMemoryIntact(t *testing.T) {
	s := New(10)
	if err := s.EnableHTTPDisk(filepath.Join(t.TempDir(), "history.sqlite")); err != nil {
		t.Fatal(err)
	}
	s.AddHTTPTx(&model.HTTPTx{Host: "keep.test"})
	s.httpDisk.db.Close() // deterministic failed-disk fixture; no permissions changes
	if _, err := s.ClearHistoryAndNotify(); err == nil {
		t.Fatal("closed database clear was acknowledged")
	}
	if len(s.ListHTTPTx("")) != 1 {
		t.Fatal("failed disk delete destroyed memory evidence")
	}
}

func TestConcurrentHistoryClearAndWritesStayConsistent(t *testing.T) {
	s := New(1000)
	if err := s.EnableHTTPDisk(filepath.Join(t.TempDir(), "history.sqlite")); err != nil {
		t.Fatal(err)
	}
	defer s.CloseHTTPDisk()
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				s.AddHTTPTx(&model.HTTPTx{Host: fmt.Sprintf("worker-%d.test", worker), Path: fmt.Sprint(i), ReqRaw: fmt.Sprintf("worker=%d item=%d", worker, i)})
			}
		}(worker)
	}
	for i := 0; i < 20; i++ {
		if _, err := s.ClearHistoryAndNotify(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	s.AddHTTPTx(&model.HTTPTx{Host: "last.test"})
	memory := s.ListHTTPTx("")
	disk, _, err := s.QueryHTTPTx(HTTPQuery{})
	if err != nil {
		t.Fatal(err)
	}
	if len(memory) != len(disk) {
		t.Fatalf("memory=%d disk=%d", len(memory), len(disk))
	}
	byID := map[uint64]*model.HTTPTx{}
	for _, tx := range memory {
		byID[tx.ID] = tx
	}
	for _, tx := range disk {
		m := byID[tx.ID]
		if m == nil || m.Host != tx.Host || m.ReqRaw != tx.ReqRaw {
			t.Fatalf("mixed/stale disk row: %+v", tx)
		}
	}
}

func TestPersistenceRestoresCaptureKeylogAndSequence(t *testing.T) {
	dir := t.TempDir()
	s := New(20)
	s.PutCapture(&model.Capture{ID: "cap-1", Running: true, LinkType: 101})
	s.AddPacket(model.Packet{CaptureID: "cap-1", TS: time.Now().UTC(), Raw: []byte{0x45, 0, 0, 3}})
	s.AddKeylogLine("CLIENT_RANDOM fixture evidence")
	event := s.Publish(model.Event{Kind: "test", Data: "preserved"})
	stop, err := s.EnablePersistence(PersistConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	stop()
	fresh := New(20)
	stop, err = fresh.EnablePersistence(PersistConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	capture, ok := fresh.GetCapture("cap-1")
	if !ok || capture.Running || capture.LinkType != 101 {
		t.Fatalf("restored capture = %+v", capture)
	}
	if fresh.CaptureLinkTypeForExport("cap-1") != 101 || len(fresh.ListPackets("cap-1")) != 1 {
		t.Fatal("raw capture export metadata was lost")
	}
	if len(fresh.Keylog()) != 1 || fresh.AddKeylogLine("CLIENT_RANDOM fixture evidence") {
		t.Fatal("keylog restore/dedup failed")
	}
	if next := fresh.Publish(model.Event{Kind: "next"}); next.ID <= event.ID {
		t.Fatal("restored event sequence went backwards")
	}
}

func TestHTTPPageSummarySearchAndLiteralWildcards(t *testing.T) {
	s := New(2)
	if err := s.EnableHTTPDisk(filepath.Join(t.TempDir(), "history.sqlite")); err != nil {
		t.Fatal(err)
	}
	defer s.CloseHTTPDisk()
	for i := 0; i < 8; i++ {
		s.AddHTTPTx(&model.HTTPTx{Host: "page.test", Path: fmt.Sprint(i), ReqRaw: "body: literal_%", RespRaw: "响应中文"})
	}
	for _, needle := range []string{"literal_%", "响应中文", "page.test"} {
		rows, total, enabled, err := s.QueryHTTPPage(HTTPQuery{Filter: HTTPFilter{Query: needle}, Limit: 3, Offset: 2, Summary: true})
		if err != nil || !enabled || total != 8 || len(rows) != 3 {
			t.Fatalf("q=%q total=%d len=%d enabled=%v err=%v", needle, total, len(rows), enabled, err)
		}
		if rows[0].ReqRaw != "" || rows[0].RespRaw != "" || rows[0].RespRawLen != len("响应中文") {
			t.Fatal("summary body/byte length mismatch")
		}
	}
	_, total, _, err := s.QueryHTTPPage(HTTPQuery{Filter: HTTPFilter{Query: "not%present"}})
	if err != nil || total != 0 {
		t.Fatalf("SQL treated literal query as wildcard: total=%d err=%v", total, err)
	}
}

func TestHTTPEvidenceCopiesCannotBeMutatedByCaller(t *testing.T) {
	s := New(4)
	source := &model.HTTPTx{Host: "original.test", ReqHdr: map[string]string{"Cookie": "original"}}
	returned := s.AddHTTPTx(source)
	source.Host, source.ReqHdr["Cookie"] = "changed", "changed"
	returned.ReqHdr["Cookie"] = "returned changed"
	rows := s.ListHTTPTx("")
	rows[0].ReqHdr["Cookie"] = "list changed"
	got, _ := s.GetHTTPTx(returned.ID)
	if got.Host != "original.test" || got.ReqHdr["Cookie"] != "original" {
		t.Fatalf("stored evidence aliased mutable caller: %+v", got)
	}
}

func TestRestoreOwnsHTTPValuesAndDoesNotDuplicateIDs(t *testing.T) {
	source := New(8)
	original := source.AddHTTPTx(&model.HTTPTx{Host: "saved.test", ReqHdr: map[string]string{"Cookie": "saved"}})
	snap := source.Snapshot()
	restored := New(8)
	restored.Restore(snap)
	restored.Restore(snap)
	snap.HTTPTxs[0].Host = "mutated.test"
	snap.HTTPTxs[0].ReqHdr["Cookie"] = "mutated"
	got, _ := restored.GetHTTPTx(original.ID)
	if got.Host != "saved.test" || got.ReqHdr["Cookie"] != "saved" || len(restored.ListHTTPTx("")) != 1 {
		t.Fatalf("Restore aliased snapshot or duplicated IDs: %+v", got)
	}
}

func TestHTTPDiskMigratesVariablePrecisionTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.sqlite")
	disk, err := OpenHTTPDisk(path)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 9, 21, 1, 2, 3, 0, time.UTC)
	for i, ns := range []int{0, 100000000, 110000000, 10000000, 1} {
		ts := stamp.Add(time.Duration(ns))
		if err := disk.Upsert(&model.HTTPTx{ID: uint64(i + 1), TS: ts, LastSeen: ts}); err != nil {
			t.Fatal(err)
		}
		// Recreate the pre-upgrade on-disk format, including mixed precision.
		if _, err := disk.db.Exec(`UPDATE http_txs SET ts=?,last_seen=? WHERE id=?`, ts.Format(time.RFC3339Nano), ts.Format(time.RFC3339Nano), i+1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := disk.db.Exec(`DELETE FROM history_meta WHERE key='fixed_time_format'`); err != nil {
		t.Fatal(err)
	}
	disk.Close()
	disk, err = OpenHTTPDisk(path)
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	rows, total, err := disk.QueryPage(HTTPQuery{Summary: true})
	if err != nil || total != 5 {
		t.Fatalf("total=%d err=%v", total, err)
	}
	want := []uint64{3, 2, 4, 5, 1}
	for i, tx := range rows {
		if tx.ID != want[i] {
			t.Fatalf("row %d ID=%d want=%d", i, tx.ID, want[i])
		}
	}
}

func TestClearCrashPreservesWebSocketAndEventHighwaters(t *testing.T) {
	dir := t.TempDir()
	s := New(8)
	stop, err := s.EnablePersistence(PersistConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "history.sqlite")
	if err := s.EnableHTTPDisk(path); err != nil {
		t.Fatal(err)
	}
	s.AddWSMessage(&model.WSMessage{Data: "first"})
	stop()
	stale, err := os.ReadFile(filepath.Join(dir, "capx_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	lastWS := s.AddWSMessage(&model.WSMessage{Data: "after snapshot"})
	lastEvent := s.Publish(model.Event{Kind: "after snapshot"})
	if _, err := s.ClearHistoryAndNotify(); err != nil {
		t.Fatal(err)
	}
	s.CloseHTTPDisk()
	if err := os.WriteFile(filepath.Join(dir, "capx_state.json"), stale, 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := New(8)
	stop, err = fresh.EnablePersistence(PersistConfig{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	if err := fresh.EnableHTTPDisk(path); err != nil {
		t.Fatal(err)
	}
	defer fresh.CloseHTTPDisk()
	if ws := fresh.AddWSMessage(&model.WSMessage{Data: "new"}); ws.ID <= lastWS.ID {
		t.Fatal("clear/crash reused WS ID")
	}
	if event := fresh.Publish(model.Event{Kind: "new"}); event.ID <= lastEvent.ID+1 {
		t.Fatal("clear/crash reused event or clear notification ID")
	}
}
