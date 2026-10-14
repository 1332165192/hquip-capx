package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hquip/capx/internal/model"
)

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := New(100)
	s.AddHTTPTx(&model.HTTPTx{Scheme: "https", Method: "GET", Host: "example.com", URL: "https://example.com/", Status: 200})
	s.AddMemHit(&model.MemHit{PID: 42, Addr: 0x1000, Type: "i32", Value: "99"})
	s.UpsertFlow(&model.Flow{ID: "tcp|1.2.3.4:80>5.6.7.8:443", L4: model.TCP, SrcIP: "1.2.3.4", SrcPort: 80, DstIP: "5.6.7.8", DstPort: 443})

	stop, err := s.EnablePersistence(PersistConfig{Dir: dir, Interval: 1})
	if err != nil {
		t.Fatal(err)
	}
	// Force a flush by stopping.
	stop()

	// Verify the file was created.
	if _, err := os.Stat(filepath.Join(dir, "capx_state.json")); err != nil {
		t.Fatal("state file not created:", err)
	}

	// Load into a new store.
	s2 := New(100)
	stop2, err := s2.EnablePersistence(PersistConfig{Dir: dir, Interval: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer stop2()

	if txs := s2.ListHTTPTx(""); len(txs) != 1 || txs[0].Host != "example.com" {
		t.Fatalf("HTTP roundtrip failed: %+v", txs)
	}
	if mems := s2.ListMemHits(); len(mems) != 1 || mems[0].PID != 42 {
		t.Fatalf("MemHit roundtrip failed: %+v", mems)
	}
	if flows := s2.ListFlows(); len(flows) != 1 || flows[0].ID != "tcp|1.2.3.4:80>5.6.7.8:443" {
		t.Fatalf("Flow roundtrip failed: %+v", flows)
	}
}

func TestPersistMergesDirectionalFlowPairs(t *testing.T) {
	dir := t.TempDir()
	s := New(100)
	s.UpsertFlow(&model.Flow{ID: "tcp|1.2.3.4:80>5.6.7.8:443", L4: model.TCP, SrcIP: "1.2.3.4", SrcPort: 80, DstIP: "5.6.7.8", DstPort: 443, Bytes: 10, Packets: 2})
	s.UpsertFlow(&model.Flow{ID: "tcp|5.6.7.8:443>1.2.3.4:80", L4: model.TCP, SrcIP: "5.6.7.8", SrcPort: 443, DstIP: "1.2.3.4", DstPort: 80, Bytes: 5, Packets: 3})

	stop, err := s.EnablePersistence(PersistConfig{Dir: dir, Interval: 1})
	if err != nil {
		t.Fatal(err)
	}
	stop()

	s2 := New(100)
	stop2, err := s2.EnablePersistence(PersistConfig{Dir: dir, Interval: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer stop2()

	flows := s2.ListFlows()
	if len(flows) != 1 {
		t.Fatalf("merged flow count = %d, want 1", len(flows))
	}
	if flows[0].ID != "tcp|1.2.3.4:80>5.6.7.8:443" {
		t.Fatalf("merged flow id = %s", flows[0].ID)
	}
	if flows[0].Packets != 5 || flows[0].Bytes != 15 {
		t.Fatalf("merged flow counters = bytes %d packets %d, want 15/5", flows[0].Bytes, flows[0].Packets)
	}
}
