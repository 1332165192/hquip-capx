package store

import (
	"testing"

	"github.com/hquip/capx/internal/model"
)

func TestHistoryClearGenerationMatchesNotificationAndNeverRepeats(t *testing.T) {
	s := New(16)
	ch, unsubscribe := s.Subscribe(8)
	defer unsubscribe()
	for want := uint64(1); want <= 3; want++ {
		counts, err := s.ClearHistoryAndNotify()
		if err != nil || counts.Generation != want {
			t.Fatalf("clear generation = %d, want %d, err=%v", counts.Generation, want, err)
		}
		event := <-ch
		data, ok := event.Data.(HistoryCounts)
		if !ok || event.Kind != "history_cleared" || data.Generation != counts.Generation {
			t.Fatalf("REST/SSE clear generations differ: %+v %+v", counts, event)
		}
		if event.HistoryGeneration != counts.Generation {
			t.Fatalf("clear envelope generation %d differs from data generation %d", event.HistoryGeneration, counts.Generation)
		}
	}
}

func TestPublishedTrafficEventsCarryTheirHistoryGeneration(t *testing.T) {
	s := New(16)
	before := s.Publish(model.Event{Kind: "http_tx"})
	if before.HistoryGeneration != 0 {
		t.Fatalf("initial history generation = %d", before.HistoryGeneration)
	}
	if _, err := s.ClearHistoryAndNotify(); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"http_tx", "ws_msg", "packet"} {
		after := s.Publish(model.Event{Kind: kind})
		if after.HistoryGeneration != 1 {
			t.Fatalf("%s generation = %d, want 1", kind, after.HistoryGeneration)
		}
	}
	if before.HistoryGeneration != 0 {
		t.Fatal("queued event generation was mutated by clear")
	}
}
