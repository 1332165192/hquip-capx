package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
	"github.com/hquip/capx/internal/store"
)

func TestStreamMarksRecentCopiesAsReplayAndSubscriptionEventsAsLive(t *testing.T) {
	st := store.New(16)
	old := st.Publish(model.Event{Kind: "http_tx", Data: map[string]int{"id": 1}})
	api := &Server{st: st}
	server := httptest.NewServer(http.HandlerFunc(api.stream))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	scanner := bufio.NewScanner(response.Body)
	readEvent := func() model.Event {
		t.Helper()
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			var event model.Event
			if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:"))), &event); err != nil {
				t.Fatal(err)
			}
			return event
		}
		t.Fatalf("stream ended before event: %v", scanner.Err())
		return model.Event{}
	}
	replayed := readEvent()
	if replayed.ID != old.ID || !replayed.Replayed {
		t.Fatalf("retained event not marked as replay: %+v", replayed)
	}
	live := st.Publish(model.Event{Kind: "ws_msg", Data: map[string]int{"id": 2}})
	future := readEvent()
	if future.ID != live.ID || future.Replayed {
		t.Fatalf("future event incorrectly marked as replay: %+v", future)
	}
	for _, event := range st.Recent() {
		if event.Replayed {
			t.Fatal("stream mutated the persisted recent-event ring")
		}
	}
}
