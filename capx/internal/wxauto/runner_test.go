package wxauto

import (
	"sync"
	"testing"
	"time"

	"github.com/hquip/capx/internal/model"
)

type fakeOperator struct {
	mu       sync.Mutex
	elements []Element
	traffic  *[]*model.HTTPTx
}

func (f *fakeOperator) Snapshot(bool) (*Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &Snapshot{Route: "pages/index", Elements: append([]Element(nil), f.elements...)}, nil
}

func (f *fakeOperator) Click(Locator) (*locateResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.elements = nil
	*f.traffic = append(*f.traffic, &model.HTTPTx{ID: 1, Method: "POST", Host: "api.test", Path: "/click", Status: 200, RepeatCnt: 1, LastSeen: time.Now()})
	return &locateResult{Found: true}, nil
}

func (f *fakeOperator) Input(Locator, string, bool) (*locateResult, error) {
	return &locateResult{Found: true}, nil
}

func (f *fakeOperator) Back() error { return nil }

func TestAutomationBindsTrafficToClick(t *testing.T) {
	traffic := []*model.HTTPTx{}
	operator := &fakeOperator{
		elements: []Element{{ID: "wx-1", Tag: "button", Role: "button", Text: "查询", Selector: "button", Width: 80, Height: 30}},
		traffic:  &traffic,
	}
	automation := NewAutomation(operator, func() []*model.HTTPTx {
		return append([]*model.HTTPTx(nil), traffic...)
	})
	run, err := automation.Start(AutoConfig{MaxActions: 3, MaxDepth: 2, SettleMS: 1})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := automation.Status()
		if status != nil && status.Status == "completed" {
			if len(status.Actions) != 1 {
				t.Fatalf("actions = %+v", status.Actions)
			}
			action := status.Actions[0]
			if action.Kind != "click" || len(action.Traffic) != 1 || action.Traffic[0].ID != 1 {
				t.Fatalf("action = %+v", action)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("run %s did not complete: %+v", run.ID, automation.Status())
}

func TestChooseCandidateUsesConfiguredInput(t *testing.T) {
	snapshot := &Snapshot{Route: "pages/login", Elements: []Element{{ID: "user", Tag: "input", Name: "username", Placeholder: "账号"}}}
	config := normalizeAutoConfig(AutoConfig{InputValues: map[string]string{"username": "tester"}})
	element, value, kind := chooseCandidate(snapshot, config, map[string]bool{}, 0)
	if element == nil || element.ID != "user" || value != "tester" || kind != "input" {
		t.Fatalf("candidate = %+v value=%q kind=%q", element, value, kind)
	}
}

func TestTrafficDiffDetectsCollapsedRepeat(t *testing.T) {
	now := time.Now()
	before := snapshotTraffic(func() []*model.HTTPTx {
		return []*model.HTTPTx{{ID: 7, RepeatCnt: 1, LastSeen: now}}
	})
	diff := trafficDiff(before, func() []*model.HTTPTx {
		return []*model.HTTPTx{{ID: 7, Method: "GET", Host: "api.test", Path: "/same", Status: 200, RepeatCnt: 2, LastSeen: now.Add(time.Second)}}
	})
	if len(diff) != 1 || !diff[0].Repeated || diff[0].ID != 7 {
		t.Fatalf("diff = %+v", diff)
	}
}
