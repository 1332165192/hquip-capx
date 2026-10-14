package wxauto

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hquip/capx/internal/model"
)

type Operator interface {
	Snapshot(withScreenshot bool) (*Snapshot, error)
	Click(locator Locator) (*locateResult, error)
	Input(locator Locator, value string, clear bool) (*locateResult, error)
	Back() error
}

type TrafficFunc func() []*model.HTTPTx

type AutoConfig struct {
	MaxActions   int               `json:"max_actions"`
	MaxDepth     int               `json:"max_depth"`
	SettleMS     int               `json:"settle_ms"`
	IncludeRisky bool              `json:"include_risky"`
	InputValues  map[string]string `json:"input_values,omitempty"`
}

type TrafficDelta struct {
	ID          uint64 `json:"id"`
	Scheme      string `json:"scheme"`
	Method      string `json:"method"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	Status      int    `json:"status"`
	MIME        string `json:"mime,omitempty"`
	RepeatCount int    `json:"repeat_count"`
	Repeated    bool   `json:"repeated"`
}

type AutoAction struct {
	Index       int            `json:"index"`
	Kind        string         `json:"kind"`
	RouteBefore string         `json:"route_before"`
	RouteAfter  string         `json:"route_after,omitempty"`
	Element     *Element       `json:"element,omitempty"`
	Value       string         `json:"value,omitempty"`
	BeforeMaxID uint64         `json:"before_max_id"`
	Traffic     []TrafficDelta `json:"traffic,omitempty"`
	StartedAt   time.Time      `json:"started_at"`
	FinishedAt  time.Time      `json:"finished_at"`
	Error       string         `json:"error,omitempty"`
}

type AutoRun struct {
	ID           string       `json:"id"`
	Status       string       `json:"status"`
	Config       AutoConfig   `json:"config"`
	StartedAt    time.Time    `json:"started_at"`
	FinishedAt   time.Time    `json:"finished_at,omitempty"`
	CurrentRoute string       `json:"current_route,omitempty"`
	Actions      []AutoAction `json:"actions"`
	Error        string       `json:"error,omitempty"`
}

type Automation struct {
	operator Operator
	traffic  TrafficFunc

	mu     sync.Mutex
	seq    uint64
	run    *AutoRun
	cancel context.CancelFunc
}

func NewAutomation(operator Operator, traffic TrafficFunc) *Automation {
	return &Automation{operator: operator, traffic: traffic}
}

func (a *Automation) Start(config AutoConfig) (*AutoRun, error) {
	if a.operator == nil {
		return nil, errors.New("mini-program operator is unavailable")
	}
	config = normalizeAutoConfig(config)
	a.mu.Lock()
	if a.run != nil && a.run.Status == "running" {
		running := cloneRun(a.run)
		a.mu.Unlock()
		return running, fmt.Errorf("automation %s is already running", running.ID)
	}
	a.seq++
	ctx, cancel := context.WithCancel(context.Background())
	run := &AutoRun{
		ID:        fmt.Sprintf("wxauto-%d-%d", time.Now().Unix(), a.seq),
		Status:    "running",
		Config:    config,
		StartedAt: time.Now().UTC(),
		Actions:   []AutoAction{},
	}
	a.run = run
	a.cancel = cancel
	copy := cloneRun(run)
	a.mu.Unlock()
	go a.execute(ctx, run.ID)
	return copy, nil
}

func (a *Automation) Stop() *AutoRun {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	if a.run != nil && a.run.Status == "running" {
		a.run.Status = "stopping"
	}
	copy := cloneRun(a.run)
	a.mu.Unlock()
	return copy
}

func (a *Automation) Status() *AutoRun {
	a.mu.Lock()
	defer a.mu.Unlock()
	return cloneRun(a.run)
}

func (a *Automation) execute(ctx context.Context, runID string) {
	visited := map[string]bool{}
	routes := []string{}
	for {
		if ctx.Err() != nil {
			a.finish(runID, "stopped", "")
			return
		}
		run := a.Status()
		if run == nil || run.ID != runID {
			return
		}
		if len(run.Actions) >= run.Config.MaxActions {
			a.finish(runID, "completed", "")
			return
		}
		snapshot, err := a.operator.Snapshot(false)
		if err != nil {
			a.finish(runID, "failed", err.Error())
			return
		}
		a.setRoute(runID, snapshot.Route)
		if len(routes) == 0 {
			routes = append(routes, snapshot.Route)
		} else if snapshot.Route != "" && snapshot.Route != routes[len(routes)-1] {
			routes = append(routes, snapshot.Route)
		}

		candidate, value, kind := chooseCandidate(snapshot, run.Config, visited, len(routes)-1)
		if candidate == nil {
			if len(routes) > 1 {
				before := snapshotTraffic(a.traffic)
				action := AutoAction{Index: len(run.Actions) + 1, Kind: "back", RouteBefore: snapshot.Route, BeforeMaxID: before.maxID, StartedAt: time.Now().UTC()}
				err := a.operator.Back()
				if err == nil {
					err = waitContext(ctx, time.Duration(run.Config.SettleMS)*time.Millisecond)
				}
				afterSnapshot, snapshotErr := a.operator.Snapshot(false)
				if snapshotErr == nil {
					action.RouteAfter = afterSnapshot.Route
				}
				action.Traffic = trafficDiff(before, a.traffic)
				action.FinishedAt = time.Now().UTC()
				if err != nil {
					action.Error = err.Error()
				}
				a.appendAction(runID, action)
				routes = routes[:len(routes)-1]
				continue
			}
			a.finish(runID, "completed", "")
			return
		}

		fingerprint := elementFingerprint(snapshot.Route, *candidate)
		visited[fingerprint] = true
		before := snapshotTraffic(a.traffic)
		elementCopy := *candidate
		action := AutoAction{
			Index:       len(run.Actions) + 1,
			Kind:        kind,
			RouteBefore: snapshot.Route,
			Element:     &elementCopy,
			Value:       value,
			BeforeMaxID: before.maxID,
			StartedAt:   time.Now().UTC(),
		}
		if kind == "input" {
			_, err = a.operator.Input(Locator{ElementID: candidate.ID, Selector: candidate.Selector}, value, true)
		} else {
			_, err = a.operator.Click(Locator{ElementID: candidate.ID, Selector: candidate.Selector, Text: candidate.Text})
		}
		if err == nil {
			err = waitContext(ctx, time.Duration(run.Config.SettleMS)*time.Millisecond)
		}
		afterSnapshot, snapshotErr := a.operator.Snapshot(false)
		if snapshotErr == nil {
			action.RouteAfter = afterSnapshot.Route
		}
		action.Traffic = trafficDiff(before, a.traffic)
		action.FinishedAt = time.Now().UTC()
		if err != nil {
			action.Error = err.Error()
		}
		a.appendAction(runID, action)
	}
}

func chooseCandidate(snapshot *Snapshot, config AutoConfig, visited map[string]bool, depth int) (*Element, string, string) {
	if depth >= config.MaxDepth {
		return nil, "", ""
	}
	elements := append([]Element(nil), snapshot.Elements...)
	sort.SliceStable(elements, func(i, j int) bool {
		if elements[i].Y == elements[j].Y {
			return elements[i].X < elements[j].X
		}
		return elements[i].Y < elements[j].Y
	})
	for i := range elements {
		element := &elements[i]
		if element.Disabled || (!config.IncludeRisky && element.Risk != "") {
			continue
		}
		fingerprint := elementFingerprint(snapshot.Route, *element)
		if visited[fingerprint] {
			continue
		}
		if isInputElement(*element) {
			if value, ok := inputValue(config.InputValues, *element); ok {
				return element, value, "input"
			}
			continue
		}
		if strings.TrimSpace(element.Text+element.Role) == "" {
			continue
		}
		return element, "", "click"
	}
	return nil, "", ""
}

func isInputElement(element Element) bool {
	return element.Tag == "input" || element.Tag == "textarea" || element.Tag == "select" || element.Role == "textbox" || element.Role == "combobox"
}

func inputValue(values map[string]string, element Element) (string, bool) {
	if len(values) == 0 {
		return "", false
	}
	for _, key := range []string{element.ID, element.Name, element.Placeholder, element.Type, "default"} {
		if key != "" {
			if value, ok := values[key]; ok {
				return value, true
			}
		}
	}
	return "", false
}

func elementFingerprint(route string, element Element) string {
	return strings.Join([]string{route, element.Tag, element.Role, element.Type, element.Name, element.Selector, element.Text}, "\x00")
}

type trafficMarker struct {
	maxID uint64
	items map[uint64]trafficState
}

type trafficState struct {
	repeat   int
	lastSeen time.Time
}

func snapshotTraffic(source TrafficFunc) trafficMarker {
	marker := trafficMarker{items: map[uint64]trafficState{}}
	if source == nil {
		return marker
	}
	for _, tx := range source() {
		if tx == nil {
			continue
		}
		if tx.ID > marker.maxID {
			marker.maxID = tx.ID
		}
		marker.items[tx.ID] = trafficState{repeat: tx.RepeatCnt, lastSeen: tx.LastSeen}
	}
	return marker
}

func trafficDiff(before trafficMarker, source TrafficFunc) []TrafficDelta {
	if source == nil {
		return nil
	}
	out := []TrafficDelta{}
	for _, tx := range source() {
		if tx == nil {
			continue
		}
		previous, exists := before.items[tx.ID]
		repeated := exists && (tx.RepeatCnt > previous.repeat || tx.LastSeen.After(previous.lastSeen))
		if exists && !repeated {
			continue
		}
		out = append(out, TrafficDelta{
			ID: tx.ID, Scheme: tx.Scheme, Method: tx.Method, Host: tx.Host,
			Path: tx.Path, Status: tx.Status, MIME: tx.MIME,
			RepeatCount: tx.RepeatCnt, Repeated: repeated,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func normalizeAutoConfig(config AutoConfig) AutoConfig {
	if config.MaxActions <= 0 {
		config.MaxActions = 20
	}
	if config.MaxActions > 200 {
		config.MaxActions = 200
	}
	if config.MaxDepth <= 0 {
		config.MaxDepth = 3
	}
	if config.MaxDepth > 10 {
		config.MaxDepth = 10
	}
	if config.SettleMS <= 0 {
		config.SettleMS = 1500
	}
	if config.SettleMS > 15000 {
		config.SettleMS = 15000
	}
	if config.InputValues == nil {
		config.InputValues = map[string]string{}
	}
	return config
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (a *Automation) setRoute(runID, route string) {
	a.mu.Lock()
	if a.run != nil && a.run.ID == runID {
		a.run.CurrentRoute = route
	}
	a.mu.Unlock()
}

func (a *Automation) appendAction(runID string, action AutoAction) {
	a.mu.Lock()
	if a.run != nil && a.run.ID == runID {
		a.run.Actions = append(a.run.Actions, action)
		a.run.CurrentRoute = action.RouteAfter
	}
	a.mu.Unlock()
}

func (a *Automation) finish(runID, status, message string) {
	a.mu.Lock()
	if a.run != nil && a.run.ID == runID {
		a.run.Status = status
		a.run.Error = message
		a.run.FinishedAt = time.Now().UTC()
		a.cancel = nil
	}
	a.mu.Unlock()
}

func cloneRun(run *AutoRun) *AutoRun {
	if run == nil {
		return nil
	}
	copy := *run
	copy.Config.InputValues = map[string]string{}
	for key, value := range run.Config.InputValues {
		copy.Config.InputValues[key] = value
	}
	copy.Actions = append([]AutoAction(nil), run.Actions...)
	for i := range copy.Actions {
		copy.Actions[i].Traffic = append([]TrafficDelta(nil), run.Actions[i].Traffic...)
		if run.Actions[i].Element != nil {
			elementCopy := *run.Actions[i].Element
			copy.Actions[i].Element = &elementCopy
		}
	}
	return &copy
}
