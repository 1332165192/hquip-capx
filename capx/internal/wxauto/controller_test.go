package wxauto

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func runtimeResponse(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return json.RawMessage(fmt.Sprintf(`{"id":1,"result":{"result":{"type":"object","value":%s}}}`, data))
}

func TestControllerSnapshotAndRiskClassification(t *testing.T) {
	controller := NewController(func(method string, params any, timeout time.Duration) (json.RawMessage, error) {
		if method != "Runtime.evaluate" {
			t.Fatalf("method = %s", method)
		}
		return runtimeResponse(map[string]any{
			"route": "pages/index", "url": "https://mini.test/", "title": "Demo",
			"viewport": map[string]any{"width": 375, "height": 667},
			"elements": []map[string]any{{"id": "wx-1", "tag": "button", "text": "立即支付", "width": 80, "height": 30}},
		}), nil
	})
	snapshot, err := controller.Snapshot(false)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Route != "pages/index" || len(snapshot.Elements) != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
	if snapshot.Elements[0].Risk != "支付" {
		t.Fatalf("risk = %q", snapshot.Elements[0].Risk)
	}
}

func TestControllerClickDispatchesMouseEvents(t *testing.T) {
	methods := []string{}
	controller := NewController(func(method string, params any, timeout time.Duration) (json.RawMessage, error) {
		methods = append(methods, method)
		if method == "Runtime.evaluate" {
			return runtimeResponse(map[string]any{"found": true, "tag": "button", "text": "查询", "rect": map[string]any{"x": 10, "y": 20, "width": 100, "height": 40}}), nil
		}
		data, _ := json.Marshal(map[string]any{"id": len(methods), "result": map[string]any{}})
		return data, nil
	})
	result, err := controller.Click(Locator{ElementID: "wx-2"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Found || result.Text != "查询" {
		t.Fatalf("result = %+v", result)
	}
	want := []string{"Runtime.evaluate", "Input.dispatchMouseEvent", "Input.dispatchMouseEvent"}
	if fmt.Sprint(methods) != fmt.Sprint(want) {
		t.Fatalf("methods = %v", methods)
	}
}

func TestControllerScreenshot(t *testing.T) {
	controller := NewController(func(method string, params any, timeout time.Duration) (json.RawMessage, error) {
		return json.RawMessage(`{"id":1,"result":{"data":"iVBORw0KGgo="}}`), nil
	})
	image, err := controller.Screenshot()
	if err != nil {
		t.Fatal(err)
	}
	if image != "iVBORw0KGgo=" {
		t.Fatalf("image = %q", image)
	}
}

func TestAllowedRiskDefaults(t *testing.T) {
	snapshot := &Snapshot{Route: "pages/order", Elements: []Element{
		{ID: "pay", Tag: "button", Text: "立即支付", Risk: "支付"},
		{ID: "query", Tag: "button", Text: "查询订单"},
	}}
	visited := map[string]bool{}
	element, _, _ := chooseCandidate(snapshot, normalizeAutoConfig(AutoConfig{}), visited, 0)
	if element == nil || element.ID != "query" {
		t.Fatalf("candidate = %+v", element)
	}
}
