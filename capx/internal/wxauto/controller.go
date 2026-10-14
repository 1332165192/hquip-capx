package wxauto

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

//go:embed snapshot.js
var snapshotExpression string

type CallFunc func(method string, params any, timeout time.Duration) (json.RawMessage, error)

type Controller struct {
	call CallFunc
}

type Rect struct {
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type Element struct {
	ID          string  `json:"id"`
	Tag         string  `json:"tag"`
	Role        string  `json:"role,omitempty"`
	Type        string  `json:"type,omitempty"`
	Name        string  `json:"name,omitempty"`
	Text        string  `json:"text,omitempty"`
	Placeholder string  `json:"placeholder,omitempty"`
	Selector    string  `json:"selector,omitempty"`
	Disabled    bool    `json:"disabled"`
	Risk        string  `json:"risk,omitempty"`
	X           float64 `json:"x"`
	Y           float64 `json:"y"`
	Width       float64 `json:"width"`
	Height      float64 `json:"height"`
}

type Viewport struct {
	Width   float64 `json:"width"`
	Height  float64 `json:"height"`
	ScrollX float64 `json:"scroll_x"`
	ScrollY float64 `json:"scroll_y"`
}

type Snapshot struct {
	Route      string    `json:"route"`
	URL        string    `json:"url"`
	Title      string    `json:"title"`
	Viewport   Viewport  `json:"viewport"`
	Elements   []Element `json:"elements"`
	Screenshot string    `json:"screenshot_base64,omitempty"`
	CapturedAt time.Time `json:"captured_at"`
}

type Locator struct {
	ElementID string `json:"element_id,omitempty"`
	Selector  string `json:"selector,omitempty"`
	Text      string `json:"text,omitempty"`
}

type locateResult struct {
	Found bool   `json:"found"`
	Text  string `json:"text"`
	Tag   string `json:"tag"`
	Rect  Rect   `json:"rect"`
}

func NewController(call CallFunc) *Controller { return &Controller{call: call} }

func (c *Controller) Snapshot(withScreenshot bool) (*Snapshot, error) {
	var snapshot Snapshot
	if err := c.evaluateValue(snapshotExpression, &snapshot); err != nil {
		return nil, err
	}
	for i := range snapshot.Elements {
		snapshot.Elements[i].Risk = classifyRisk(snapshot.Elements[i])
	}
	snapshot.CapturedAt = time.Now().UTC()
	if withScreenshot {
		image, err := c.Screenshot()
		if err != nil {
			return nil, err
		}
		snapshot.Screenshot = image
	}
	return &snapshot, nil
}

func (c *Controller) Screenshot() (string, error) {
	raw, err := c.call("Page.captureScreenshot", map[string]any{
		"format":                "png",
		"fromSurface":           true,
		"captureBeyondViewport": false,
	}, 12*time.Second)
	if err != nil {
		return "", err
	}
	var envelope struct {
		Error  *cdpError `json:"error"`
		Result struct {
			Data string `json:"data"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return "", err
	}
	if envelope.Error != nil {
		return "", envelope.Error
	}
	if envelope.Result.Data == "" {
		return "", errors.New("CDP screenshot returned empty data")
	}
	return envelope.Result.Data, nil
}

func (c *Controller) Click(locator Locator) (*locateResult, error) {
	found, err := c.locate(locator, true)
	if err != nil {
		return nil, err
	}
	x := found.Rect.X + found.Rect.Width/2
	y := found.Rect.Y + found.Rect.Height/2
	common := map[string]any{"x": x, "y": y, "button": "left", "clickCount": 1}
	pressed := cloneMap(common)
	pressed["type"] = "mousePressed"
	if _, err := c.call("Input.dispatchMouseEvent", pressed, 5*time.Second); err != nil {
		return nil, err
	}
	released := cloneMap(common)
	released["type"] = "mouseReleased"
	if _, err := c.call("Input.dispatchMouseEvent", released, 5*time.Second); err != nil {
		return nil, err
	}
	return found, nil
}

func (c *Controller) Input(locator Locator, value string, clear bool) (*locateResult, error) {
	query, _ := json.Marshal(locator)
	text, _ := json.Marshal(value)
	expression := fmt.Sprintf(`(function(q,value,clear){
var all=[],seen=new Set();function walk(root){if(!root||!root.querySelectorAll)return;var ns=root.querySelectorAll('*');for(var i=0;i<ns.length;i++){var n=ns[i];if(!seen.has(n)){seen.add(n);all.push(n);}if(n.shadowRoot)walk(n.shadowRoot);}}walk(document);
var el=null;if(q.element_id){el=all.find(function(n){return n.getAttribute&&n.getAttribute('data-capx-auto-id')===q.element_id;});}if(!el&&q.selector){try{el=document.querySelector(q.selector);}catch(e){}}if(!el&&q.text){el=all.find(function(n){return String(n.innerText||n.value||n.getAttribute('aria-label')||'').trim().indexOf(q.text)>=0;});}if(!el)return {found:false};
el.scrollIntoView({block:'center',inline:'center'});el.focus();if(clear&&typeof el.select==='function')el.select();
var proto=Object.getPrototypeOf(el),desc=proto&&Object.getOwnPropertyDescriptor(proto,'value');if(desc&&desc.set)desc.set.call(el,value);else el.value=value;
el.dispatchEvent(new Event('input',{bubbles:true}));el.dispatchEvent(new Event('change',{bubbles:true}));var r=el.getBoundingClientRect();return {found:true,text:String(el.value||''),tag:el.tagName.toLowerCase(),rect:{x:r.x,y:r.y,width:r.width,height:r.height}};})(%s,%s,%t)`, string(query), string(text), clear)
	var result locateResult
	if err := c.evaluateValue(expression, &result); err != nil {
		return nil, err
	}
	if !result.Found {
		return nil, errors.New("mini-program input element not found")
	}
	return &result, nil
}

func (c *Controller) Scroll(deltaX, deltaY float64) error {
	_, err := c.call("Input.dispatchMouseEvent", map[string]any{
		"type":   "mouseWheel",
		"x":      1,
		"y":      1,
		"deltaX": deltaX,
		"deltaY": deltaY,
	}, 5*time.Second)
	return err
}

func (c *Controller) Back() error {
	var result string
	return c.evaluateValue(`(function(){try{if(typeof wx!=='undefined'&&wx.navigateBack){wx.navigateBack({delta:1});return 'wx.navigateBack';}history.back();return 'history.back';}catch(e){return String(e);}})()`, &result)
}

func (c *Controller) locate(locator Locator, scroll bool) (*locateResult, error) {
	query, _ := json.Marshal(locator)
	expression := fmt.Sprintf(`(function(q,scroll){var all=[],seen=new Set();function walk(root){if(!root||!root.querySelectorAll)return;var ns=root.querySelectorAll('*');for(var i=0;i<ns.length;i++){var n=ns[i];if(!seen.has(n)){seen.add(n);all.push(n);}if(n.shadowRoot)walk(n.shadowRoot);}}walk(document);var el=null;if(q.element_id){el=all.find(function(n){return n.getAttribute&&n.getAttribute('data-capx-auto-id')===q.element_id;});}if(!el&&q.selector){try{el=document.querySelector(q.selector);}catch(e){}}if(!el&&q.text){el=all.find(function(n){return String(n.innerText||n.value||n.getAttribute('aria-label')||'').trim().indexOf(q.text)>=0;});}if(!el)return {found:false};if(scroll)el.scrollIntoView({block:'center',inline:'center'});el.focus();var r=el.getBoundingClientRect();return {found:true,text:String(el.innerText||el.value||''),tag:el.tagName.toLowerCase(),rect:{x:r.x,y:r.y,width:r.width,height:r.height}};})(%s,%t)`, string(query), scroll)
	var result locateResult
	if err := c.evaluateValue(expression, &result); err != nil {
		return nil, err
	}
	if !result.Found || result.Rect.Width <= 0 || result.Rect.Height <= 0 {
		return nil, errors.New("mini-program element not found or hidden")
	}
	return &result, nil
}

type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *cdpError) Error() string { return fmt.Sprintf("CDP %d: %s", e.Code, e.Message) }

func (c *Controller) evaluateValue(expression string, dst any) error {
	raw, err := c.call("Runtime.evaluate", map[string]any{
		"expression":    expression,
		"returnByValue": true,
		"awaitPromise":  true,
		"userGesture":   true,
	}, 10*time.Second)
	if err != nil {
		return err
	}
	var envelope struct {
		Error  *cdpError `json:"error"`
		Result struct {
			Result struct {
				Value json.RawMessage `json:"value"`
			} `json:"result"`
			Exception json.RawMessage `json:"exceptionDetails"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("decode CDP response: %w", err)
	}
	if envelope.Error != nil {
		return envelope.Error
	}
	if len(envelope.Result.Exception) > 0 && string(envelope.Result.Exception) != "null" {
		return fmt.Errorf("CDP runtime exception: %s", envelope.Result.Exception)
	}
	if len(envelope.Result.Result.Value) == 0 {
		return errors.New("CDP Runtime.evaluate returned no value")
	}
	if err := json.Unmarshal(envelope.Result.Result.Value, dst); err != nil {
		return fmt.Errorf("decode runtime value: %w", err)
	}
	return nil
}

func classifyRisk(element Element) string {
	text := strings.ToLower(strings.TrimSpace(element.Text + " " + element.Placeholder))
	for _, word := range []string{"支付", "付款", "购买", "下单", "充值", "转账", "提现", "删除", "注销", "解绑", "退出登录", "授权", "订阅"} {
		if strings.Contains(text, word) {
			return word
		}
	}
	return ""
}

func cloneMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src)+1)
	for key, value := range src {
		out[key] = value
	}
	return out
}
