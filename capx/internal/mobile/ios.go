package mobile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"image/png"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const IOSSerial = "ios-wda"

var wdaSessionRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
var iosBundleRE = regexp.MustCompile(`^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$`)

// IOSController uses an already running, operator-authorized WDA service.
// It neither installs/signs WDA nor changes the phone's proxy or CA trust.
type IOSController struct {
	mu                sync.Mutex
	endpoint, session string
	client            *http.Client
}

type ScreenSize struct {
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

func NewIOS() *IOSController {
	return &IOSController{client: &http.Client{
		Timeout:       25 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("WDA redirects are not supported") },
	}}
}

func normalizeWDAEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("WDA 地址须为 http://127.0.0.1:端口，不含路径、凭据或查询参数")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 || ip == nil || !ip.IsLoopback() {
		return "", errors.New("WDA 须通过本机 loopback 端口转发连接")
	}
	return "http://" + net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
}

type wdaEnvelope struct {
	Value     json.RawMessage `json:"value"`
	SessionID string          `json:"sessionId"`
	Status    int             `json:"status"`
}

func (c *IOSController) call(endpoint, method, route string, body any, dst any) (string, error) {
	var data io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return "", err
		}
		data = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, endpoint+route, data)
	if err != nil {
		return "", errors.New("invalid WDA request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", errors.New("无法连接 WDA；请检查 XCTest、USB 转发、设备授权及签名有效期")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, (32<<20)+1))
	if err != nil || len(raw) > 32<<20 {
		return "", errors.New("WDA response exceeds limit or cannot be read")
	}
	var result wdaEnvelope
	if json.Unmarshal(raw, &result) != nil {
		return "", errors.New("WDA 未返回有效的 WebDriver JSON")
	}
	var failure struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(result.Value, &failure)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || result.Status != 0 || failure.Error != "" {
		return "", fmt.Errorf("WDA 请求失败 (HTTP %d, %s)；会话失效时请重新连接", resp.StatusCode, failure.Error)
	}
	if dst != nil && json.Unmarshal(result.Value, dst) != nil {
		return "", errors.New("WDA response has an unexpected value")
	}
	return result.SessionID, nil
}

// Connect first reuses the active WDA session. A new session is created only
// when none exists; connecting does not launch an app or terminate an existing one.
func (c *IOSController) Connect(raw, session string) (map[string]any, error) {
	endpoint, err := normalizeWDAEndpoint(raw)
	if err != nil {
		return nil, err
	}
	session = strings.TrimSpace(session)
	if session != "" && !wdaSessionRE.MatchString(session) {
		return nil, errors.New("无效的 WDA 会话 ID")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.endpoint != "" && (c.endpoint != endpoint || (session != "" && c.session != session)) {
		return nil, errors.New("请先断开当前 WDA，再切换控制服务或会话")
	}
	var status struct {
		Ready bool `json:"ready"`
	}
	if _, err := c.call(endpoint, "GET", "/status", nil, &status); err != nil {
		return nil, err
	}
	if !status.Ready {
		return nil, errors.New("WDA 尚未就绪，请完成手机上的 UI 自动化授权")
	}
	if session == "" {
		var active struct {
			SessionID string `json:"sessionId"`
		}
		topID, err := c.call(endpoint, "GET", "/session", nil, &active)
		if err != nil {
			return nil, err
		}
		session = active.SessionID
		if session == "" {
			session = topID
		}
	}
	if session == "" {
		var created struct {
			SessionID string `json:"sessionId"`
		}
		topID, err := c.call(endpoint, "POST", "/session", map[string]any{"capabilities": map[string]any{"alwaysMatch": map[string]any{"shouldTerminateApp": false, "defaultActiveApplication": "auto", "waitForIdleTimeout": 0}}}, &created)
		if err != nil {
			return nil, err
		}
		session = created.SessionID
		if session == "" {
			session = topID
		}
	}
	if !wdaSessionRE.MatchString(session) {
		return nil, errors.New("WDA 没有返回可用会话")
	}
	if _, err := c.size(endpoint, session); err != nil {
		return nil, err
	}
	if _, err := c.call(endpoint, "POST", "/session/"+url.PathEscape(session)+"/appium/settings", map[string]any{"settings": map[string]any{"defaultActiveApplication": "auto", "waitForIdleTimeout": 0}}, nil); err != nil {
		return nil, err
	}
	c.endpoint, c.session = endpoint, session
	return c.statusLocked()
}

// Disconnect relinquishes Capx's connection without terminating XCTest or apps.
func (c *IOSController) Disconnect() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.endpoint, c.session = "", ""
}

func (c *IOSController) configured() error {
	if c.endpoint == "" || c.session == "" {
		return errors.New("请先连接已授权的 iOS WDA 控制服务")
	}
	return nil
}

func (c *IOSController) route(path string) string {
	return "/session/" + url.PathEscape(c.session) + path
}

func (c *IOSController) size(endpoint, session string) (ScreenSize, error) {
	var size ScreenSize
	_, err := c.call(endpoint, "GET", "/session/"+url.PathEscape(session)+"/window/size", nil, &size)
	if err != nil {
		return size, err
	}
	if size.Width <= 0 || size.Height <= 0 || math.IsNaN(size.Width) || math.IsNaN(size.Height) || math.IsInf(size.Width, 0) || math.IsInf(size.Height, 0) {
		return size, errors.New("WDA 屏幕坐标尺寸无效")
	}
	return size, nil
}

func (c *IOSController) statusLocked() (map[string]any, error) {
	if err := c.configured(); err != nil {
		return nil, err
	}
	size, err := c.size(c.endpoint, c.session)
	if err != nil {
		return nil, err
	}
	return map[string]any{"serial": IOSSerial, "platform": "ios", "wda_connected": true, "wda_endpoint": c.endpoint, "screen": size, "coordinate_space": "points", "supports_unicode": true, "supports_back": false, "managed": false, "wired": false,
		"ca_note": "iPhone 抓包使用 Wi-Fi 代理，并在系统设置中安装 CA、开启完全信任；WDA 操作授权不包含证书信任"}, nil
}

func (c *IOSController) Status() (map[string]any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.statusLocked()
}

func (c *IOSController) Devices() ([]Device, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.endpoint == "" {
		return []Device{}, nil
	}
	state := "device"
	if _, err := c.statusLocked(); err != nil {
		state = "offline"
	}
	return []Device{{Serial: IOSSerial, State: state, Model: "iPhone / WDA", Platform: "ios"}}, nil
}

// ScreenshotWithSize returns the unmodified PNG and UIKit points for the UI.
func (c *IOSController) ScreenshotWithSize() ([]byte, ScreenSize, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.configured(); err != nil {
		return nil, ScreenSize{}, err
	}
	size, err := c.size(c.endpoint, c.session)
	if err != nil {
		return nil, size, err
	}
	var encoded string
	if _, err := c.call(c.endpoint, "GET", c.route("/screenshot"), nil, &encoded); err != nil {
		return nil, size, err
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, size, errors.New("WDA screenshot is not base64")
	}
	config, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, size, errors.New("WDA screenshot is not a PNG")
	}
	if math.Abs(float64(config.Width)/float64(config.Height)/(size.Width/size.Height)-1) > .02 {
		return nil, size, errors.New("iOS 屏幕方向已变化，请重新截图后操作")
	}
	return data, size, nil
}

func (c *IOSController) Screenshot() ([]byte, error) {
	data, _, err := c.ScreenshotWithSize()
	return data, err
}

func (c *IOSController) command(path string, body any) error {
	if err := c.configured(); err != nil {
		return err
	}
	_, err := c.call(c.endpoint, "POST", c.route(path), body, nil)
	return err
}

func (c *IOSController) Tap(x, y int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if x < 0 || y < 0 {
		return errors.New("点击坐标不能为负数")
	}
	if err := c.configured(); err != nil {
		return err
	}
	size, err := c.size(c.endpoint, c.session)
	if err != nil {
		return err
	}
	if float64(x) >= size.Width || float64(y) >= size.Height {
		return errors.New("iOS 点击坐标超出屏幕；请使用 points，截图像素需要按比例换算")
	}
	return c.command("/wda/tap", map[string]int{"x": x, "y": y})
}

func (c *IOSController) Input(text string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.command("/wda/keys", map[string]any{"value": []string{text}})
}

func (c *IOSController) Swipe(x1, y1, x2, y2, durationMS int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if x1 < 0 || y1 < 0 || x2 < 0 || y2 < 0 || durationMS < 0 || durationMS > 10000 {
		return errors.New("无效滑动坐标或 duration_ms")
	}
	if err := c.configured(); err != nil {
		return err
	}
	size, err := c.size(c.endpoint, c.session)
	if err != nil {
		return err
	}
	if float64(x1) >= size.Width || float64(x2) >= size.Width || float64(y1) >= size.Height || float64(y2) >= size.Height {
		return errors.New("iOS 滑动坐标超出屏幕 points 范围")
	}
	if durationMS == 0 {
		durationMS = 300
	}
	return c.command("/wda/dragfromtoforduration", map[string]any{"fromX": x1, "fromY": y1, "toX": x2, "toY": y2, "duration": float64(durationMS) / 1000})
}

func (c *IOSController) Home() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.configured(); err != nil {
		return err
	}
	if _, err := c.size(c.endpoint, c.session); err != nil {
		return err
	}
	_, err := c.call(c.endpoint, "POST", "/wda/homescreen", map[string]any{}, nil)
	return err
}

func (c *IOSController) Back() error {
	return errors.New("iOS 没有通用返回键；请点击页面返回按钮或使用滑动")
}
func (c *IOSController) Key(code string) error {
	switch strings.TrimSpace(code) {
	case "KEYCODE_HOME", "HOME", "3":
		return c.Home()
	case "KEYCODE_ENTER", "ENTER", "66":
		return c.Input("\n")
	case "KEYCODE_DEL", "DEL", "67":
		return c.Input("\b")
	default:
		return errors.New("iOS 按键仅支持 HOME、ENTER 和 DEL")
	}
}

func (c *IOSController) LaunchApp(bundle string) error {
	if !iosBundleRE.MatchString(strings.TrimSpace(bundle)) {
		return errors.New("无效的 iOS bundle ID")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.command("/wda/apps/launch", map[string]any{"bundleId": strings.TrimSpace(bundle), "shouldWaitForQuiescence": false})
}

func (c *IOSController) ForegroundApp() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.configured(); err != nil {
		return "", err
	}
	if _, err := c.size(c.endpoint, c.session); err != nil {
		return "", err
	}
	var app struct {
		Bundle string `json:"bundleId"`
	}
	_, err := c.call(c.endpoint, "GET", "/wda/activeAppInfo", nil, &app)
	return app.Bundle, err
}

// WDA XML uses UIKit points and accessibility identifiers rather than Android IDs.
type iosNode struct {
	XMLName  xml.Name
	Type     string    `xml:"type,attr"`
	Name     string    `xml:"name,attr"`
	Label    string    `xml:"label,attr"`
	Value    string    `xml:"value,attr"`
	Visible  string    `xml:"visible,attr"`
	Enabled  string    `xml:"enabled,attr"`
	X        float64   `xml:"x,attr"`
	Y        float64   `xml:"y,attr"`
	Width    float64   `xml:"width,attr"`
	Height   float64   `xml:"height,attr"`
	Children []iosNode `xml:",any"`
}

func (c *IOSController) snapshotLocked() (SnapshotInfo, error) {
	if err := c.configured(); err != nil {
		return SnapshotInfo{}, err
	}
	var source string
	if _, err := c.call(c.endpoint, "GET", c.route("/source?format=xml"), nil, &source); err != nil {
		return SnapshotInfo{}, err
	}
	var root iosNode
	if err := xml.Unmarshal([]byte(source), &root); err != nil {
		return SnapshotInfo{}, errors.New("WDA 元素树不是有效 XML")
	}
	els := []Element{}
	var visit func(iosNode)
	visit = func(n iosNode) {
		if n.Width > 0 && n.Height > 0 && n.Visible != "false" && n.Enabled != "false" && (n.Name != "" || n.Label != "" || n.Value != "") {
			text := n.Label
			if text == "" {
				text = n.Value
			}
			els = append(els, Element{Index: len(els), Class: n.Type, ResourceID: n.Name, Text: text, Desc: n.Label, Clickable: true,
				X: int(n.X + n.Width/2), Y: int(n.Y + n.Height/2), Width: int(n.Width), Height: int(n.Height)})
		}
		if n.Visible != "false" {
			for _, child := range n.Children {
				visit(child)
			}
		}
	}
	visit(root)
	return SnapshotInfo{Elements: els, Source: "wda", SupportsText: true, BoundsAccurate: true, Note: "iOS 坐标单位为 points；resource_id 对应 accessibility name"}, nil
}

func (c *IOSController) SnapshotWithInfo() (SnapshotInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.snapshotLocked()
}

func (c *IOSController) Click(loc Locator) (Element, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if loc.empty() {
		return Element{}, errors.New("需要 text、resource_id 或 content_desc 之一")
	}
	snapshot, err := c.snapshotLocked()
	if err != nil {
		return Element{}, err
	}
	for _, el := range snapshot.Elements {
		match := func(want, got string) bool {
			want = strings.TrimSpace(want)
			return want == "" || got == want || (loc.Partial && strings.Contains(got, want))
		}
		if match(loc.Text, el.Text) && match(loc.Desc, el.Desc) && (strings.TrimSpace(loc.ResourceID) == "" || strings.TrimSpace(loc.ResourceID) == el.ResourceID) {
			return el, c.command("/wda/tap", map[string]int{"x": el.X, "y": el.Y})
		}
	}
	return Element{}, errors.New("未找到匹配的 iOS 元素")
}
