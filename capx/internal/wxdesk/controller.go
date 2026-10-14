// Package wxdesk controls official Windows WeChat windows. The host client
// runs the published mini-program; this package supplies a local view/control
// surface and never claims to implement a separate WeChat runtime or login.
package wxdesk

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

var ErrUnsupported = errors.New("电脑微信窗口操作仅支持 Windows")

type Window struct {
	ID         string `json:"id"`
	PID        uint32 `json:"pid"`
	Title      string `json:"title"`
	Class      string `json:"class"`
	Process    string `json:"process"`
	Kind       string `json:"kind"`
	Width      int    `json:"width"`
	Height     int    `json:"height"`
	Minimized  bool   `json:"minimized"`
	Foreground bool   `json:"foreground"`
}

type Backend interface {
	Available() bool
	Environment() Environment
	Windows() ([]Window, error)
	Launch() error
	Show(id string) error
	Screenshot(id string) ([]byte, error)
	Tap(id string, x, y, width, height int) error
	Input(id, text string) error
	Key(id, key string) error
	Scroll(id string, delta int) error
}

type Controller struct {
	mu      sync.Mutex
	backend Backend
}

func New() *Controller                           { return &Controller{backend: newBackend()} }
func NewWithBackend(backend Backend) *Controller { return &Controller{backend: backend} }
func (c *Controller) Available() bool            { return c != nil && c.backend != nil && c.backend.Available() }
func (c *Controller) Environment() Environment   { return c.backend.Environment() }

type Environment struct {
	Mode      string `json:"mode"`
	Available bool   `json:"available"`
	Root      string `json:"root,omitempty"`
	Note      string `json:"note"`
}

func boxRoot() string {
	if path := strings.TrimSpace(os.Getenv("CAPX_WECHAT_BOX_DIR")); path != "" {
		return path
	}
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "capx", "isolated-wechat")
}
func (c *Controller) Windows() ([]Window, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backend.Windows()
}
func (c *Controller) Launch() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backend.Launch()
}
func (c *Controller) Show(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backend.Show(id)
}
func (c *Controller) Screenshot(id string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backend.Screenshot(id)
}
func (c *Controller) Tap(id string, x, y, width, height int) error {
	if x < 0 || y < 0 || width <= 0 || height <= 0 || width > 8192 || height > 8192 || x >= width || y >= height {
		return fmt.Errorf("点击坐标或截图尺寸无效")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backend.Tap(id, x, y, width, height)
}
func (c *Controller) Input(id, text string) error {
	if len([]rune(text)) > 2000 || strings.ContainsAny(text, "\r\n\x00") {
		return fmt.Errorf("输入最多 2000 个字符，不能包含换行或 NUL")
	}
	if text == "" {
		return fmt.Errorf("输入内容为空")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backend.Input(id, text)
}
func (c *Controller) Key(id, key string) error {
	key = strings.ToUpper(strings.TrimSpace(key))
	if _, ok := virtualKeys[key]; !ok {
		return fmt.Errorf("不支持的按键 %q", key)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backend.Key(id, key)
}
func (c *Controller) Scroll(id string, delta int) error {
	if delta == 0 || delta < -1200 || delta > 1200 {
		return fmt.Errorf("delta 必须在 -1200 到 1200 之间且不能为 0")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.backend.Scroll(id, delta)
}

var virtualKeys = map[string]uint16{"ESC": 0x1b, "ENTER": 0x0d, "TAB": 0x09, "BACKSPACE": 0x08, "F12": 0x7b,
	"UP": 0x26, "DOWN": 0x28, "LEFT": 0x25, "RIGHT": 0x27, "CTRL_A": 0x41, "CTRL_F": 0x46}

func allowedProcess(path string) bool {
	if installer := strings.TrimSpace(os.Getenv("CAPX_WECHAT_INSTALLER")); installer != "" && strings.EqualFold(filepath.Clean(path), filepath.Clean(installer)) && strings.EqualFold(filepath.Base(path), "WeChatSetup.exe") {
		return true
	}
	switch strings.ToLower(filepath.Base(path)) {
	case "weixin.exe", "wechat.exe", "wechatappex.exe":
		return true
	}
	return false
}

func parseID(id string) (uintptr, uint32, uint64, error) {
	parts := strings.Split(id, ":")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("窗口 ID 无效，请重新选择")
	}
	hwnd, err := strconv.ParseUint(parts[0], 16, strconv.IntSize)
	if err != nil || hwnd == 0 {
		return 0, 0, 0, fmt.Errorf("窗口 ID 无效")
	}
	pid, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil || pid == 0 {
		return 0, 0, 0, fmt.Errorf("窗口进程 ID 无效")
	}
	created, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || created == 0 {
		return 0, 0, 0, fmt.Errorf("窗口进程身份无效")
	}
	return uintptr(hwnd), uint32(pid), created, nil
}
