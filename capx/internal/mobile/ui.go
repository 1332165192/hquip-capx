package mobile

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ErrUIDumpBlocked means both hierarchy sources failed. Failure alone does not
// establish a ROM/module issue: disconnected or locked devices can also fail.
var ErrUIDumpBlocked = errors.New("无法获取元素树（uiautomator 与 dumpsys 均失败）；请检查设备连接、屏幕和 UiAutomation 占用，或使用截图+坐标点击")

// SnapshotInfo keeps the source's limitations visible to API consumers.
type SnapshotInfo struct {
	Elements       []Element `json:"elements"`
	Source         string    `json:"source"`
	Degraded       bool      `json:"degraded"`
	SupportsText   bool      `json:"supports_text"`
	BoundsAccurate bool      `json:"bounds_accurate"`
	Note           string    `json:"note,omitempty"`
}

var dumpSequence atomic.Uint64

func (c *Controller) dumpForSerial(serial string, interactableOnly bool) (SnapshotInfo, error) {
	full := func(data []byte) (SnapshotInfo, error) {
		els, err := parseUIDump(stripDumpNoise(data), interactableOnly)
		return SnapshotInfo{Elements: els, Source: "uiautomator", SupportsText: true, BoundsAccurate: true}, err
	}
	// Fast path: dump straight to stdout.
	if out, err := c.runBytes(serial, "exec-out", "uiautomator", "dump", "/dev/tty"); err == nil {
		if snapshot, perr := full(out); perr == nil {
			return snapshot, nil
		}
	}
	// Portable path: dump to a file, then read it back.
	// Unique paths prevent stale or cross-instance dumps from being read.
	remote := fmt.Sprintf("/data/local/tmp/capx-ui-%d-%d-%d.xml", os.Getpid(), time.Now().UnixNano(), dumpSequence.Add(1))
	defer c.run(serial, "shell", "rm", "-f", remote)
	if _, err := c.run(serial, "shell", "uiautomator", "dump", remote); err == nil {
		if data, derr := c.runBytes(serial, "exec-out", "cat", remote); derr == nil {
			if snapshot, perr := full(data); perr == nil {
				return snapshot, nil
			}
		}
	}
	// Fallback does not register a UiAutomation service. It provides native
	// view IDs and approximate bounds, with no text/content descriptions.
	if data, err := c.runBytes(serial, "exec-out", "dumpsys", "activity", "top"); err == nil {
		if els := parseDumpsysTop(data, interactableOnly); len(els) > 0 {
			return SnapshotInfo{Elements: els, Source: "dumpsys", Degraded: true,
				Note: "仅提供原生视图和 resource_id；无文字/描述，滚动、窗口偏移和变换可能影响坐标，请结合截图核对"}, nil
		}
	}
	return SnapshotInfo{}, ErrUIDumpBlocked
}

// stripDumpNoise removes the "UI hierchary dumped to: ..." trailer some devices
// append after the XML, which would otherwise break the parser.
func stripDumpNoise(b []byte) []byte {
	s := string(b)
	if i := strings.Index(s, "<?xml"); i >= 0 {
		s = s[i:]
	} else if i := strings.Index(s, "<hierarchy"); i >= 0 {
		s = s[i:]
	}
	if i := strings.LastIndex(s, "</hierarchy>"); i >= 0 {
		return []byte(s[:i+len("</hierarchy>")])
	}
	return []byte(s)
}

// Snapshot returns the interactable elements on the current screen.
func (c *Controller) Snapshot() ([]Element, error) {
	snapshot, err := c.SnapshotWithInfo()
	return snapshot.Elements, err
}

func (c *Controller) SnapshotWithInfo() (SnapshotInfo, error) {
	c.shared().uiMu.Lock()
	defer c.shared().uiMu.Unlock()
	serial, err := c.Serial()
	if err != nil {
		return SnapshotInfo{}, err
	}
	return c.dumpForSerial(serial, true)
}

// Screenshot returns a PNG of the current screen.
func (c *Controller) Screenshot() ([]byte, error) {
	serial, err := c.Serial()
	if err != nil {
		return nil, err
	}
	return c.runBytes(serial, "exec-out", "screencap", "-p")
}

// Tap taps absolute screen coordinates.
func (c *Controller) Tap(x, y int) error {
	if x < 0 || y < 0 {
		return fmt.Errorf("点击坐标不能为负数")
	}
	_, err := c.sh("shell", "input", "tap", strconv.Itoa(x), strconv.Itoa(y))
	return err
}

// Click finds the first element matching the locator and taps its center.
func (c *Controller) Click(loc Locator) (Element, error) {
	if loc.empty() {
		return Element{}, fmt.Errorf("需要 text、resource_id 或 content_desc 之一")
	}
	c.shared().uiMu.Lock()
	defer c.shared().uiMu.Unlock()
	serial, err := c.Serial()
	if err != nil {
		return Element{}, err
	}
	snapshot, err := c.dumpForSerial(serial, false)
	if err != nil {
		return Element{}, err
	}
	if !snapshot.SupportsText && (strings.TrimSpace(loc.Text) != "" || strings.TrimSpace(loc.Desc) != "") {
		return Element{}, fmt.Errorf("当前 dumpsys 回退不支持文字或描述定位，请使用 resource_id 或截图坐标")
	}
	for _, e := range snapshot.Elements {
		if e.Width <= 0 || e.Height <= 0 {
			continue
		}
		if loc.matches(e) {
			_, err := c.run(serial, "shell", "input", "tap", strconv.Itoa(e.X), strconv.Itoa(e.Y))
			return e, err
		}
	}
	return Element{}, fmt.Errorf("未找到匹配元素")
}

// Input types text into the focused field. It does not focus a field itself;
// click the target first. Android's stock input command only reliably supports
// printable ASCII. Unicode requires an IME/instrumentation backend.
func (c *Controller) Input(text string) error {
	for _, r := range text {
		if r < 32 || r > 126 {
			return fmt.Errorf("原生 adb input 仅支持可打印 ASCII；中文或控制字符需使用输入法或 Appium 后端")
		}
	}
	if text == "" {
		return nil
	}
	c.shared().uiMu.Lock()
	defer c.shared().uiMu.Unlock()
	serial, err := c.Serial()
	if err != nil {
		return err
	}
	for text != "" {
		chunk := text
		text = ""
		// input interprets %s as a space. Split a literal %s across calls.
		if i := strings.Index(chunk, "%s"); i >= 0 {
			text, chunk = chunk[i+1:], chunk[:i+1]
		}
		escaped := strings.ReplaceAll(chunk, " ", "%s")
		if _, err := c.run(serial, "shell", "input", "text", shellQuote(escaped)); err != nil {
			return err
		}
	}
	return nil
}

// adb joins shell arguments into a command on the device; host-side exec
// argument separation alone does not protect remote shell metacharacters.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

// Swipe drags between two points over durationMS milliseconds.
func (c *Controller) Swipe(x1, y1, x2, y2, durationMS int) error {
	if x1 < 0 || y1 < 0 || x2 < 0 || y2 < 0 || durationMS < 0 || durationMS > 10000 {
		return fmt.Errorf("滑动坐标不能为负数，duration_ms 必须在 0 到 10000 之间")
	}
	if durationMS <= 0 {
		durationMS = 300
	}
	_, err := c.sh("shell", "input", "swipe",
		strconv.Itoa(x1), strconv.Itoa(y1), strconv.Itoa(x2), strconv.Itoa(y2), strconv.Itoa(durationMS))
	return err
}

// Key sends an Android keyevent (name like "KEYCODE_ENTER" or a numeric code).
func (c *Controller) Key(code string) error {
	code = strings.TrimSpace(code)
	if !keyCodeRE.MatchString(code) {
		return fmt.Errorf("keycode 必须是数字或 KEYCODE_ 名称")
	}
	_, err := c.sh("shell", "input", "keyevent", code)
	return err
}

var keyCodeRE = regexp.MustCompile(`^(?:[0-9]+|(?:KEYCODE_)?[A-Z][A-Z0-9_]*)$`)
var packageRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$`)

// Back and Home are convenience keyevents.
func (c *Controller) Back() error { return c.Key("KEYCODE_BACK") }
func (c *Controller) Home() error { return c.Key("KEYCODE_HOME") }

// LaunchApp starts an app's default launcher activity by package name.
func (c *Controller) LaunchApp(pkg string) error {
	pkg = strings.TrimSpace(pkg)
	if !packageRE.MatchString(pkg) {
		return fmt.Errorf("package 名称无效")
	}
	out, err := c.sh("shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1")
	if err != nil {
		return fmt.Errorf("启动 %s 失败: %s", pkg, out)
	}
	return nil
}

// ForegroundApp returns the package currently in the foreground.
func (c *Controller) ForegroundApp() (string, error) {
	out, err := c.sh("shell", "dumpsys", "activity", "activities")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ResumedActivity") || strings.Contains(line, "mResumedActivity") {
			if i := strings.Index(line, "{"); i >= 0 {
				fields := strings.Fields(line[i:])
				for _, f := range fields {
					if strings.Contains(f, "/") {
						return strings.SplitN(f, "/", 2)[0], nil
					}
				}
			}
		}
	}
	return "", nil
}
