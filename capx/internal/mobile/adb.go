// Package mobile drives a single Android device over adb. It is the mobile
// counterpart of the desktop wxauto controller: it wires the device's HTTP(S)
// traffic into the capx MITM proxy and performs deterministic UI automation so
// app-side flows can be captured and replayed the same way desktop WeChat is.
//
// The package shells out to the platform adb binary. Traffic decryption still
// happens in the capx proxy; this package only routes the device and drives its
// screen. Capturable HTTP(S) depends on whether the app uses the proxy and
// trusts its CA. UI automation does not decrypt private protocols or bypass
// certificate pinning.
package mobile

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Device is one entry from `adb devices -l`.
type Device struct {
	Serial   string `json:"serial"`
	State    string `json:"state"`
	Model    string `json:"model,omitempty"`
	Platform string `json:"platform,omitempty"`
}

// textRunner runs adb (optionally targeting serial) and returns trimmed
// combined output. bytesRunner returns raw stdout for binary payloads such as
// screenshots. Both are fields so tests can drive the controller without a
// physical device.
type textRunner func(serial string, args ...string) (string, error)
type bytesRunner func(serial string, args ...string) ([]byte, error)

// Controller targets one device. A zero serial means "the only connected
// device"; it is resolved lazily so a controller can outlive hot-plugging.
type Controller struct {
	root      *Controller
	mu        sync.Mutex
	serial    string
	uiMu      sync.Mutex
	captureMu sync.Mutex
	captures  map[string]*captureSession
	run       textRunner
	runBytes  bytesRunner
}

// New builds a controller bound to the real adb binary.
func New() *Controller {
	return &Controller{run: execADBText, runBytes: execADBBytes}
}

// ForDevice binds a request to a device while sharing session ownership and
// operation locks. It does not change the default device selected by Use.
func (c *Controller) ForDevice(serial string) *Controller {
	if serial = strings.TrimSpace(serial); serial == "" {
		return c
	}
	return &Controller{root: c.shared(), serial: serial, run: c.run, runBytes: c.runBytes}
}

func (c *Controller) shared() *Controller {
	if c.root != nil {
		return c.root
	}
	return c
}

// adbPath resolves the adb binary, honoring ADB_PATH then PATH.
func adbPath() string {
	if p := strings.TrimSpace(os.Getenv("ADB_PATH")); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("adb.exe"); err == nil {
			return p
		}
		return "adb.exe"
	}
	if p, err := exec.LookPath("adb"); err == nil {
		return p
	}
	return "adb"
}

func adbArgs(serial string, args ...string) []string {
	if s := strings.TrimSpace(serial); s != "" {
		return append([]string{"-s", s}, args...)
	}
	return args
}

func execADBText(serial string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, adbPath(), adbArgs(serial, args...)...)
	cmd.SysProcAttr = hiddenSysProcAttr()
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	s := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() != nil {
			return s, fmt.Errorf("adb %s: %w", args[0], ctx.Err())
		}
		if s == "" {
			s = err.Error()
		}
		return s, fmt.Errorf("adb %s: %s", strings.Join(args, " "), s)
	}
	return s, nil
}

func execADBBytes(serial string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, adbPath(), adbArgs(serial, args...)...)
	cmd.SysProcAttr = hiddenSysProcAttr()
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("adb %s: %w", args[0], ctx.Err())
		}
		return nil, fmt.Errorf("adb %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// Devices lists all connected devices in the "device" (authorized) or other
// states so the caller can surface unauthorized/offline devices too.
func (c *Controller) Devices() ([]Device, error) {
	out, err := c.run("", "devices", "-l")
	if err != nil {
		return nil, err
	}
	devs := make([]Device, 0)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "list of devices") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			continue // adb daemon startup diagnostics are not devices.
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		d := Device{Serial: fields[0], State: fields[1]}
		for _, f := range fields[2:] {
			if strings.HasPrefix(f, "model:") {
				d.Model = strings.TrimPrefix(f, "model:")
			}
		}
		devs = append(devs, d)
	}
	return devs, nil
}

// Use pins the target serial. An empty value restores auto-selection.
func (c *Controller) Use(serial string) {
	c.mu.Lock()
	c.serial = strings.TrimSpace(serial)
	c.mu.Unlock()
}

// Serial returns the resolved target device, erroring when the choice is
// ambiguous so callers never operate on the wrong phone.
func (c *Controller) Serial() (string, error) {
	c.mu.Lock()
	pinned := c.serial
	c.mu.Unlock()
	if pinned != "" {
		return pinned, nil
	}
	devs, err := c.Devices()
	if err != nil {
		return "", err
	}
	online := make([]Device, 0, len(devs))
	for _, d := range devs {
		if d.State == "device" {
			online = append(online, d)
		}
	}
	switch len(online) {
	case 0:
		return "", fmt.Errorf("没有已授权的 Android 设备；请 USB 连接并在手机上允许调试")
	case 1:
		return online[0].Serial, nil
	default:
		names := make([]string, 0, len(online))
		for _, d := range online {
			names = append(names, d.Serial)
		}
		return "", fmt.Errorf("检测到多个设备，请先指定 serial：%s", strings.Join(names, ", "))
	}
}

func (c *Controller) sh(args ...string) (string, error) {
	c.shared().uiMu.Lock()
	defer c.shared().uiMu.Unlock()
	serial, err := c.Serial()
	if err != nil {
		return "", err
	}
	return c.run(serial, args...)
}
