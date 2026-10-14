//go:build windows

package wxdesk

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

var user32 = windows.NewLazySystemDLL("user32.dll")
var gdi32 = windows.NewLazySystemDLL("gdi32.dll")
var enumWindows = user32.NewProc("EnumWindows")
var isVisible = user32.NewProc("IsWindowVisible")
var getPID = user32.NewProc("GetWindowThreadProcessId")
var getTitle = user32.NewProc("GetWindowTextW")
var getClass = user32.NewProc("GetClassNameW")
var getRect = user32.NewProc("GetClientRect")
var getWindowRect = user32.NewProc("GetWindowRect")
var monitorFromWindow = user32.NewProc("MonitorFromWindow")
var getMonitorInfo = user32.NewProc("GetMonitorInfoW")
var setWindowPos = user32.NewProc("SetWindowPos")
var isIconic = user32.NewProc("IsIconic")
var getForeground = user32.NewProc("GetForegroundWindow")
var setForeground = user32.NewProc("SetForegroundWindow")
var attachThreadInput = user32.NewProc("AttachThreadInput")
var setThreadDPI = user32.NewProc("SetThreadDpiAwarenessContext")
var showWindow = user32.NewProc("ShowWindow")
var clientToScreen = user32.NewProc("ClientToScreen")
var windowFromPoint = user32.NewProc("WindowFromPoint")
var getAncestor = user32.NewProc("GetAncestor")
var isHung = user32.NewProc("IsHungAppWindow")
var getDC = user32.NewProc("GetDC")
var releaseDC = user32.NewProc("ReleaseDC")
var sendInput = user32.NewProc("SendInput")
var setCursorPos = user32.NewProc("SetCursorPos")
var getCursorPos = user32.NewProc("GetCursorPos")
var getSystemMetrics = user32.NewProc("GetSystemMetrics")
var createDC = gdi32.NewProc("CreateCompatibleDC")
var deleteDC = gdi32.NewProc("DeleteDC")
var createBitmap = gdi32.NewProc("CreateCompatibleBitmap")
var deleteObject = gdi32.NewProc("DeleteObject")
var selectObject = gdi32.NewProc("SelectObject")
var getDIBits = gdi32.NewProc("GetDIBits")
var bitBlt = gdi32.NewProc("BitBlt")

type nativeBackend struct{}
type rect struct{ Left, Top, Right, Bottom int32 }
type point struct{ X, Y int32 }
type monitorInfo struct {
	Size          uint32
	Monitor, Work rect
	Flags         uint32
}

func nativeThread() func() {
	runtime.LockOSThread()
	previous, _, _ := setThreadDPI.Call(^uintptr(3)) // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
	return func() {
		if previous != 0 {
			setThreadDPI.Call(previous)
		}
		runtime.UnlockOSThread()
	}
}

func newBackend() Backend {
	if inSandbox() {
		return &nativeBackend{}
	}
	return &relayBackend{root: boxRoot()}
}
func inSandbox() bool {
	if os.Getenv("CAPX_WECHAT_SANDBOX") != "1" {
		return false
	}
	account, err := user.Current()
	if err != nil {
		return false
	}
	name := account.Username
	if i := strings.LastIndex(name, "\\"); i >= 0 {
		name = name[i+1:]
	}
	return strings.EqualFold(name, "WDAGUtilityAccount")
}
func (*nativeBackend) Available() bool { return inSandbox() }
func (*nativeBackend) Environment() Environment {
	return Environment{Mode: "windows-sandbox", Available: inSandbox(), Note: "微信在 Windows 沙箱独立用户中运行，登录状态由客户端确认"}
}

func processIdentity(pid uint32) (string, uint64, error) {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", 0, err
	}
	defer windows.CloseHandle(handle)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return "", 0, err
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return "", 0, err
	}
	stamp := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	return windows.UTF16ToString(buf[:size]), stamp, nil
}

func describe(hwnd uintptr) (Window, error) {
	var pid uint32
	getPID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	path, stamp, err := processIdentity(pid)
	if err != nil || !allowedProcess(path) {
		return Window{}, fmt.Errorf("窗口不属于电脑版微信或小程序，请重新选择")
	}
	var bounds rect
	if ok, _, _ := getRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds))); ok == 0 {
		return Window{}, fmt.Errorf("无法读取窗口尺寸")
	}
	buf := make([]uint16, 1024)
	getTitle.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	class := make([]uint16, 256)
	getClass.Call(hwnd, uintptr(unsafe.Pointer(&class[0])), uintptr(len(class)))
	minimized, _, _ := isIconic.Call(hwnd)
	foreground, _, _ := getForeground.Call()
	kind := "wechat"
	if strings.EqualFold(filepath.Base(path), "WeChatAppEx.exe") {
		kind = "miniapp"
	}
	if strings.EqualFold(filepath.Base(path), "WeChatSetup.exe") {
		kind = "installer"
	}
	return Window{ID: fmt.Sprintf("%x:%d:%d", hwnd, pid, stamp), PID: pid, Title: windows.UTF16ToString(buf), Class: windows.UTF16ToString(class),
		Process: filepath.Base(path), Kind: kind, Width: int(bounds.Right - bounds.Left), Height: int(bounds.Bottom - bounds.Top), Minimized: minimized != 0, Foreground: foreground == hwnd}, nil
}

func resolve(id string) (uintptr, Window, error) {
	hwnd, pid, created, err := parseID(id)
	if err != nil {
		return 0, Window{}, err
	}
	w, err := describe(hwnd)
	if err != nil {
		return 0, Window{}, err
	}
	if w.ID != fmt.Sprintf("%x:%d:%d", hwnd, pid, created) {
		return 0, Window{}, fmt.Errorf("窗口已关闭或更换，请重新选择")
	}
	visible, _, _ := isVisible.Call(hwnd)
	if visible == 0 {
		return 0, Window{}, fmt.Errorf("微信窗口当前不可见")
	}
	return hwnd, w, nil
}

type enumeration struct{ windows []Window }

var enumerationMu sync.Mutex
var activeEnumeration *enumeration

var enumerateCallback = syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
	visible, _, _ := isVisible.Call(hwnd)
	if visible != 0 {
		if w, err := describe(hwnd); err == nil && w.Width >= 80 && w.Height >= 80 {
			if strings.EqualFold(w.Class, "popupshadow") {
				return 1
			}
			if activeEnumeration != nil {
				activeEnumeration.windows = append(activeEnumeration.windows, w)
			}
		}
	}
	return 1
})

func (*nativeBackend) Windows() ([]Window, error) {
	restore := nativeThread()
	defer restore()
	enumerationMu.Lock()
	defer enumerationMu.Unlock()
	result := enumeration{windows: make([]Window, 0)}
	activeEnumeration = &result
	defer func() { activeEnumeration = nil }()
	ok, _, err := enumWindows.Call(enumerateCallback, 0)
	if ok == 0 {
		return nil, fmt.Errorf("枚举微信窗口失败: %w", err)
	}
	return result.windows, nil
}

func (b *nativeBackend) Launch() error {
	windows, err := b.Windows()
	if err != nil {
		return err
	}
	for _, w := range windows {
		if w.Kind == "wechat" {
			return b.Show(w.ID)
		}
	}
	var candidates []string
	if path := runningClientExecutable(); path != "" {
		candidates = append(candidates, path)
	}
	if p := strings.TrimSpace(os.Getenv("CAPX_WECHAT_EXE")); p != "" {
		candidates = append(candidates, p)
	}
	for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
		for _, sub := range []string{"Tencent/Weixin/Weixin.exe", "Tencent/WeChat/WeChat.exe"} {
			candidates = append(candidates, filepath.Join(base, sub))
		}
	}
	for _, p := range candidates {
		if !allowedProcess(p) || strings.EqualFold(filepath.Base(p), "WeChatAppEx.exe") {
			continue
		}
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			cmd := exec.Command(p)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			if err := cmd.Start(); err != nil {
				return err
			}
			go cmd.Wait()
			return nil
		}
	}
	return fmt.Errorf("未找到电脑版微信，请先打开微信，或设置 CAPX_WECHAT_EXE")
}

func (*nativeBackend) Show(id string) error {
	restore := nativeThread()
	defer restore()
	hwnd, _, err := resolve(id)
	if err != nil {
		return err
	}
	if minimized, _, _ := isIconic.Call(hwnd); minimized != 0 {
		showWindow.Call(hwnd, 9) // SW_RESTORE; retain existing maximized windows.
	}
	fitVisibleWindow(hwnd)
	foreground, _, _ := getForeground.Call()
	current := uintptr(windows.GetCurrentThreadId())
	foregroundThread, _, _ := getPID.Call(foreground, 0)
	targetThread, _, _ := getPID.Call(hwnd, 0)
	for _, thread := range []uintptr{foregroundThread, targetThread} {
		if thread != 0 && thread != current {
			if attached, _, _ := attachThreadInput.Call(current, thread, 1); attached != 0 {
				defer attachThreadInput.Call(current, thread, 0)
			}
		}
	}
	setForeground.Call(hwnd)
	for i := 0; i < 5; i++ {
		fg, _, _ := getForeground.Call()
		if fg == hwnd {
			return nil
		}
		time.Sleep(40 * time.Millisecond)
	}
	return fmt.Errorf("Windows 未允许切换前台，请手动点击目标微信窗口后重试")
}

func fitVisibleWindow(hwnd uintptr) {
	monitor, _, _ := monitorFromWindow.Call(hwnd, 2) // MONITOR_DEFAULTTONEAREST
	info := monitorInfo{Size: uint32(unsafe.Sizeof(monitorInfo{}))}
	var bounds rect
	if monitor == 0 {
		return
	}
	if ok, _, _ := getMonitorInfo.Call(monitor, uintptr(unsafe.Pointer(&info))); ok == 0 {
		return
	}
	if ok, _, _ := getWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&bounds))); ok == 0 {
		return
	}
	work := info.Work
	if bounds.Left >= work.Left && bounds.Top >= work.Top && bounds.Right <= work.Right && bounds.Bottom <= work.Bottom {
		return
	}
	width, height := bounds.Right-bounds.Left, bounds.Bottom-bounds.Top
	// Retain a mini-program's narrow layout when only its height exceeds the
	// viewport; maximizing would stretch its rpx content across the desktop.
	width = min(width, work.Right-work.Left)
	height = min(height, work.Bottom-work.Top)
	x := max(work.Left, min(bounds.Left, work.Right-width))
	y := max(work.Top, min(bounds.Top, work.Bottom-height))
	setWindowPos.Call(hwnd, 0, uintptr(x), uintptr(y), uintptr(width), uintptr(height), 0x0014) // no z-order/activation change
}

func (*nativeBackend) Screenshot(id string) ([]byte, error) {
	traceCapture("begin")
	restore := nativeThread()
	defer restore()
	hwnd, w, err := foregroundTarget(id)
	traceCapture("foreground complete")
	if err != nil {
		return nil, err
	}
	if w.Minimized {
		return nil, fmt.Errorf("窗口已最小化，请先点「前置窗口」")
	}
	if w.Width <= 0 || w.Height <= 0 || w.Width > 8192 || w.Height > 8192 || w.Width*w.Height > 16000000 {
		return nil, fmt.Errorf("窗口截图尺寸无效")
	}
	hung, _, _ := isHung.Call(hwnd)
	if hung != 0 {
		return nil, fmt.Errorf("微信窗口没有响应")
	}
	// PrintWindow can hang in Qt/Chromium application drawing handlers.
	// Capture the visible client rectangle of the selected sandbox window.
	time.Sleep(80 * time.Millisecond)
	origin := point{}
	if ok, _, _ := clientToScreen.Call(hwnd, uintptr(unsafe.Pointer(&origin))); ok == 0 {
		return nil, fmt.Errorf("无法定位截图窗口")
	}
	// Test inside rounded Qt borders rather than in transparent corner pixels.
	for _, offset := range []point{{int32(w.Width / 2), int32(w.Height / 2)}, {16, 16}, {int32(w.Width - 17), int32(w.Height - 17)}} {
		p := point{origin.X + offset.X, origin.Y + offset.Y}
		hit := windowAt(p)
		root, _, _ := getAncestor.Call(hit, 2)
		if root != hwnd {
			return nil, fmt.Errorf("目标窗口被遮挡，请前置目标窗口或选择当前弹窗")
		}
	}
	traceCapture("visibility complete")
	dc, _, _ := getDC.Call(0)
	if dc == 0 {
		return nil, fmt.Errorf("无法获取窗口画面")
	}
	defer releaseDC.Call(0, dc)
	mem, _, _ := createDC.Call(dc)
	if mem == 0 {
		return nil, fmt.Errorf("创建截图 DC 失败")
	}
	defer deleteDC.Call(mem)
	bmp, _, _ := createBitmap.Call(dc, uintptr(w.Width), uintptr(w.Height))
	if bmp == 0 {
		return nil, fmt.Errorf("创建截图位图失败")
	}
	defer deleteObject.Call(bmp)
	old, _, _ := selectObject.Call(mem, bmp)
	defer selectObject.Call(mem, old)
	ok, _, _ := bitBlt.Call(mem, 0, 0, uintptr(w.Width), uintptr(w.Height), dc, uintptr(origin.X), uintptr(origin.Y), 0x40cc0020)
	traceCapture("bitblt complete")
	if ok == 0 {
		return nil, fmt.Errorf("窗口截图失败")
	}
	// DIB extraction requires the bitmap not to be selected into a DC.
	selectObject.Call(mem, old)
	info := make([]byte, 40)
	binary.LittleEndian.PutUint32(info, 40)
	binary.LittleEndian.PutUint32(info[4:], uint32(w.Width))
	binary.LittleEndian.PutUint32(info[8:], uint32(-int32(w.Height)))
	binary.LittleEndian.PutUint16(info[12:], 1)
	binary.LittleEndian.PutUint16(info[14:], 32)
	pixels := make([]byte, w.Width*w.Height*4)
	lines, _, _ := getDIBits.Call(dc, bmp, 0, uintptr(w.Height), uintptr(unsafe.Pointer(&pixels[0])), uintptr(unsafe.Pointer(&info[0])), 0)
	traceCapture("dibits complete")
	if int(lines) != w.Height {
		return nil, fmt.Errorf("读取窗口像素失败")
	}
	img := image.NewRGBA(image.Rect(0, 0, w.Width, w.Height))
	nonzero := false
	for i := 0; i < len(pixels); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = pixels[i+2], pixels[i+1], pixels[i], 255
		if pixels[i] != 0 || pixels[i+1] != 0 || pixels[i+2] != 0 {
			nonzero = true
		}
	}
	if !nonzero {
		return nil, fmt.Errorf("微信返回了黑色画面，请前置窗口后重试")
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	traceCapture("png complete")
	return buf.Bytes(), nil
}

func traceCapture(stage string) {
	if os.Getenv("CAPX_WXDESK_DIAGNOSTICS") != "1" {
		return
	}
	file, err := os.OpenFile(filepath.Join(os.Getenv("CAPX_DATA_DIR"), "window-capture.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer file.Close()
	fmt.Fprintln(file, time.Now().UTC().Format(time.RFC3339), stage)
}

func foregroundTarget(id string) (uintptr, Window, error) {
	if err := (&nativeBackend{}).Show(id); err != nil {
		return 0, Window{}, err
	}
	hwnd, w, err := resolve(id)
	if err != nil {
		return 0, Window{}, err
	}
	fg, _, _ := getForeground.Call()
	if fg != hwnd || w.Minimized {
		return 0, Window{}, fmt.Errorf("操作前请前置目标微信窗口，避免输入到其他应用")
	}
	return hwnd, w, nil
}

func windowAt(p point) uintptr {
	var hit uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		packed := uint64(uint32(p.X)) | uint64(uint32(p.Y))<<32
		hit, _, _ = windowFromPoint.Call(uintptr(packed))
	} else {
		hit, _, _ = windowFromPoint.Call(uintptr(uint32(p.X)), uintptr(uint32(p.Y)))
	}
	return hit
}

func inputBytes(kind uint32) ([]byte, int) {
	size, offset := 28, 4
	if unsafe.Sizeof(uintptr(0)) == 8 {
		size, offset = 40, 8
	}
	b := make([]byte, size)
	binary.LittleEndian.PutUint32(b, kind)
	return b, offset
}
func keyboard(vk, scan uint16, flags uint32) []byte {
	b, o := inputBytes(1)
	binary.LittleEndian.PutUint16(b[o:], vk)
	binary.LittleEndian.PutUint16(b[o+2:], scan)
	binary.LittleEndian.PutUint32(b[o+4:], flags)
	return b
}
func mouse(flags, data uint32) []byte {
	b, o := inputBytes(0)
	binary.LittleEndian.PutUint32(b[o+8:], data)
	binary.LittleEndian.PutUint32(b[o+12:], flags)
	return b
}
func mouseMove(p point) []byte {
	metric := func(index int) int64 {
		value, _, _ := getSystemMetrics.Call(uintptr(index))
		return int64(int32(value))
	}
	left, top := metric(76), metric(77) // virtual desktop, in physical pixels
	width, height := metric(78), metric(79)
	x := max(int64(0), min(int64(p.X)-left, width-1)) * 65535 / max(int64(1), width-1)
	y := max(int64(0), min(int64(p.Y)-top, height-1)) * 65535 / max(int64(1), height-1)
	b, offset := inputBytes(0)
	binary.LittleEndian.PutUint32(b[offset:], uint32(x))
	binary.LittleEndian.PutUint32(b[offset+4:], uint32(y))
	binary.LittleEndian.PutUint32(b[offset+12:], 0xc001) // MOVE | ABSOLUTE | VIRTUALDESK
	return b
}
func send(events ...[]byte) error {
	if len(events) == 0 {
		return nil
	}
	data := bytes.Join(events, nil)
	n, _, _ := sendInput.Call(uintptr(len(events)), uintptr(unsafe.Pointer(&data[0])), uintptr(len(events[0])))
	if int(n) != len(events) {
		return fmt.Errorf("Windows 拒绝输入，请检查目标窗口与程序权限")
	}
	return nil
}

func (*nativeBackend) Tap(id string, x, y, width, height int) error {
	restore := nativeThread()
	defer restore()
	hwnd, w, err := foregroundTarget(id)
	if err != nil {
		return err
	}
	if w.Width != width || w.Height != height {
		return fmt.Errorf("窗口尺寸已变化，请刷新截图再点击")
	}
	p := point{int32(x), int32(y)}
	if ok, _, _ := clientToScreen.Call(hwnd, uintptr(unsafe.Pointer(&p))); ok == 0 {
		return fmt.Errorf("无法定位窗口坐标")
	}
	packed := uint64(uint32(p.X)) | uint64(uint32(p.Y))<<32
	var hit uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		hit, _, _ = windowFromPoint.Call(uintptr(packed))
	} else {
		hit, _, _ = windowFromPoint.Call(uintptr(uint32(p.X)), uintptr(uint32(p.Y)))
	}
	root, _, _ := getAncestor.Call(hit, 2)
	if root != hwnd {
		return fmt.Errorf("目标坐标被其他窗口遮挡，请刷新截图")
	}
	var previous point
	gotPrevious, _, _ := getCursorPos.Call(uintptr(unsafe.Pointer(&previous)))
	fg, _, _ := getForeground.Call()
	if fg != hwnd {
		return fmt.Errorf("前台窗口已变化，请重试")
	}
	events := [][]byte{mouseMove(p), mouse(0x0002, 0), mouse(0x0004, 0)}
	if gotPrevious != 0 {
		// Keep restoration in the same input queue. SetCursorPos immediately
		// after SendInput can overtake a queued click and change its target.
		events = append(events, mouseMove(previous))
	}
	return send(events...)
}

func (*nativeBackend) Input(id, text string) error {
	restore := nativeThread()
	defer restore()
	if _, _, err := foregroundTarget(id); err != nil {
		return err
	}
	units := utf16.Encode([]rune(text))
	events := make([][]byte, 0, len(units)*2)
	for _, unit := range units {
		events = append(events, keyboard(0, unit, 4), keyboard(0, unit, 6))
	}
	return send(events...)
}
func (*nativeBackend) Key(id, key string) error {
	restore := nativeThread()
	defer restore()
	if _, _, err := foregroundTarget(id); err != nil {
		return err
	}
	vk := virtualKeys[key]
	events := [][]byte{}
	if strings.HasPrefix(key, "CTRL_") {
		events = append(events, keyboard(0x11, 0, 0))
	}
	events = append(events, keyboard(vk, 0, 0), keyboard(vk, 0, 2))
	if strings.HasPrefix(key, "CTRL_") {
		events = append(events, keyboard(0x11, 0, 2))
	}
	return send(events...)
}
func (*nativeBackend) Scroll(id string, delta int) error {
	restore := nativeThread()
	defer restore()
	hwnd, w, err := foregroundTarget(id)
	if err != nil {
		return err
	}
	p := point{int32(w.Width / 2), int32(w.Height / 2)}
	if ok, _, _ := clientToScreen.Call(hwnd, uintptr(unsafe.Pointer(&p))); ok == 0 {
		return fmt.Errorf("无法定位滚动窗口")
	}
	var previous point
	gotPrevious, _, _ := getCursorPos.Call(uintptr(unsafe.Pointer(&previous)))
	fg, _, _ := getForeground.Call()
	if fg != hwnd {
		return fmt.Errorf("前台窗口已变化，请重试")
	}
	events := [][]byte{mouseMove(p), mouse(0x0800, uint32(int32(delta)))}
	if gotPrevious != 0 {
		events = append(events, mouseMove(previous))
	}
	return send(events...)
}
