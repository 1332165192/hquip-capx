//go:build windows

package wxdesk

import (
	"bytes"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Run a compiled test executable named Weixin.exe with this opt-in. All native
// operations target a test-owned static window, never an installed client.
func TestNativeFixtureWindow(t *testing.T) {
	if os.Getenv("CAPX_WXDESK_NATIVE_FIXTURE") != "1" {
		t.Skip("explicit native fixture run only")
	}
	executable, _ := os.Executable()
	if !strings.EqualFold(filepath.Base(executable), "Weixin.exe") {
		t.Fatal("compile this test fixture as Weixin.exe before running")
	}
	restore := nativeThread()
	defer restore()
	create := user32.NewProc("CreateWindowExW")
	register := user32.NewProc("RegisterClassW")
	defWindow := user32.NewProc("DefWindowProcW")
	windowProcedure := syscall.NewCallback(func(hwnd, message, wparam, lparam uintptr) uintptr {
		result, _, _ := defWindow.Call(hwnd, message, wparam, lparam)
		return result
	})
	type windowClass struct {
		Style                              uint32
		Procedure                          uintptr
		ClassExtra, WindowExtra            int32
		Instance, Icon, Cursor, Background uintptr
		Menu, Name                         *uint16
	}
	show := user32.NewProc("ShowWindow")
	getMessage := user32.NewProc("GetMessageW")
	translate := user32.NewProc("TranslateMessage")
	dispatch := user32.NewProc("DispatchMessageW")
	post := user32.NewProc("PostMessageW")
	destroy := user32.NewProc("DestroyWindow")
	setFocus := user32.NewProc("SetFocus")
	type msg struct {
		HWND           uintptr
		Message        uint32
		WParam, LParam uintptr
		Time           uint32
		Point          point
		Private        uint32
	}
	type handles struct {
		root, edit uintptr
		err        error
	}
	created := make(chan handles, 1)
	done := make(chan struct{})
	closeRequest := uint32(0x8001)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		defer close(done)
		class := windows.StringToUTF16("CapxWindowFixture")
		definition := windowClass{Procedure: windowProcedure, Background: 6, Name: &class[0]}
		if atom, _, err := register.Call(uintptr(unsafe.Pointer(&definition))); atom == 0 {
			created <- handles{err: fmt.Errorf("register fixture class: %w", err)}
			return
		}
		caption := windows.StringToUTF16("Capx isolated control fixture")
		// Mini-programs may keep topmost windows open during a live test. Keep
		// this test-owned fixture above them without changing any real client.
		hwnd, _, err := create.Call(0x00000008, uintptr(unsafe.Pointer(&class[0])), uintptr(unsafe.Pointer(&caption[0])), 0x00cf0000, 150, 150, 500, 350, 0, 0, 0, 0)
		if hwnd == 0 {
			created <- handles{err: fmt.Errorf("create fixture: %w", err)}
			return
		}
		editClass := windows.StringToUTF16("EDIT")
		empty := windows.StringToUTF16("")
		edit, _, _ := create.Call(0, uintptr(unsafe.Pointer(&editClass[0])), uintptr(unsafe.Pointer(&empty[0])), 0x50800080, 20, 20, 420, 80, hwnd, 0, 0, 0)
		if edit == 0 {
			destroy.Call(hwnd)
			created <- handles{err: fmt.Errorf("create fixture edit")}
			return
		}
		show.Call(hwnd, 4)
		setFocus.Call(edit)
		created <- handles{root: hwnd, edit: edit}
		var message msg
		for {
			result, _, _ := getMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
			if result == 0 || int32(result) == -1 {
				break
			}
			if message.HWND == hwnd && message.Message == closeRequest {
				destroy.Call(hwnd)
				break
			}
			translate.Call(uintptr(unsafe.Pointer(&message)))
			dispatch.Call(uintptr(unsafe.Pointer(&message)))
		}
	}()
	h := <-created
	if h.err != nil {
		t.Fatal(h.err)
	}
	defer func() {
		post.Call(h.root, uintptr(closeRequest), 0, 0)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("fixture thread did not close")
		}
	}()
	window, err := describe(h.root)
	if err != nil {
		t.Fatal(err)
	}
	if window.PID != uint32(os.Getpid()) {
		t.Fatal("fixture identity must be its own process")
	}
	b := &nativeBackend{}
	listed, err := b.Windows()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, candidate := range listed {
		if candidate.ID == window.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("test-owned visible window was not enumerated")
	}
	if err = b.Show(window.ID); err != nil {
		t.Fatal(err)
	}
	window, err = describe(h.root)
	if err != nil {
		t.Fatal(err)
	}
	photo, err := b.Screenshot(window.ID)
	if err != nil {
		origin := point{}
		clientToScreen.Call(h.root, uintptr(unsafe.Pointer(&origin)))
		t.Logf("client origin=%+v size=%dx%d hwnd=%x", origin, window.Width, window.Height, h.root)
		for _, offset := range []point{{int32(window.Width / 2), int32(window.Height / 2)}, {2, 2}, {int32(window.Width - 3), int32(window.Height - 3)}} {
			p := point{origin.X + offset.X, origin.Y + offset.Y}
			hit := windowAt(p)
			root, _, _ := getAncestor.Call(hit, 2)
			t.Logf("sample=%+v hit=%x root=%x", p, hit, root)
		}
		t.Fatal(err)
	}
	image, err := png.Decode(bytes.NewReader(photo))
	if err != nil {
		t.Fatal(err)
	}
	if image.Bounds().Dx() != window.Width || image.Bounds().Dy() != window.Height {
		t.Fatalf("invalid image size: got %v expected %dx%d err=%v", image.Bounds(), window.Width, window.Height, err)
	}
	if err = b.Tap(window.ID, 40, 40, window.Width+1, window.Height); err == nil {
		t.Fatal("resized screenshot should be rejected")
	}
	if err = b.Tap(window.ID, 50, 50, window.Width, window.Height); err != nil {
		t.Fatal(err)
	}
	if err = b.Input(window.ID, "capx测试"); err != nil {
		t.Fatal(err)
	}
	wanted := "capx测试"
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		text := make([]uint16, 100)
		getTitle.Call(h.edit, uintptr(unsafe.Pointer(&text[0])), uintptr(len(text)))
		if windows.UTF16ToString(text) == wanted {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Unicode input did not reach the test-owned edit field")
}
