package mobile

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestSnapshotAcceptsEmptyHierarchy(t *testing.T) {
	c := &Controller{serial: "phone", runBytes: func(_ string, _ ...string) ([]byte, error) {
		return []byte("diagnostic prefix\n<hierarchy rotation=\"0\"></hierarchy>\nUI hierarchy dumped"), nil
	}}
	snapshot, err := c.SnapshotWithInfo()
	if err != nil || snapshot.Source != "uiautomator" || snapshot.Degraded || !snapshot.SupportsText {
		t.Fatalf("valid empty hierarchy treated as failure: %+v err=%v", snapshot, err)
	}
	data, err := json.Marshal(snapshot)
	if err != nil || !strings.Contains(string(data), `"elements":[]`) {
		t.Fatalf("empty elements must be a JSON array: %s err=%v", data, err)
	}
}

func TestSnapshotFilePathIsUniqueAndCleaned(t *testing.T) {
	var paths, removed []string
	c := &Controller{serial: "phone",
		run: func(_ string, args ...string) (string, error) {
			if len(args) == 4 && args[1] == "uiautomator" {
				paths = append(paths, args[3])
			} else if len(args) == 4 && args[1] == "rm" {
				removed = append(removed, args[3])
			} else {
				t.Fatalf("unexpected command: %v", args)
			}
			return "", nil
		},
		runBytes: func(_ string, args ...string) ([]byte, error) {
			if args[1] == "uiautomator" {
				return nil, errors.New("no tty")
			}
			if args[1] != "cat" || args[2] != paths[len(paths)-1] {
				t.Fatalf("read an unexpected/stale dump: %v", args)
			}
			return []byte(sampleDump), nil
		},
	}
	for i := 0; i < 2; i++ {
		if _, err := c.Snapshot(); err != nil {
			t.Fatal(err)
		}
	}
	if len(paths) != 2 || len(removed) != 2 || paths[0] == paths[1] || paths[0] != removed[0] || paths[1] != removed[1] {
		t.Fatalf("dump paths not unique/cleaned: paths=%v removed=%v", paths, removed)
	}
}

func fallbackController(t *testing.T, tap func(string, []string)) *Controller {
	t.Helper()
	return &Controller{serial: "phone",
		run: func(serial string, args ...string) (string, error) {
			if args[1] == "uiautomator" {
				return "", errors.New("UiAutomation already registered")
			}
			if args[1] == "input" {
				tap(serial, args)
			}
			return "", nil
		},
		runBytes: func(_ string, args ...string) ([]byte, error) {
			if args[1] == "dumpsys" {
				return []byte(sampleDumpsys), nil
			}
			return nil, errors.New("dump unavailable")
		},
	}
}

func TestFallbackReportsLimitsAndClickKeepsDevice(t *testing.T) {
	var taps int
	c := fallbackController(t, func(serial string, args []string) {
		taps++
		if serial != "phone" || strings.Join(args, " ") != "shell input tap 160 234" {
			t.Fatalf("clicked wrong device or location: %q %v", serial, args)
		}
	})
	snapshot, err := c.SnapshotWithInfo()
	if err != nil || snapshot.Source != "dumpsys" || !snapshot.Degraded || snapshot.SupportsText || snapshot.BoundsAccurate || snapshot.Note == "" {
		t.Fatalf("fallback concealed its limitations: %+v err=%v", snapshot, err)
	}
	if _, err := c.Click(Locator{Text: "微信"}); err == nil || !strings.Contains(err.Error(), "dumpsys") || taps != 0 {
		t.Fatal("text locator should report unsupported without tapping")
	}
	original := c.runBytes
	c.runBytes = func(serial string, args ...string) ([]byte, error) {
		// Simulate another API client switching the target during the dump.
		c.Use("second")
		return original(serial, args...)
	}
	if _, err := c.Click(Locator{ResourceID: "com.miui.home:id/icon_icon"}); err != nil || taps != 1 {
		t.Fatalf("resource-id click failed: taps=%d err=%v", taps, err)
	}
}

func TestDumpsysHidesInvisibleDescendantsAndParsesFlags(t *testing.T) {
	data := `ACTIVITY com.example/.Main 123 pid=1
  View Hierarchy:
    ViewGroup{a V.E...... ........ 0,0-100,100}
      ViewGroup{b I.E...... ........ 0,0-100,100}
        Button{c VFED..C.. .F...... 5,5-20,20 #7f123 app:id/hidden_child}
      Button{d VFED..C.. .F...... 20,20-40,40}`
	els := parseDumpsysTop([]byte(data), true)
	if len(els) != 1 || !els[0].Clickable || !els[0].Focused || els[0].Package != "com.example" {
		t.Fatalf("hidden children or clickable flags parsed incorrectly: %+v", els)
	}
}

func TestInputQuotesRemoteShellAndPreservesLiteralPercentS(t *testing.T) {
	var argsSeen []string
	c := &Controller{serial: "phone", run: func(serial string, args ...string) (string, error) {
		if serial != "phone" || len(args) != 4 || strings.Join(args[:3], " ") != "shell input text" {
			t.Fatalf("unexpected input command: %q %v", serial, args)
		}
		argsSeen = append(argsSeen, args[3])
		return "", nil
	}}
	if err := c.Input(`a b;$(id)&"x"'c`); err != nil {
		t.Fatal(err)
	}
	if len(argsSeen) != 1 || argsSeen[0] != `'a%sb;$(id)&"x"'\''c'` {
		t.Fatalf("input not quoted for the device shell: %v", argsSeen)
	}
	argsSeen = nil
	if err := c.Input("100%s done"); err != nil {
		t.Fatal(err)
	}
	if strings.Join(argsSeen, "|") != "'100%'|'s%sdone'" {
		t.Fatalf("literal %%s would become a space: %v", argsSeen)
	}
	argsSeen = nil
	for _, unsupported := range []string{"微信", "hello\nworld", "\x00"} {
		if err := c.Input(unsupported); err == nil {
			t.Fatalf("unsupported text accepted: %q", unsupported)
		}
	}
	if len(argsSeen) != 0 {
		t.Fatal("unsupported input ran a device command")
	}
}

func TestControlArgumentsRejectShellCommands(t *testing.T) {
	c := &Controller{serial: "phone", run: func(_ string, _ ...string) (string, error) {
		t.Fatal("invalid argument reached adb")
		return "", nil
	}}
	if err := c.Key("KEYCODE_HOME; id"); err == nil {
		t.Fatal("key command accepted shell syntax")
	}
	if err := c.LaunchApp("com.tencent.mm; id"); err == nil {
		t.Fatal("package accepted shell syntax")
	}
	if err := c.Tap(-1, 1); err == nil {
		t.Fatal("negative tap accepted")
	}
	if err := c.Swipe(0, 0, 1, 1, 10001); err == nil {
		t.Fatal("unbounded swipe accepted")
	}
}

func TestLocatorDoesNotClickIDPrefix(t *testing.T) {
	e := Element{ResourceID: "com.example:id/search_btn"}
	for _, id := range []string{"search", "com.example:id/search"} {
		if (Locator{ResourceID: id}).matches(e) {
			t.Fatalf("resource id %q matched a different button", id)
		}
	}
}
