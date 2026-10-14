package mobile

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type captureDevice struct {
	proxy   string
	reverse map[string]string
}

type captureADB struct {
	devices map[string]*captureDevice
	fail    func(string, []string) error
	writes  int
}

func newCaptureController(proxy string) (*Controller, *captureADB) {
	fake := &captureADB{devices: map[string]*captureDevice{
		"phone": {proxy: proxy, reverse: make(map[string]string)},
	}}
	return &Controller{serial: "phone", run: fake.run}, fake
}

func (f *captureADB) run(serial string, args ...string) (string, error) {
	if f.fail != nil {
		if err := f.fail(serial, args); err != nil {
			return "", err
		}
	}
	d := f.devices[serial]
	if d == nil {
		return "", fmt.Errorf("unknown device: %s", serial)
	}
	switch {
	case len(args) == 5 && strings.Join(args, " ") == "shell settings get global http_proxy":
		if d.proxy == "" {
			return "null", nil
		}
		return d.proxy, nil
	case len(args) == 6 && strings.Join(args[:5], " ") == "shell settings put global http_proxy":
		f.writes++
		d.proxy = args[5]
		if strings.HasPrefix(d.proxy, "'") && strings.HasSuffix(d.proxy, "'") {
			d.proxy = strings.ReplaceAll(d.proxy[1:len(d.proxy)-1], "'\\''", "'")
		}
		return "", nil
	case len(args) == 5 && strings.Join(args, " ") == "shell settings delete global http_proxy":
		f.writes++
		d.proxy = ""
		return "", nil
	case len(args) == 2 && strings.Join(args, " ") == "reverse --list":
		var lines []string
		for remote, target := range d.reverse {
			lines = append(lines, "UsbFfs "+remote+" "+target)
		}
		return strings.Join(lines, "\n"), nil
	case len(args) == 4 && args[0] == "reverse" && args[1] == "--no-rebind":
		if d.reverse[args[2]] != "" {
			return "", errors.New("cannot rebind")
		}
		f.writes++
		d.reverse[args[2]] = args[3]
		return "", nil
	case len(args) == 3 && args[0] == "reverse" && args[1] == "--remove":
		f.writes++
		delete(d.reverse, args[2])
		return "", nil
	default:
		return "", fmt.Errorf("unexpected command: %v", args)
	}
}

func TestCaptureRestoresPreviousConfiguration(t *testing.T) {
	for _, original := range []string{"", ":0", "192.168.1.2:8888"} {
		t.Run(original, func(t *testing.T) {
			c, fake := newCaptureController(original)
			if _, err := c.StartCapture(18080, nil); err != nil {
				t.Fatal(err)
			}
			// Repeated start must not replace the original backup.
			if _, err := c.StartCapture(18080, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := c.StartCapture(18081, nil); err == nil {
				t.Fatal("port switch should require stopping the existing session")
			}
			if err := c.StopCapture(18081); err == nil {
				t.Fatal("wrong port should not stop capture")
			}
			if err := c.StopCapture(0); err != nil {
				t.Fatal(err)
			}
			d := fake.devices["phone"]
			if d.proxy != original || len(d.reverse) != 0 {
				t.Fatalf("not restored: %+v", d)
			}
			writes := fake.writes
			if err := c.StopCapture(0); err != nil || fake.writes != writes {
				t.Fatalf("repeated stop mutated configuration: %v", err)
			}
		})
	}
}

func TestCapturePreservesOtherToolsConfiguration(t *testing.T) {
	t.Run("no owned session", func(t *testing.T) {
		c, fake := newCaptureController("192.168.1.2:8888")
		fake.devices["phone"].reverse["tcp:18080"] = "tcp:12345"
		if err := c.StopCapture(18080); err != nil || fake.writes != 0 {
			t.Fatalf("stop altered another tool's configuration: %v", err)
		}
		if _, err := c.StartCapture(18080, nil); err == nil || fake.writes != 0 {
			t.Fatal("start must refuse a conflicting reverse")
		}
	})
	t.Run("reuse existing tunnel", func(t *testing.T) {
		c, fake := newCaptureController("")
		fake.devices["phone"].reverse["tcp:18080"] = "tcp:18080"
		if _, err := c.StartCapture(18080, nil); err != nil {
			t.Fatal(err)
		}
		if err := c.StopCapture(0); err != nil {
			t.Fatal(err)
		}
		if fake.devices["phone"].reverse["tcp:18080"] != "tcp:18080" {
			t.Fatal("removed an existing tunnel owned by another tool")
		}
	})
	t.Run("external replacement", func(t *testing.T) {
		c, fake := newCaptureController("")
		if _, err := c.StartCapture(18080, nil); err != nil {
			t.Fatal(err)
		}
		d := fake.devices["phone"]
		d.proxy, d.reverse["tcp:18080"] = "10.0.0.1:9999", "tcp:9999"
		if err := c.StopCapture(0); err != nil {
			t.Fatal(err)
		}
		if d.proxy != "10.0.0.1:9999" || d.reverse["tcp:18080"] != "tcp:9999" {
			t.Fatalf("overwrote external changes: %+v", d)
		}
	})
}

func TestCaptureRollbackAndRetry(t *testing.T) {
	c, fake := newCaptureController("10.0.0.1:8080")
	fake.fail = func(_ string, args []string) error {
		if len(args) == 6 && args[5] == "127.0.0.1:18080" {
			return errors.New("settings write denied")
		}
		return nil
	}
	if _, err := c.StartCapture(18080, nil); err == nil {
		t.Fatal("expected failure")
	}
	d := fake.devices["phone"]
	if d.proxy != "10.0.0.1:8080" || len(d.reverse) != 0 || len(c.captures) != 0 {
		t.Fatalf("failed start left partial state: %+v", d)
	}
	fake.fail = nil
	if _, err := c.StartCapture(18080, nil); err != nil {
		t.Fatal(err)
	}
	fake.fail = func(_ string, args []string) error {
		if len(args) > 1 && args[1] == "--remove" {
			return errors.New("temporary removal failure")
		}
		return nil
	}
	if err := c.StopCapture(0); err == nil || len(c.captures) != 1 {
		t.Fatal("failed cleanup must retain session for retry")
	}
	fake.fail = nil
	if err := c.StopCapture(0); err != nil || len(d.reverse) != 0 || d.proxy != "10.0.0.1:8080" {
		t.Fatalf("retry did not finish cleanup: %+v err=%v", d, err)
	}
}

func TestCloseRestoresAllDevices(t *testing.T) {
	c, fake := newCaptureController("10.0.0.1:8080")
	fake.devices["second"] = &captureDevice{reverse: make(map[string]string)}
	if _, err := c.StartCapture(18080, nil); err != nil {
		t.Fatal(err)
	}
	c.Use("second")
	if _, err := c.StartCapture(18081, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if fake.devices["phone"].proxy != "10.0.0.1:8080" || fake.devices["second"].proxy != "" || len(c.captures) != 0 {
		t.Fatal("close did not restore both devices")
	}
}

func TestStatusRequiresMatchingReverse(t *testing.T) {
	c, fake := newCaptureController("127.0.0.1:18080")
	for _, target := range []string{"", "tcp:12345", "tcp:18080"} {
		fake.devices["phone"].reverse["tcp:18080"] = target
		status, err := c.Status()
		if err != nil || status["wired"] != (target == "tcp:18080") {
			t.Fatalf("target=%q status=%v err=%v", target, status, err)
		}
	}
	fake.fail = func(_ string, _ []string) error { return errors.New("device offline") }
	if _, err := c.Status(); err == nil {
		t.Fatal("offline device must not be reported as wired")
	}
}

func TestFailedProxyRestoreKeepsRoutingAndCanRetry(t *testing.T) {
	c, fake := newCaptureController("10.0.0.1:8080")
	if _, err := c.StartCapture(18080, nil); err != nil {
		t.Fatal(err)
	}
	fake.fail = func(_ string, args []string) error {
		if len(args) == 6 && args[5] == "'10.0.0.1:8080'" {
			return errors.New("restore denied")
		}
		return nil
	}
	if err := c.StopCapture(0); err == nil {
		t.Fatal("restore failure was ignored")
	}
	d := fake.devices["phone"]
	if d.proxy != "127.0.0.1:18080" || d.reverse["tcp:18080"] != "tcp:18080" || len(c.captures) != 1 {
		t.Fatalf("failed restoration left a dead proxy or lost the backup: %+v", d)
	}
	fake.fail = nil
	if err := c.StopCapture(0); err != nil || d.proxy != "10.0.0.1:8080" || len(d.reverse) != 0 {
		t.Fatalf("restore retry failed: %+v err=%v", d, err)
	}
}

func TestConcurrentCaptureLifecycle(t *testing.T) {
	c, fake := newCaptureController("10.0.0.1:8080")
	for _, start := range []bool{true, false} {
		var wg sync.WaitGroup
		errs := make(chan error, 12)
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if start {
					_, err := c.StartCapture(18080, nil)
					errs <- err
				} else {
					errs <- c.StopCapture(0)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	if fake.devices["phone"].proxy != "10.0.0.1:8080" || len(fake.devices["phone"].reverse) != 0 {
		t.Fatal("concurrent requests lost the original configuration")
	}
}

func TestDeviceRequestsShareCaptureOwnershipWithoutChangingSelection(t *testing.T) {
	c, fake := newCaptureController("10.0.0.1:8080")
	fake.devices["second"] = &captureDevice{reverse: make(map[string]string)}
	if _, err := c.ForDevice("second").StartCapture(18081, nil); err != nil {
		t.Fatal(err)
	}
	if serial, _ := c.Serial(); serial != "phone" {
		t.Fatalf("request changed default selection to %q", serial)
	}
	status, err := c.ForDevice("second").Status()
	if err != nil || status["managed"] != true || status["wired"] != true {
		t.Fatalf("fresh request lost session state: %v err=%v", status, err)
	}
	if err := c.ForDevice("second").StopCapture(0); err != nil {
		t.Fatal(err)
	}
	if fake.devices["phone"].proxy != "10.0.0.1:8080" || fake.devices["second"].proxy != "" || len(c.captures) != 0 {
		t.Fatal("scoped stop affected the wrong device or lost its backup")
	}
	if _, err := c.ForDevice("second").StartCapture(18081, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil || fake.devices["second"].proxy != "" {
		t.Fatalf("root shutdown did not restore scoped sessions: %v", err)
	}
}
