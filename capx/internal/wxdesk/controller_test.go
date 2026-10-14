package wxdesk

import (
	"testing"
)

func TestInvalidWindowIdentities(t *testing.T) {
	for _, id := range []string{"", "123", "0:1:2", "ffff:0:2", "ffff:1:0", "ffff:1:wrong", "../bad:1:2"} {
		if _, _, _, err := parseID(id); err == nil {
			t.Fatalf("accepted %q", id)
		}
	}
	hwnd, pid, created, err := parseID("ff:12:34")
	if err != nil || hwnd != 255 || pid != 12 || created != 34 {
		t.Fatalf("identity %x %d %d %v", hwnd, pid, created, err)
	}
}

func TestInvalidActionsCannotReachBackend(t *testing.T) {
	c := NewWithBackend(nil)
	for _, err := range []error{c.Tap("x", -1, 0, 100, 100), c.Tap("x", 10, 20, 0, 0), c.Tap("x", 100, 10, 100, 100), c.Input("x", "bad\nline"), c.Input("x", ""), c.Key("x", "ctrl+send"), c.Scroll("x", 0), c.Scroll("x", 1201)} {
		if err == nil {
			t.Fatal("invalid input should not reach a backend")
		}
	}
}
