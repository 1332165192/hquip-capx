//go:build windows

package wxdesk

import (
	"testing"
)

func TestNormalHostNeverGetsNativePersonalWindowBackend(t *testing.T) {
	t.Setenv("CAPX_WECHAT_SANDBOX", "")
	controller := New()
	if _, ok := controller.backend.(*relayBackend); !ok {
		t.Fatal("host must use sandbox relay exclusively")
	}
	t.Setenv("CAPX_WECHAT_SANDBOX", "1")
	if !inSandbox() {
		if _, ok := New().backend.(*relayBackend); !ok {
			t.Fatal("environment flag alone must not grant access to personal desktop")
		}
	}
}
