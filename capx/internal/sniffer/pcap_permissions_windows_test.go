//go:build pcap && windows

package sniffer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows/registry"
)

func TestNpcapPermissionCheckRejectsOnlyRestrictedUnelevatedToken(t *testing.T) {
	for _, test := range []struct {
		name      string
		adminOnly uint64
		readErr   error
		elevated  bool
		denied    bool
	}{
		{name: "administrator only", adminOnly: 1, denied: true},
		{name: "elevated administrator", adminOnly: 1, elevated: true},
		{name: "unrestricted installation"},
		{name: "driver not installed", readErr: registry.ErrNotExist},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkNpcapPermissions(func() (uint64, error) { return test.adminOnly, test.readErr }, func() bool { return test.elevated })
			if errors.Is(err, os.ErrPermission) != test.denied || !test.denied && err != nil {
				t.Fatalf("permission result: %v", err)
			}
			if test.denied && !strings.Contains(err.Error(), "Npcap") {
				t.Fatalf("missing actionable driver name: %v", err)
			}
		})
	}
	readErr := errors.New("registry fixture unavailable")
	if err := checkNpcapPermissions(func() (uint64, error) { return 0, readErr }, func() bool { return false }); !errors.Is(err, readErr) {
		t.Fatalf("registry read failure discarded: %v", err)
	}
}

func TestRestrictedNpcapInventoryAndRunRejectBeforeNativeDriver(t *testing.T) {
	denied := fmt.Errorf("fixture restriction: %w", os.ErrPermission)
	sniffer := pcapSniffer{permissionCheck: func() error { return denied }}
	if devices, err := sniffer.Interfaces(); devices != nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("restricted inventory: %v / %v", devices, err)
	}
	for _, iface := range []string{"", `\Device\NPF_fixture`} {
		// A nil store and invalid interface prove rejection precedes both native
		// device enumeration/open and any capture-state mutation.
		if err := sniffer.Run(context.Background(), "fixture", Config{Iface: iface}, nil); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("restricted run for %q: %v", iface, err)
		}
	}
}

func TestLocalRestrictedNpcapPermissionRejectionWithoutDriver(t *testing.T) {
	// This integration check only proceeds when read-only registry/token
	// preflight has already denied access. It never probes an allowed driver.
	if err := checkPCapPermissions(); !errors.Is(err, os.ErrPermission) {
		t.Skip("local Npcap installation is not administrator-only for this token")
	}
	sniffer := pcapSniffer{}
	if devices, err := sniffer.Interfaces(); devices != nil || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("local restricted inventory: %v / %v", devices, err)
	}
	if err := sniffer.Run(context.Background(), "fixture", Config{Iface: `\Device\NPF_fixture`}, nil); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("local restricted capture guard: %v", err)
	}
	t.Log("administrator-only Npcap rejected before driver enumeration/open; hardware capture remains unverified")
}
