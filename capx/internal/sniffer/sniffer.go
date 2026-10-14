// Package sniffer captures L3/L4 traffic (TCP/UDP) and turns it into flows and
// packet events. The live backend uses gopacket/libpcap and is compiled only
// with the "pcap" build tag (it needs Npcap on Windows / libpcap on Linux). The
// default build ships a stub so the rest of capx builds and runs without those
// native dependencies.
package sniffer

import (
	"context"
	"errors"
	"strings"

	"github.com/hquip/capx/internal/store"
)

// ErrNoPcap is returned when the binary was built without the live pcap backend.
var ErrNoPcap = errors.New("sniffer: live capture not built in (rebuild with -tags pcap and install Npcap/libpcap)")

// Config controls a sniffer run.
type Config struct {
	Iface  string // interface name; empty = backend default
	Filter string // BPF filter, e.g. "tcp or udp"
	Snap   int32  // snap length; 0 = backend default
	MaxRaw int    // max raw bytes to attach per packet event (0 = none)
}

// PreferCaptureDevice picks a usable live interface from pcap.FindAllDevs
// output. Loopback and NICs that already have an IPv4/IPv6 address beat the
// first (often unusable) Npcap adapter on Windows.
func PreferCaptureDevice(devs []Device) Device {
	if len(devs) == 0 {
		return Device{}
	}
	score := func(d Device) int {
		n := strings.ToLower(d.Name + " " + d.Description)
		s := 0
		if len(d.Addresses) > 0 {
			s += 4
		}
		if strings.Contains(n, "loopback") || strings.Contains(n, "npcap_loopback") || d.Name == "\\Device\\NPF_Loopback" {
			s += 3
		}
		if strings.Contains(n, "ethernet") || strings.Contains(n, "wi-fi") || strings.Contains(n, "wifi") || strings.Contains(n, "wlan") {
			s += 2
		}
		if strings.Contains(n, "wan miniport") || strings.Contains(n, "bluetooth") || strings.Contains(n, "virtualbox") {
			s -= 3
		}
		return s
	}
	best := 0
	for i := 1; i < len(devs); i++ {
		if score(devs[i]) > score(devs[best]) {
			best = i
		}
	}
	return devs[best]
}

// Device describes a capture interface as reported by the live backend.
type Device struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
}

// Sniffer captures packets into the store as Flow/Packet events.
type Sniffer interface {
	// Run blocks capturing until ctx is cancelled or an error occurs.
	Run(ctx context.Context, captureID string, cfg Config, st *store.Store) error
	// Backend returns a short backend name (e.g. "gopacket", "stub").
	Backend() string
	// Interfaces lists capture devices. The stub backend returns ErrNoPcap.
	Interfaces() ([]Device, error)
}

// New returns the sniffer backend compiled into this binary.
func New() Sniffer { return newBackend() }
