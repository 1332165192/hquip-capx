package sniffer

import "testing"

func TestPreferCaptureDevicePrefersAddressedNIC(t *testing.T) {
	devs := []Device{
		{Name: "\\Device\\NPF_{dead}", Description: "WAN Miniport (IP)"},
		{Name: "\\Device\\NPF_{eth}", Description: "Intel Ethernet", Addresses: []string{"192.168.1.10"}},
		{Name: "\\Device\\NPF_Loopback", Description: "Adapter for loopback traffic capture"},
	}
	got := PreferCaptureDevice(devs)
	if got.Name != "\\Device\\NPF_{eth}" {
		t.Fatalf("prefer = %+v, want ethernet with address", got)
	}
}

func TestPreferCaptureDeviceEmpty(t *testing.T) {
	if got := PreferCaptureDevice(nil); got.Name != "" {
		t.Fatalf("empty list = %+v", got)
	}
}
