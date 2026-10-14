//go:build !pcap

package spoof

import "errors"

// errNoPcap is returned by the stub when raw frame injection isn't built in.
var errNoPcap = errors.New("ARP spoofing needs a -tags pcap build with Npcap/libpcap and admin/root")

type stubSpoofer struct{}

func newSpoofer() spoofer { return stubSpoofer{} }

func (stubSpoofer) available() bool                        { return false }
func (stubSpoofer) start(_, _, _ string) error             { return errNoPcap }
func (stubSpoofer) stop() error                            { return errNoPcap }
func (stubSpoofer) status() (bool, string, string, string) { return false, "", "", "" }
