//go:build pcap && !windows

package sniffer

func checkPCapPermissions() error { return nil }
