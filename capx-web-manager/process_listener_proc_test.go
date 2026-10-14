package main

import "testing"

// Sample rows mirror the real /proc/net/tcp column layout:
//   sl  local_address rem_address st ... inode ...
// 0100007F = 127.0.0.1 (little-endian words); 48B1 = 18609; 0A = TCP_LISTEN.
func TestParseProcNetListenerInodesSelectsLoopbackListener(t *testing.T) {
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:48B1 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:48B2 0100007F:C3A0 01 00000000:00000000 00:00000000 00000000     0        0 555002 1 0000000000000000 100 0 0 10 0
   2: 00000000:48B1 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555003 1 0000000000000000 100 0 0 10 0
`
	inodes, err := parseProcNetListenerInodes(content, 18609)
	if err != nil {
		t.Fatal(err)
	}
	if len(inodes) != 1 || inodes[0] != "555001" {
		t.Fatalf("got inodes %v, want [555001]", inodes)
	}
}

func TestParseProcNetListenerInodesIgnoresNonMatching(t *testing.T) {
	content := `   0: 0100007F:48B1 00000000:0000 01 0 0 0 0 0 555001 1 0 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 0 0 0 0 0 555002 1 0 100 0 0 10 0
`
	// Port 18609 is only present as an ESTABLISHED (01) socket; the LISTEN
	// socket is on a different port (1F90 = 8080). Neither should match.
	inodes, err := parseProcNetListenerInodes(content, 18609)
	if err != nil {
		t.Fatal(err)
	}
	if len(inodes) != 0 {
		t.Fatalf("got inodes %v, want none", inodes)
	}
}

func TestParseProcNetListenerInodesMatchesIPv6Loopback(t *testing.T) {
	// ::1 in /proc/net/tcp6 word form; 48B1 = 18609; 0A = LISTEN.
	content := `   0: 00000000000000000000000001000000:48B1 00000000000000000000000000000000:0000 0A 0 0 0 0 0 777001 1 0 100 0 0 10 0
`
	inodes, err := parseProcNetListenerInodes(content, 18609)
	if err != nil {
		t.Fatal(err)
	}
	if len(inodes) != 1 || inodes[0] != "777001" {
		t.Fatalf("got inodes %v, want [777001]", inodes)
	}
}

func TestIsProcLoopbackAddr(t *testing.T) {
	loopback := []string{
		"0100007F",                         // 127.0.0.1
		"00000000000000000000000001000000", // ::1
		"0000000000000000FFFF00000100007F", // ::ffff:127.0.0.1
	}
	for _, addr := range loopback {
		if !isProcLoopbackAddr(addr) {
			t.Errorf("loopback address %q was rejected", addr)
		}
	}
	nonLoopback := []string{
		"00000000",                         // 0.0.0.0
		"0101A8C0",                         // 192.168.1.1
		"00000000000000000000000000000000", // ::
	}
	for _, addr := range nonLoopback {
		if isProcLoopbackAddr(addr) {
			t.Errorf("non-loopback address %q was accepted", addr)
		}
	}
}

func TestManagedBrowserExecutableAcceptsLinuxNames(t *testing.T) {
	accepted := []string{
		`C:\Program Files\Google\Chrome\Application\chrome.exe`,
		"/usr/bin/google-chrome",
		"/usr/bin/google-chrome-stable",
		"/opt/google/chrome/chrome",
		"/usr/bin/chromium",
		"/usr/bin/chromium-browser",
		"/usr/bin/microsoft-edge",
	}
	for _, path := range accepted {
		if !managedBrowserExecutable(path) {
			t.Errorf("browser executable %q was rejected", path)
		}
	}
	rejected := []string{
		"/usr/bin/bash",
		"/usr/bin/node",
		`C:\Windows\System32\notepad.exe`,
	}
	for _, path := range rejected {
		if managedBrowserExecutable(path) {
			t.Errorf("non-browser executable %q was accepted", path)
		}
	}
}
