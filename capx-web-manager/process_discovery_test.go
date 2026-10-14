package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCapxProcessQueryIncludesSelectedExecutableAndManagedPIDs(t *testing.T) {
	query, names := capxProcessQuery(
		filepath.Join("build", "capx-captured.next.exe"),
		[]instanceManifest{{PID: 12345}, {PID: 0}},
	)

	if _, ok := names["capx-captured.exe"]; !ok {
		t.Fatal("standard executable name is missing")
	}
	if _, ok := names["capx-captured.next.exe"]; !ok {
		t.Fatal("selected executable name is missing")
	}
	for _, expected := range []string{
		"Name=''capx-captured.exe''",
		"Name=''capx-captured.next.exe''",
		"ProcessId=12345",
	} {
		if !strings.Contains(query, expected) {
			t.Fatalf("query %q is missing %q", query, expected)
		}
	}
	if strings.Contains(query, "ProcessId=0") {
		t.Fatalf("query included an invalid manifest PID: %q", query)
	}
}

func TestCapxProcessQueryQuotesCustomExecutableName(t *testing.T) {
	query, _ := capxProcessQuery(filepath.Join("build", "capx-$value's.exe"), nil)
	if strings.Contains(query, "$value's.exe") {
		t.Fatalf("query contains an unescaped PowerShell apostrophe: %q", query)
	}
	if !strings.Contains(query, "$value''''s.exe") {
		t.Fatalf("query did not quote the custom executable name: %q", query)
	}
}

func TestParseNetstatListenerPIDSelectsExactLoopbackListener(t *testing.T) {
	output := `
  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:18608        0.0.0.0:0              LISTENING       11111
  TCP    127.0.0.1:18609        0.0.0.0:0              ESTABLISHED     22222
  TCP    0.0.0.0:18609          0.0.0.0:0              LISTENING       33333
  TCP    127.0.0.1:18609        0.0.0.0:0              LISTENING       42512
`
	pid, err := parseNetstatListenerPID(output, 18609)
	if err != nil {
		t.Fatal(err)
	}
	if pid != 42512 {
		t.Fatalf("got listener PID %d, want 42512", pid)
	}
}

func TestParseNetstatListenerPIDRejectsMissingAndConflictingOwners(t *testing.T) {
	if _, err := parseNetstatListenerPID("", 18609); err == nil {
		t.Fatal("missing listener was accepted")
	}
	conflicting := `
TCP 127.0.0.1:18609 0.0.0.0:0 LISTENING 100
TCP 127.0.0.1:18609 0.0.0.0:0 LISTENING 200
`
	if _, err := parseNetstatListenerPID(conflicting, 18609); err == nil {
		t.Fatal("conflicting listener owners were accepted")
	}
}

func TestManagedBrowserProcessMatchesFlags(t *testing.T) {
	flags := []string{
		"--remote-debugging-port=18609",
		`--user-data-dir=C:\state\browser-profile`,
		"--capx-instance-id=cs_claude",
		"--capx-generation=generation-1",
	}
	matching := procInfo{
		ProcessID:      42512,
		ExecutablePath: `J:\Program Files\Google\Chrome\Application\chrome.exe`,
		CommandLine:    `"J:\Program Files\Google\Chrome\Application\chrome.exe" ` + strings.Join(flags, " "),
	}
	if !managedBrowserProcessMatchesFlags(matching, flags) {
		t.Fatal("matching managed browser identity was rejected")
	}
	wrongExecutable := matching
	wrongExecutable.ExecutablePath = `C:\Windows\System32\notepad.exe`
	if managedBrowserProcessMatchesFlags(wrongExecutable, flags) {
		t.Fatal("non-browser executable was accepted")
	}
	missingFlag := matching
	missingFlag.CommandLine = strings.ReplaceAll(missingFlag.CommandLine, "--capx-generation=generation-1", "")
	if managedBrowserProcessMatchesFlags(missingFlag, flags) {
		t.Fatal("browser missing a managed identity flag was accepted")
	}
}

func TestVerifyManagedBrowserPIDUsesWMIIndependentFallback(t *testing.T) {
	oldImagePath := managedBrowserImagePath
	oldProcessQuery := managedBrowserProcessQuery
	t.Cleanup(func() {
		managedBrowserImagePath = oldImagePath
		managedBrowserProcessQuery = oldProcessQuery
	})
	managedBrowserImagePath = func(pid int) (string, error) {
		if pid != 42512 {
			t.Fatalf("queried image for PID %d, want 42512", pid)
		}
		return `J:\Program Files\Google\Chrome\Application\chrome.exe`, nil
	}
	managedBrowserProcessQuery = func(int) ([]procInfo, error) {
		return nil, errors.New("CIM unavailable: 0x800705af")
	}

	pid, err := verifyManagedBrowserPID(42512, []string{"--capx-instance-id=cs_claude"})
	if err != nil {
		t.Fatal(err)
	}
	if pid != 42512 {
		t.Fatalf("got verified PID %d, want 42512", pid)
	}
}

func TestVerifyManagedBrowserPIDRejectsAvailableMetadataMismatch(t *testing.T) {
	oldImagePath := managedBrowserImagePath
	oldProcessQuery := managedBrowserProcessQuery
	t.Cleanup(func() {
		managedBrowserImagePath = oldImagePath
		managedBrowserProcessQuery = oldProcessQuery
	})
	managedBrowserImagePath = func(int) (string, error) {
		return `J:\Program Files\Google\Chrome\Application\chrome.exe`, nil
	}
	managedBrowserProcessQuery = func(pid int) ([]procInfo, error) {
		return []procInfo{{
			ProcessID:      pid,
			ExecutablePath: `J:\Program Files\Google\Chrome\Application\chrome.exe`,
			CommandLine:    `chrome.exe --capx-instance-id=another_project`,
		}}, nil
	}

	if _, err := verifyManagedBrowserPID(42512, []string{"--capx-instance-id=cs_claude"}); err == nil {
		t.Fatal("available command-line metadata mismatch was accepted")
	}
}

func TestProcessExecutablePathReadsCurrentProcessWithoutWMI(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Win32 process image queries are Windows-only")
	}
	executablePath, err := processExecutablePath(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(strings.ToLower(executablePath), ".test.exe") {
		t.Fatalf("unexpected test process image: %s", executablePath)
	}
}

func TestGetProcessInfosHasHardTimeout(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell process queries are Windows-only")
	}
	started := time.Now()
	_, err := getProcessInfosWithin("Start-Sleep -Seconds 30", 100*time.Millisecond)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got error %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timed process query returned too slowly: %s", elapsed)
	}
}

func TestManagedInstancesFallbackIncludesOnlyVerifiedActiveManifests(t *testing.T) {
	oldProcessPath := managedFallbackProcessPath
	oldIdentity := managedFallbackIdentity
	t.Cleanup(func() {
		managedFallbackProcessPath = oldProcessPath
		managedFallbackIdentity = oldIdentity
	})
	managedFallbackProcessPath = func(pid int) (string, error) {
		if pid == 41001 {
			return `F:\tools\capx-captured.exe`, nil
		}
		return "", errors.New("process is not running")
	}
	managedFallbackIdentity = func(manifest instanceManifest) error {
		if manifest.InstanceID == "active_project" {
			return nil
		}
		return errors.New("runtime identity is unavailable")
	}

	manifests := []instanceManifest{
		{
			InstanceID:       "active_project",
			ProjectRoot:      `F:\projects\active`,
			APIBase:          "http://127.0.0.1:41002",
			Proxy:            "http://127.0.0.1:41003",
			StateDir:         `C:\state-active`,
			CDPPort:          41004,
			IdentityRequired: true,
			PID:              41001,
			BrowserPID:       41005,
			Generation:       "generation-active",
		},
		{InstanceID: "offline_project", PID: 0, Generation: "generation-offline"},
		{InstanceID: "legacy_project", PID: 42001, Generation: "generation-legacy"},
	}

	items := managedInstancesFromManifests(manifests, "", false)
	if len(items) != 1 {
		t.Fatalf("got %d fallback instances, want 1: %+v", len(items), items)
	}
	item := items[0]
	if item.InstanceID != "active_project" || item.Status != "受管运行中" || item.APIPort != 41002 || item.ProxyPort != 41003 || item.CDPPort != 41004 {
		t.Fatalf("unexpected fallback instance: %+v", item)
	}
	if item.Addr != "127.0.0.1:41002" || item.Proxy != "127.0.0.1:41003" || item.Exe != `F:\tools\capx-captured.exe` {
		t.Fatalf("fallback endpoints were not normalized: %+v", item)
	}

	if filtered := managedInstancesFromManifests(manifests, `F:\tools\another.exe`, true); len(filtered) != 0 {
		t.Fatalf("path-filtered fallback returned %+v", filtered)
	}
	if matched := managedInstancesFromManifests(manifests, `F:\tools\capx-captured.exe`, true); len(matched) != 1 {
		t.Fatalf("matching path filter returned %+v", matched)
	}
}
