package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func useTemporaryManagerDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("LOCALAPPDATA", root)
	return filepath.Join(root, "capx-web-manager")
}

func TestConfigReadsLatestAtomicSave(t *testing.T) {
	useTemporaryManagerDir(t)
	first := config{CapturedPath: `F:\one.exe`, ADBPath: `F:\adb-one.exe`, Count: 1}
	second := config{CapturedPath: `F:\two.exe`, ADBPath: `F:\adb-two.exe`, Count: 2}
	if err := saveConfig(first); err != nil {
		t.Fatal(err)
	}
	if got := loadConfig(); got.CapturedPath != first.CapturedPath {
		t.Fatalf("first config was not visible: %+v", got)
	}
	if err := saveConfig(second); err != nil {
		t.Fatal(err)
	}
	if got := loadConfig(); got.CapturedPath != second.CapturedPath || got.Count != 2 {
		t.Fatalf("latest config was not visible: %+v", got)
	}
}

func TestAutoPortsModePersistsInConfig(t *testing.T) {
	useTemporaryManagerDir(t)
	custom := config{CapturedPath: `F:\captured.exe`, APIPort: 60701, ProxyPort: 60702, AutoPorts: false, Count: 1}
	if err := saveConfig(custom); err != nil {
		t.Fatal(err)
	}
	if got := loadConfig(); got.AutoPorts || got.APIPort != 60701 || got.ProxyPort != 60702 {
		t.Fatalf("custom port mode was not preserved: %+v", got)
	}
	automatic := custom
	automatic.AutoPorts = true
	if err := saveConfig(automatic); err != nil {
		t.Fatal(err)
	}
	if got := loadConfig(); !got.AutoPorts {
		t.Fatalf("automatic port mode was not preserved: %+v", got)
	}
}

func TestConcurrentConfigSavesAlwaysPublishCompleteJSON(t *testing.T) {
	useTemporaryManagerDir(t)
	var wg sync.WaitGroup
	errs := make(chan error, 24)
	for i := 1; i <= 24; i++ {
		wg.Add(1)
		go func(value int) {
			defer wg.Done()
			errs <- saveConfig(config{CapturedPath: fmt.Sprintf(`F:\captured-%d.exe`, value), Count: value})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(configPath())
	if err != nil {
		t.Fatal(err)
	}
	var got config
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("published config is incomplete: %v\n%s", err, raw)
	}
	if got.Count < 1 || got.Count > 24 {
		t.Fatalf("published config came from no writer: %+v", got)
	}
}

func TestRuntimeSessionReplacementAndRemoval(t *testing.T) {
	useTemporaryManagerDir(t)
	if _, err := recordADBSession(adbSession{Serial: "device-1", ProxyPort: 18080}); err != nil {
		t.Fatal(err)
	}
	replaced, err := recordADBSession(adbSession{Serial: "device-1", ProxyPort: 18081})
	if err != nil {
		t.Fatal(err)
	}
	if len(replaced) != 1 || replaced[0].ProxyPort != 18080 {
		t.Fatalf("unexpected replaced sessions: %+v", replaced)
	}
	state := loadRuntimeSessions()
	if len(state.ADB) != 1 || state.ADB[0].ProxyPort != 18081 {
		t.Fatalf("unexpected persisted sessions: %+v", state)
	}
	if err := removeADBSession("device-1", 18081); err != nil {
		t.Fatal(err)
	}
	if got := loadRuntimeSessions(); len(got.ADB) != 0 {
		t.Fatalf("ADB session was not removed: %+v", got)
	}
}

func TestFailedADBStopKeepsPendingSessionForRetry(t *testing.T) {
	useTemporaryManagerDir(t)
	original := adbCommandRunner
	adbCommandRunner = func(string, ...string) (string, error) { return "unauthorized", errors.New("failed") }
	t.Cleanup(func() { adbCommandRunner = original })

	failures := stopRecordedADB(18086, "device-pending")
	if len(failures) == 0 {
		t.Fatal("unauthorized ADB cleanup unexpectedly succeeded")
	}
	state := loadRuntimeSessions()
	if len(state.ADB) != 1 || state.ADB[0].Serial != "device-pending" || state.ADB[0].ProxyPort != 18086 {
		t.Fatalf("pending ADB cleanup was not persisted: %+v", state)
	}

	adbCommandRunner = func(string, ...string) (string, error) { return "", nil }
	if failures := stopRecordedADB(18086, "device-pending"); len(failures) != 0 {
		t.Fatalf("ADB cleanup retry failed: %v", failures)
	}
	if got := loadRuntimeSessions(); len(got.ADB) != 0 {
		t.Fatalf("successful retry retained session: %+v", got)
	}
}
