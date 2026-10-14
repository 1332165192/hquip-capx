package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const runtimeSessionsSchemaVersion = 1

type browserSession struct {
	APIPort     int    `json:"api_port"`
	ProxyPort   int    `json:"proxy_port"`
	PID         int    `json:"pid"`
	Executable  string `json:"executable"`
	CommandLine string `json:"command_line"`
	ProfileDir  string `json:"profile_dir"`
	StartedAt   string `json:"started_at"`
}

type adbSession struct {
	Serial    string `json:"serial"`
	ProxyPort int    `json:"proxy_port"`
	StartedAt string `json:"started_at"`
}

type runtimeSessions struct {
	SchemaVersion int              `json:"schema_version"`
	Browsers      []browserSession `json:"browsers"`
	ADB           []adbSession     `json:"adb"`
}

func runtimeSessionsPath() string { return filepath.Join(managerDir(), "runtime-sessions.json") }

func loadRuntimeSessions() runtimeSessions {
	data, err := os.ReadFile(runtimeSessionsPath())
	if err != nil || len(data) > 1024*1024 {
		return runtimeSessions{SchemaVersion: runtimeSessionsSchemaVersion}
	}
	var state runtimeSessions
	if json.Unmarshal(data, &state) != nil || state.SchemaVersion != runtimeSessionsSchemaVersion {
		return runtimeSessions{SchemaVersion: runtimeSessionsSchemaVersion}
	}
	return state
}

func updateRuntimeSessions(update func(*runtimeSessions) error) error {
	dir := managerDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	release, err := acquireManagerFileLock(filepath.Join(dir, ".runtime-sessions.lock"))
	if err != nil {
		return err
	}
	defer release()

	state := loadRuntimeSessions()
	state.SchemaVersion = runtimeSessionsSchemaVersion
	if err := update(&state); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".runtime-sessions-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameWithRetry(tmpPath, runtimeSessionsPath()); err != nil {
		return err
	}
	committed = true
	return syncRegistryDirectory(dir)
}

func recordBrowserSession(session browserSession) error {
	return updateRuntimeSessions(func(state *runtimeSessions) error {
		filtered := state.Browsers[:0]
		for _, current := range state.Browsers {
			if current.APIPort != session.APIPort || current.ProxyPort != session.ProxyPort {
				filtered = append(filtered, current)
			}
		}
		state.Browsers = append(filtered, session)
		return nil
	})
}

func removeBrowserSessions(pids map[int]struct{}) error {
	return updateRuntimeSessions(func(state *runtimeSessions) error {
		filtered := state.Browsers[:0]
		for _, session := range state.Browsers {
			if _, remove := pids[session.PID]; !remove {
				filtered = append(filtered, session)
			}
		}
		state.Browsers = filtered
		return nil
	})
}

func recordADBSession(session adbSession) ([]adbSession, error) {
	var replaced []adbSession
	err := updateRuntimeSessions(func(state *runtimeSessions) error {
		filtered := state.ADB[:0]
		for _, current := range state.ADB {
			if strings.EqualFold(current.Serial, session.Serial) {
				replaced = append(replaced, current)
				continue
			}
			filtered = append(filtered, current)
		}
		state.ADB = append(filtered, session)
		return nil
	})
	return replaced, err
}

func removeADBSession(serial string, proxyPort int) error {
	return updateRuntimeSessions(func(state *runtimeSessions) error {
		filtered := state.ADB[:0]
		for _, session := range state.ADB {
			if strings.EqualFold(session.Serial, serial) && session.ProxyPort == proxyPort {
				continue
			}
			filtered = append(filtered, session)
		}
		state.ADB = filtered
		return nil
	})
}

func ensureADBSession(session adbSession) error {
	return updateRuntimeSessions(func(state *runtimeSessions) error {
		for _, current := range state.ADB {
			if strings.EqualFold(current.Serial, session.Serial) && current.ProxyPort == session.ProxyPort {
				return nil
			}
		}
		state.ADB = append(state.ADB, session)
		return nil
	})
}

func stopRecordedBrowsers(apiPort, proxyPort int) []error {
	state := loadRuntimeSessions()
	removed := map[int]struct{}{}
	var failures []error
	for _, session := range state.Browsers {
		if apiPort > 0 && session.APIPort != apiPort {
			continue
		}
		if proxyPort > 0 && session.ProxyPort != proxyPort {
			continue
		}
		terminated, err := terminateProcessVerified(session.PID, func(current procInfo) bool {
			return sameCanonicalPath(current.ExecutablePath, session.Executable) &&
				current.CommandLine == session.CommandLine &&
				strings.Contains(strings.ToLower(current.CommandLine), strings.ToLower("--user-data-dir="+session.ProfileDir))
		})
		if err != nil {
			failures = append(failures, fmt.Errorf("browser PID %d: %w", session.PID, err))
			continue
		}
		if terminated || !processRunning(session.PID) {
			removed[session.PID] = struct{}{}
		}
	}
	if len(removed) > 0 {
		if err := removeBrowserSessions(removed); err != nil {
			failures = append(failures, err)
		}
	}
	return failures
}

func stopRecordedADB(proxyPort int, serial string) []error {
	state := loadRuntimeSessions()
	sessions := append([]adbSession(nil), state.ADB...)
	if strings.TrimSpace(serial) != "" && proxyPort > 0 {
		found := false
		for _, session := range sessions {
			if strings.EqualFold(session.Serial, serial) && session.ProxyPort == proxyPort {
				found = true
			}
		}
		if !found {
			pending := adbSession{Serial: serial, ProxyPort: proxyPort, StartedAt: sessionStartedAt()}
			if err := ensureADBSession(pending); err != nil {
				return []error{err}
			}
			sessions = append(sessions, pending)
		}
	}
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].Serial == sessions[j].Serial {
			return sessions[i].ProxyPort < sessions[j].ProxyPort
		}
		return sessions[i].Serial < sessions[j].Serial
	})
	var failures []error
	for _, session := range sessions {
		if proxyPort > 0 && session.ProxyPort != proxyPort {
			continue
		}
		if serial != "" && !strings.EqualFold(session.Serial, serial) {
			continue
		}
		if err := clearADBSession(session); err != nil {
			failures = append(failures, err)
			continue
		}
		if err := removeADBSession(session.Serial, session.ProxyPort); err != nil {
			failures = append(failures, err)
		}
	}
	return failures
}

func clearADBSession(session adbSession) error {
	var failures []error
	if out, err := adbCommandRunner(session.Serial, "shell", "settings", "put", "global", "http_proxy", ":0"); err != nil {
		failures = append(failures, fmt.Errorf("ADB %s clear proxy: %s", session.Serial, out))
	}
	if out, err := adbCommandRunner(session.Serial, "shell", "settings", "delete", "global", "http_proxy"); err != nil {
		failures = append(failures, fmt.Errorf("ADB %s delete proxy: %s", session.Serial, out))
	}
	reverseName := "tcp:" + fmt.Sprint(session.ProxyPort)
	if out, err := adbCommandRunner(session.Serial, "reverse", "--list"); err != nil {
		failures = append(failures, fmt.Errorf("ADB %s list reverse: %s", session.Serial, out))
	} else if strings.Contains(out, reverseName) {
		if removeOut, removeErr := adbCommandRunner(session.Serial, "reverse", "--remove", reverseName); removeErr != nil {
			failures = append(failures, fmt.Errorf("ADB %s remove reverse: %s", session.Serial, removeOut))
		}
	}
	return errors.Join(failures...)
}

func sessionStartedAt() string { return time.Now().UTC().Format(time.RFC3339Nano) }
