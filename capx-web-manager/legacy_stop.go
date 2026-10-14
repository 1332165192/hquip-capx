package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var legacyStopQuery = func(pid int) ([]procInfo, error) {
	return getProcessInfos(fmt.Sprintf(`Get-CimInstance Win32_Process -Filter "ProcessId=%d"`, pid))
}
var legacyStopRunning = processRunning
var legacyStopTerminate = terminateProcessVerified
var legacyStopTimeout = 20 * time.Second

var errRuntimeShutdownIdentity = errors.New("runtime shutdown identity/authentication rejected; replacement preserved")

func requestRuntimeShutdown(client *http.Client, base, token, instanceID, generation string) error {
	body, _ := json.Marshal(map[string]string{"expected_instance_id": instanceID, "expected_generation": generation})
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(base, "/")+"/api/runtime/shutdown", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w (HTTP %d)", errRuntimeShutdownIdentity, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("shutdown returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Legacy describes the Manager registration mode, not a reason to bypass the
// backend cleanup protocol. Always request authenticated shutdown before the
// same-identity force fallback, just as managed instances do.
func stopLegacyInstance(selected instance) (bool, error) {
	infos, err := legacyStopQuery(selected.PID)
	if err != nil {
		return false, err
	}
	if len(infos) == 0 {
		return false, nil
	}
	matches := func(current procInfo) bool {
		return sameCanonicalPath(current.ExecutablePath, selected.Exe) && current.CommandLine == selected.CommandLine
	}
	if len(infos) != 1 || !matches(infos[0]) {
		return false, fmt.Errorf("legacy Capx identity changed before shutdown")
	}
	base := "http://" + strings.TrimPrefix(strings.TrimPrefix(selected.Addr, "http://"), "https://")
	client := &http.Client{Timeout: 1500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var health capxHealth
	requested := false
	if err := runtimeJSON(client, http.MethodGet, base+"/health", "", &health); err == nil && health.Status == "ok" {
		generation := argValue(selected.CommandLine, "generation")
		identity := argValue(selected.CommandLine, "instance-id")
		if (generation != "" && generation != health.Identity.Generation) || (identity != "" && identity != health.Identity.InstanceID) {
			return false, fmt.Errorf("legacy Capx health identity changed; replacement was preserved")
		}
		token := tokenText(selected.StateDir)
		if token == "" {
			return false, fmt.Errorf("current instance token is unavailable; shutdown was not authenticated")
		}
		// Explicitly reject authentication errors rather than silently turning a
		// failed login into an unconditional process kill.
		err = requestRuntimeShutdown(client, base, token, health.Identity.InstanceID, health.Identity.Generation)
		if errors.Is(err, errRuntimeShutdownIdentity) {
			return false, err
		}
		requested = err == nil
	}
	if requested {
		deadline := time.Now().Add(legacyStopTimeout)
		for legacyStopRunning(selected.PID) && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
		}
		if !legacyStopRunning(selected.PID) {
			return true, nil
		}
	}
	return legacyStopTerminate(selected.PID, matches)
}
