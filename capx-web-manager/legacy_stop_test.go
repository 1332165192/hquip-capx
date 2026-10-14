package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLegacyStopUsesRuntimeShutdownBeforeForce(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		replacement bool
		wantError   bool
		wantForce   bool
	}{
		{"graceful", 202, false, false, false},
		{"unsupported", 404, false, false, true},
		{"unauthorized", 401, false, true, false},
		{"changed-after-health", 409, false, true, false},
		{"replacement", 202, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldQuery, oldRunning, oldTerminate, oldTimeout := legacyStopQuery, legacyStopRunning, legacyStopTerminate, legacyStopTimeout
			defer func() {
				legacyStopQuery, legacyStopRunning, legacyStopTerminate, legacyStopTimeout = oldQuery, oldRunning, oldTerminate, oldTimeout
			}()
			state := t.TempDir()
			if err := os.WriteFile(filepath.Join(state, "token"), []byte("instance-token"), 0600); err != nil {
				t.Fatal(err)
			}
			var alive atomic.Bool
			alive.Store(true)
			var forced atomic.Bool
			var authenticated atomic.Bool
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					gen := "g"
					if tc.replacement {
						gen = "replacement"
					}
					fmt.Fprintf(w, `{"status":"ok","identity":{"instance_id":"legacy-test","generation":%q}}`, gen)
					return
				}
				if r.Header.Get("Authorization") == "Bearer instance-token" && r.Method == http.MethodPost {
					authenticated.Store(true)
				}
				var body map[string]string
				json.NewDecoder(r.Body).Decode(&body)
				if body["expected_generation"] != "g" || body["expected_instance_id"] != "legacy-test" {
					t.Error("shutdown condition missing")
				}
				if tc.status == 202 {
					alive.Store(false)
				}
				w.WriteHeader(tc.status)
			}))
			defer s.Close()
			selected := instance{PID: 123, StateDir: state, Exe: filepath.Join(state, "captured.exe"), Addr: strings.TrimPrefix(s.URL, "http://"), CommandLine: "captured --generation g --instance-id legacy-test"}
			info := procInfo{ProcessID: selected.PID, ExecutablePath: selected.Exe, CommandLine: selected.CommandLine}
			legacyStopQuery = func(int) ([]procInfo, error) { return []procInfo{info}, nil }
			legacyStopRunning = func(int) bool { return alive.Load() }
			legacyStopTerminate = func(pid int, matches func(procInfo) bool) (bool, error) {
				if !matches(info) {
					return false, fmt.Errorf("mismatch")
				}
				forced.Store(true)
				alive.Store(false)
				return true, nil
			}
			legacyStopTimeout = time.Millisecond
			_, err := stopLegacyInstance(selected)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v wantError=%v", err, tc.wantError)
			}
			if forced.Load() != tc.wantForce {
				t.Fatalf("force=%v want=%v", forced.Load(), tc.wantForce)
			}
			if !tc.replacement && !authenticated.Load() {
				t.Fatal("shutdown was not authenticated")
			}
		})
	}
}

func TestLegacyStopRefusesChangedProcessBeforeHTTP(t *testing.T) {
	oldQuery, oldTerminate := legacyStopQuery, legacyStopTerminate
	defer func() { legacyStopQuery, legacyStopTerminate = oldQuery, oldTerminate }()
	legacyStopQuery = func(int) ([]procInfo, error) {
		return []procInfo{{ExecutablePath: "other.exe", CommandLine: "unrelated"}}, nil
	}
	legacyStopTerminate = func(int, func(procInfo) bool) (bool, error) {
		t.Fatal("changed identity was terminated")
		return false, nil
	}
	if _, err := stopLegacyInstance(instance{PID: 123, Exe: "captured.exe", CommandLine: "selected"}); err == nil {
		t.Fatal("changed process accepted")
	}
}
