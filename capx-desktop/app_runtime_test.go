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

const validDesktopHealth = `{"status":"ok","sniffer":"stub","hook":"stub","inline":"stub","identity":{"instance_id":"desktop-test","generation":"generation-test"}}`

func isolateDesktop(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, key := range []string{"CAPX_TOKEN", "CAPX_TOKEN_FILE", "CAPX_BASE", "CAPX_PROXY", "CAPX_STATE_DIR"} {
		t.Setenv(key, "")
	}
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	t.Setenv("LOCALAPPDATA", root)
	t.Setenv("CAPX_DESKTOP_SETTINGS", filepath.Join(root, "desktop", "settings.json"))
	t.Setenv("CAPX_INSTANCE_DIR", filepath.Join(root, "instances"))
	return root
}
func writeFixture(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopHealthValidatesStatusAndShape(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{"missing", 404, validDesktopHealth, false}, {"error", 500, validDesktopHealth, false},
		{"html", 200, "<html>hello</html>", false}, {"generic", 200, `{"status":"ok"}`, false},
		{"trailing", 200, validDesktopHealth + `{}`, false}, {"capx", 200, validDesktopHealth, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer s.Close()
			if got := capxHealthOK(s.URL, time.Second); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestDesktopUsesInstanceTokenAndConfirmsAuthentication(t *testing.T) {
	root := isolateDesktop(t)
	state := filepath.Join(root, "state")
	t.Setenv("CAPX_STATE_DIR", state)
	writeFixture(t, filepath.Join(root, ".capx", "token"), "legacy-token")
	writeFixture(t, filepath.Join(state, "token"), "instance-token")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			fmt.Fprint(w, validDesktopHealth)
			return
		}
		if r.Header.Get("Authorization") != "Bearer instance-token" {
			http.Error(w, "bad token", 401)
			return
		}
		fmt.Fprint(w, `{"running":true}`)
	}))
	defer s.Close()
	t.Setenv("CAPX_BASE", s.URL)
	a := NewApp()
	if !a.CapxRunning() {
		t.Fatal("instance credential was not used")
	}
	if _, err := a.get("/api/proxy/status"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPX_TOKEN", "wrong-token")
	if a.CapxRunning() {
		t.Fatal("authentication failure must not be shown as connected")
	}
}

func TestDesktopFindsRuntimeAndManagedTokenFiles(t *testing.T) {
	root := isolateDesktop(t)
	state := filepath.Join(root, "custom state")
	tokenPath := filepath.Join(state, "custom-token")
	writeFixture(t, tokenPath, "managed-token")
	base := "http://127.0.0.1:25678"
	manifest := map[string]any{"api_base": base, "state_dir": state, "token_file": tokenPath, "generation": "g"}
	b, _ := json.Marshal(manifest)
	writeFixture(t, filepath.Join(root, "instances", "test.json"), string(b))
	if got := readTokenFor(base); got != "managed-token" {
		t.Fatalf("got %q", got)
	}
	out := filepath.Join(root, "outside-token")
	writeFixture(t, out, "outside")
	manifest["token_file"] = out
	b, _ = json.Marshal(manifest)
	writeFixture(t, filepath.Join(root, "instances", "test.json"), string(b))
	if got := readTokenFor(base); got == "outside" {
		t.Fatal("token_file escaped instance state")
	}
	t.Setenv("CAPX_TOKEN_FILE", out)
	if got := readTokenFor(base); got != "outside" {
		t.Fatal("explicit token file override is supported")
	}
}

type fakeBackendStop struct {
	running atomic.Bool
	kills   atomic.Int32
}

func (p *fakeBackendStop) Running() bool    { return p.running.Load() }
func (p *fakeBackendStop) Terminate() error { p.kills.Add(1); p.running.Store(false); return nil }
func (p *fakeBackendStop) Close()           {}

func TestDesktopStopPrefersAuthenticatedGracefulShutdown(t *testing.T) {
	p := &fakeBackendStop{}
	p.running.Store(true)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			fmt.Fprint(w, validDesktopHealth)
			return
		}
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "unauthorized", 401)
			return
		}
		var condition map[string]string
		if json.NewDecoder(r.Body).Decode(&condition) != nil || condition["expected_generation"] != "generation-test" || condition["expected_instance_id"] != "desktop-test" {
			t.Error("shutdown lacked observed identity precondition")
		}
		p.running.Store(false)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer s.Close()
	rt := desktopRuntime{BaseURL: s.URL, InstanceID: "desktop-test", Generation: "generation-test"}
	if err := stopCapxRuntime(s.URL, "secret", rt, p, time.Second); err != nil {
		t.Fatal(err)
	}
	if p.kills.Load() != 0 {
		t.Fatal("graceful stop used force")
	}
}

func TestDesktopShutdownConflictNeverFallsBackToForce(t *testing.T) {
	p := &fakeBackendStop{}
	p.running.Store(true)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			fmt.Fprint(w, validDesktopHealth)
			return
		}
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		if body["expected_generation"] != "generation-test" {
			t.Error("must bind even when no runtime file exists")
		}
		http.Error(w, "generation changed between health and POST", http.StatusConflict)
	}))
	defer s.Close()
	if err := stopCapxRuntime(s.URL, "secret", desktopRuntime{}, p, time.Millisecond); err == nil {
		t.Fatal("expected conflict")
	}
	if p.kills.Load() != 0 {
		t.Fatal("409 forced the replacement process")
	}
}

func TestDesktopStopRefusesReplacementAndAuthFailure(t *testing.T) {
	for _, replacement := range []bool{false, true} {
		t.Run(fmt.Sprint(replacement), func(t *testing.T) {
			p := &fakeBackendStop{}
			p.running.Store(true)
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					fmt.Fprint(w, validDesktopHealth)
					return
				}
				http.Error(w, "bad token", 401)
			}))
			defer s.Close()
			rt := desktopRuntime{BaseURL: s.URL, Generation: "generation-test"}
			if replacement {
				rt.Generation = "different"
			}
			if err := stopCapxRuntime(s.URL, "secret", rt, p, time.Millisecond); err == nil {
				t.Fatal("expected refusal")
			}
			if p.kills.Load() != 0 {
				t.Fatal("unverified/unauthorized stop forced process exit")
			}
		})
	}
}

func TestDesktopForceFallbackRequiresVerifiedProcess(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()
	if err := stopCapxRuntime(s.URL, "secret", desktopRuntime{}, nil, time.Millisecond); err == nil {
		t.Fatal("unowned process stop succeeded")
	}
	p := &fakeBackendStop{}
	p.running.Store(true)
	if err := stopCapxRuntime(s.URL, "secret", desktopRuntime{}, p, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if p.kills.Load() != 1 {
		t.Fatal("verified fallback was not executed")
	}
}

func TestBackendIdentityRequiresGenerationStateAndExecutable(t *testing.T) {
	root := t.TempDir()
	rt := desktopRuntime{PID: 42, BaseURL: "http://127.0.0.1:19091", StateDir: filepath.Join(root, "state space"), Exe: filepath.Join(root, "captured-modern.exe"), Generation: "g", InstanceID: "d"}
	line := fmt.Sprintf(`"%s" --addr 127.0.0.1:19091 --state-dir "%s" --generation g --instance-id d`, rt.Exe, rt.StateDir)
	if !backendIdentityMatches(rt, rt.Exe, line) {
		t.Fatal("exact identity rejected")
	}
	if backendIdentityMatches(rt, rt.Exe, strings.Replace(line, "--generation g", "--generation other", 1)) {
		t.Fatal("replacement generation matched")
	}
	if backendIdentityMatches(rt, filepath.Join(root, "other.exe"), line) {
		t.Fatal("wrong executable matched")
	}
	if runtimeArg("nothing", "state-dir") != "" {
		t.Fatal("missing argument")
	}
}
