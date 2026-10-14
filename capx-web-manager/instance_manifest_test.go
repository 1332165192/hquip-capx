package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type manifestFixture struct {
	registry string
	project  string
	state    string
	manifest instanceManifest
}

func newManifestFixture(t *testing.T, id string) manifestFixture {
	t.Helper()
	root := t.TempDir()
	registry := filepath.Join(root, "registry")
	project := filepath.Join(root, "Project With Spaces")
	state := filepath.Join(root, "state")
	if err := os.MkdirAll(filepath.Join(project, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("[mcp_servers.capx.env]\nCAPX_INSTANCE_ID = %q # managed\n", id)
	if err := os.WriteFile(filepath.Join(project, ".codex", "config.toml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CAPX_INSTANCE_DIR", registry)
	return manifestFixture{
		registry: registry,
		project:  project,
		state:    state,
		manifest: instanceManifest{
			SchemaVersion:    instanceManifestSchemaVersion,
			InstanceID:       id,
			ProjectRoot:      project,
			APIBase:          "http://127.0.0.1:45101",
			Proxy:            "http://127.0.0.1:45102",
			StateDir:         state,
			TokenFile:        filepath.Join(state, "token"),
			CDPPort:          45103,
			PID:              12345,
			BrowserPID:       12346,
			ProcessStartedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Generation:       "11111111-2222-3333-4444-555555555555",
			UpdatedAt:        time.Now().UTC().Format(time.RFC3339Nano),
		},
	}
}

func TestInstanceManifestRoundTripMatchesFrameworkSchema(t *testing.T) {
	f := newManifestFixture(t, "project_one")
	if err := writeInstanceManifest(f.manifest); err != nil {
		t.Fatal(err)
	}

	got, err := loadInstanceManifest(f.manifest.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.InstanceID != f.manifest.InstanceID || got.PID != f.manifest.PID || got.CDPPort != f.manifest.CDPPort {
		t.Fatalf("unexpected manifest: %+v", got)
	}
	if !got.IdentityRequired || got.BrowserPID != f.manifest.BrowserPID || got.ProcessStartedAt != f.manifest.ProcessStartedAt {
		t.Fatalf("manager identity/process fields were not preserved: %+v", got)
	}
	canonical, err := validateManagedProject(f.manifest.InstanceID, f.project)
	if err != nil {
		t.Fatal(err)
	}
	if !sameCanonicalPath(got.ProjectRoot, canonical) {
		t.Fatalf("project root %q does not match %q", got.ProjectRoot, canonical)
	}

	data, err := os.ReadFile(filepath.Join(f.registry, f.manifest.InstanceID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"schema_version", "instance_id", "project_root", "api_base", "proxy", "state_dir", "token_file", "cdp_port", "identity_required", "pid", "browser_pid", "process_started_at", "generation", "updated_at"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("framework field %q is missing", key)
		}
	}
	if string(raw["identity_required"]) != "true" {
		t.Fatalf("identity_required = %s, want true", raw["identity_required"])
	}
	if _, ok := raw["token"]; ok {
		t.Fatal("manifest contains token content")
	}
	entries, err := os.ReadDir(f.registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != f.manifest.InstanceID+".json" && name != "."+f.manifest.InstanceID+".manifest.lock" {
			t.Fatalf("unexpected registry leftover: %s", name)
		}
	}
}

func TestLoadManifestAllowsProjectToBeTemporarilyUnavailable(t *testing.T) {
	f := newManifestFixture(t, "movable_project")
	if err := writeInstanceManifest(f.manifest); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.project, f.project+".moved"); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstanceManifest(f.manifest.InstanceID); err != nil {
		t.Fatalf("lifecycle manifest became unreadable after project move: %v", err)
	}
}

func TestStoppedManagedManifestBecomesOfflineReservation(t *testing.T) {
	f := newManifestFixture(t, "reserved_project")
	if err := writeInstanceManifest(f.manifest); err != nil {
		t.Fatal(err)
	}
	reserved, err := reserveInstanceManifestIfMatch(f.manifest)
	if err != nil || !reserved {
		t.Fatalf("reserve live manifest: reserved=%v err=%v", reserved, err)
	}
	got, err := loadInstanceManifest(f.manifest.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.IdentityRequired || got.PID != 0 || got.BrowserPID != 0 || got.ProcessStartedAt != "" {
		t.Fatalf("live lifecycle fields remained in reservation: %+v", got)
	}
	if got.APIBase != f.manifest.APIBase || got.Proxy != f.manifest.Proxy || got.CDPPort != f.manifest.CDPPort || got.StateDir != f.manifest.StateDir {
		t.Fatalf("runtime reservation changed: %+v", got)
	}
	stale := f.manifest
	stale.Generation = "replacement-generation"
	if replaced, err := reserveInstanceManifestIfMatch(stale); err != nil || replaced {
		t.Fatalf("stale stop replaced reservation: replaced=%v err=%v", replaced, err)
	}
}

func TestValidateManagedProjectRejectsMissingMismatchAndDuplicateIDs(t *testing.T) {
	f := newManifestFixture(t, "project_two")
	if _, err := validateManagedProject("project_two", f.project); err != nil {
		t.Fatal(err)
	}
	if _, err := validateManagedProject("other_project", f.project); err == nil {
		t.Fatal("expected project ID mismatch")
	}

	configPath := filepath.Join(f.project, ".codex", "config.toml")
	if err := os.WriteFile(configPath, []byte("[x]\nvalue = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateManagedProject("project_two", f.project); err == nil {
		t.Fatal("expected missing CAPX_INSTANCE_ID")
	}
	duplicate := "CAPX_INSTANCE_ID = 'project_two'\nCAPX_INSTANCE_ID = \"project_two\"\n"
	if err := os.WriteFile(configPath, []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateManagedProject("project_two", f.project); err == nil {
		t.Fatal("expected duplicate CAPX_INSTANCE_ID rejection")
	}
}

func TestValidateManagedProjectAcceptsClaudeMCPConfig(t *testing.T) {
	root := t.TempDir()
	project := filepath.Join(root, "Claude Project")
	if err := os.MkdirAll(filepath.Join(project, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	mcpConfig := `{
  "mcpServers": {
    "js-reverse": {
      "type": "stdio",
      "command": "node",
      "env": { "CAPX_INSTANCE_ID": "claude_project" }
    }
  }
}`
	if err := os.WriteFile(filepath.Join(project, ".mcp.json"), []byte(mcpConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateManagedProject("claude_project", project); err != nil {
		t.Fatal(err)
	}
	if _, err := validateManagedProject("other_project", project); err == nil {
		t.Fatal("expected Claude project ID mismatch")
	}

	badConfig := `{"mcpServers":{"one":{"env":{"CAPX_INSTANCE_ID":"claude_project"}},"two":{"env":{"CAPX_INSTANCE_ID":"claude_project"}}}}`
	if err := os.WriteFile(filepath.Join(project, ".mcp.json"), []byte(badConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateManagedProject("claude_project", project); err == nil {
		t.Fatal("expected duplicate Claude CAPX_INSTANCE_ID rejection")
	}
}

func TestWriteRejectsInvalidEndpointsPathsCDPAndLifecycle(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*instanceManifest)
	}{
		{"remote API", func(m *instanceManifest) { m.APIBase = "http://example.com:45101" }},
		{"API credentials", func(m *instanceManifest) { m.APIBase = "http://user:pass@127.0.0.1:45101" }},
		{"API path", func(m *instanceManifest) { m.APIBase = "http://127.0.0.1:45101/api" }},
		{"proxy query", func(m *instanceManifest) { m.Proxy = "http://127.0.0.1:45102/?x=1" }},
		{"external token", func(m *instanceManifest) { m.TokenFile = filepath.Join(filepath.Dir(m.StateDir), "token") }},
		{"zero CDP", func(m *instanceManifest) { m.CDPPort = 0 }},
		{"large CDP", func(m *instanceManifest) { m.CDPPort = 65536 }},
		{"port collision", func(m *instanceManifest) { m.CDPPort = 45102 }},
		{"missing PID", func(m *instanceManifest) { m.PID = 0 }},
		{"negative browser PID", func(m *instanceManifest) { m.BrowserPID = -1 }},
		{"bad process start time", func(m *instanceManifest) { m.ProcessStartedAt = "yesterday" }},
		{"missing generation", func(m *instanceManifest) { m.Generation = "" }},
		{"bad time", func(m *instanceManifest) { m.UpdatedAt = "yesterday" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newManifestFixture(t, "invalid_case")
			m := f.manifest
			tc.mutate(&m)
			if err := writeInstanceManifest(m); err == nil {
				t.Fatalf("expected %s to be rejected", tc.name)
			}
		})
	}
}

func TestLoadRejectsTokenContentAndAcceptsFrameworkManifestWithoutPID(t *testing.T) {
	f := newManifestFixture(t, "legacy_framework")
	if err := os.MkdirAll(f.registry, 0o700); err != nil {
		t.Fatal(err)
	}

	legacy := map[string]any{
		"schema_version": f.manifest.SchemaVersion,
		"instance_id":    f.manifest.InstanceID,
		"project_root":   f.manifest.ProjectRoot,
		"api_base":       f.manifest.APIBase,
		"proxy":          f.manifest.Proxy,
		"state_dir":      f.manifest.StateDir,
		"token_file":     f.manifest.TokenFile,
		"cdp_port":       f.manifest.CDPPort,
		"generation":     f.manifest.Generation,
		"updated_at":     f.manifest.UpdatedAt,
	}
	path := filepath.Join(f.registry, f.manifest.InstanceID+".json")
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadInstanceManifest(f.manifest.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if got.PID != 0 {
		t.Fatalf("legacy PID = %d, want 0", got.PID)
	}
	if got.IdentityRequired || got.BrowserPID != 0 || got.ProcessStartedAt != "" {
		t.Fatalf("legacy extension fields were unexpectedly populated: %+v", got)
	}
	if removed, err := removeInstanceManifestIfMatch(got.InstanceID, got.Generation, 1); err != nil || removed {
		t.Fatalf("legacy manifest was removed: removed=%v err=%v", removed, err)
	}

	legacy["token"] = "must-not-be-stored"
	data, _ = json.Marshal(legacy)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstanceManifest(f.manifest.InstanceID); err == nil || !strings.Contains(err.Error(), "forbidden token") {
		t.Fatalf("expected forbidden token rejection, got %v", err)
	}
}

func TestRemoveInstanceManifestRequiresGenerationAndPIDMatch(t *testing.T) {
	f := newManifestFixture(t, "safe_remove")
	if err := writeInstanceManifest(f.manifest); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.registry, f.manifest.InstanceID+".json")

	removed, err := removeInstanceManifestIfMatch(f.manifest.InstanceID, "wrong-generation", f.manifest.PID)
	if err != nil || removed {
		t.Fatalf("generation mismatch: removed=%v err=%v", removed, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("manifest disappeared after generation mismatch: %v", err)
	}

	removed, err = removeInstanceManifestIfMatch(f.manifest.InstanceID, f.manifest.Generation, f.manifest.PID+1)
	if err != nil || removed {
		t.Fatalf("PID mismatch: removed=%v err=%v", removed, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("manifest disappeared after PID mismatch: %v", err)
	}

	removed, err = removeInstanceManifestIfMatch(f.manifest.InstanceID, f.manifest.Generation, f.manifest.PID)
	if err != nil || !removed {
		t.Fatalf("exact removal: removed=%v err=%v", removed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("manifest remains after exact removal: %v", err)
	}
}

func TestConcurrentManifestWritesAlwaysLeaveCompleteJSON(t *testing.T) {
	f := newManifestFixture(t, "concurrent")
	const writers = 24
	errCh := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m := f.manifest
			m.PID = 20000 + i
			m.Generation = fmt.Sprintf("generation-%02d", i)
			m.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
			errCh <- writeInstanceManifest(m)
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := loadInstanceManifest(f.manifest.InstanceID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.Generation, "generation-") || got.PID < 20000 || got.PID >= 20000+writers {
		t.Fatalf("unexpected winning manifest: %+v", got)
	}
	entries, err := os.ReadDir(f.registry)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != f.manifest.InstanceID+".json" && name != "."+f.manifest.InstanceID+".manifest.lock" {
			t.Fatalf("temporary file remains after concurrent writes: %s", name)
		}
	}
}
