package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectProjectBindingReadsCodexInstanceID(t *testing.T) {
	project := t.TempDir()
	configDir := filepath.Join(project, ".codex")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := "[mcp_servers.js_reverse.env]\nCAPX_INSTANCE_ID = \"selected_project\"\n"
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	id, bound, err := inspectProjectBinding(project)
	if err != nil {
		t.Fatal(err)
	}
	if id != "selected_project" || !bound {
		t.Fatalf("unexpected binding: id=%q bound=%v", id, bound)
	}
}

func TestInspectProjectBindingDerivesIDForUnboundDirectory(t *testing.T) {
	project := filepath.Join(t.TempDir(), "New SRC Project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	id, bound, err := inspectProjectBinding(project)
	if err != nil {
		t.Fatal(err)
	}
	if id != "new_src_project" || bound {
		t.Fatalf("unexpected derived binding: id=%q bound=%v", id, bound)
	}
}

func TestHandleSelectDirectoryReturnsProjectMetadata(t *testing.T) {
	project := t.TempDir()
	configDir := filepath.Join(project, ".codex")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte("CAPX_INSTANCE_ID = 'picker_project'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := directorySelector
	t.Cleanup(func() { directorySelector = original })
	directorySelector = func(initial, description string) (string, error) {
		if description == "" {
			t.Fatal("directory description is empty")
		}
		return project, nil
	}

	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/select-directory", strings.NewReader(`{"kind":"project"}`))
	recorder := httptest.NewRecorder()
	handleSelectDirectory(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, expected := range []string{`"instance_id":"picker_project"`, `"project_bound":true`, "目录已选择"} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("response missing %q: %s", expected, recorder.Body.String())
		}
	}
}

func TestJADXDirectoryDetection(t *testing.T) {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "jadx.bat"), []byte("@echo off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !jadxDirectoryDetected(root) {
		t.Fatal("JADX directory was not detected")
	}
}
