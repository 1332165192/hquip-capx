package main

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestBackendCandidatesIncludeApplicationBundleAndDeveloperOutputs(t *testing.T) {
	root := t.TempDir()
	for _, platform := range []string{"windows", "linux", "darwin"} {
		name := "capx-captured"
		gui := filepath.Join(root, "app", "capx-desktop")
		if platform == "windows" {
			name += ".exe"
			gui += ".exe"
		}
		if platform == "darwin" {
			gui = filepath.Join(root, "capx-desktop.app", "Contents", "MacOS", "capx-desktop")
		}
		candidates := backendCandidates(platform, gui, root)
		if !slices.Contains(candidates, filepath.Join(filepath.Dir(gui), name)) {
			t.Fatal("missing bundled backend", platform)
		}
		if !slices.Contains(candidates, filepath.Join(root, "capx", "dist", name)) {
			t.Fatal("missing developer output", platform)
		}
	}
}
