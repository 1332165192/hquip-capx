package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSuiteRootFromPacketRoot(t *testing.T) {
	repository := filepath.Join("workspace", "agent_ai")
	packetRoot := filepath.Join(repository, "packet-capture")
	if got := suiteRootFromPacketRoot(packetRoot); got != repository {
		t.Fatalf("suite root=%q want=%q", got, repository)
	}
	if got := suiteRootFromPacketRoot(repository); got != repository {
		t.Fatalf("legacy suite root=%q want=%q", got, repository)
	}
}

func TestMigrateCapturedPathOnlyUsesExistingNewLayout(t *testing.T) {
	root := t.TempDir()
	oldPath := filepath.Join(root, "capx-desktop", "build", "bin", "captured.exe")
	newPath := filepath.Join(root, "packet-capture", "capx-desktop", "build", "bin", "captured.exe")
	if err := os.MkdirAll(filepath.Dir(newPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := migrateCapturedPath(oldPath); got != newPath {
		t.Fatalf("migrated path=%q want=%q", got, newPath)
	}
	custom := filepath.Join(root, "custom", "missing.exe")
	if got := migrateCapturedPath(custom); got != custom {
		t.Fatalf("custom path changed to %q", got)
	}
}

func TestDiscoverLayoutFromProductAndRepositoryBin(t *testing.T) {
	repository := t.TempDir()
	packet := filepath.Join(repository, "packet-capture")
	for _, directory := range []string{
		filepath.Join(packet, "capx"),
		filepath.Join(packet, "capx-desktop"),
		filepath.Join(packet, "capx-web-manager"),
		filepath.Join(repository, "bin"),
	} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, start := range []string{
		filepath.Join(packet, "capx-web-manager"),
		filepath.Join(repository, "bin"),
	} {
		gotPacket, gotRepository := discoverLayout(start)
		if gotPacket != packet || gotRepository != repository {
			t.Fatalf("start=%q packet=%q repository=%q", start, gotPacket, gotRepository)
		}
	}
}
