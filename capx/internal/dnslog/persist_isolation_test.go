package dnslog

import (
	"path/filepath"
	"testing"
)

func TestDefaultPersistPathHonorsIsolatedDataDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CAPX_DATA_DIR", dir)
	if got := DefaultPersistPath(); got != filepath.Join(dir, "dnslog.json") {
		t.Fatalf("DNSLog escaped isolated state directory: %s", got)
	}
}
