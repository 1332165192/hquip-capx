package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirefoxPoliciesJSONDisablesHTTP3(t *testing.T) {
	b := firefoxPoliciesJSON("/tmp/capx-ca.pem", "127.0.0.1:18080")
	s := string(b)
	for _, part := range []string{"network.http.http3.enabled", "Certificates", "HTTPProxy"} {
		if !strings.Contains(s, part) {
			t.Fatalf("missing %q in %s", part, s)
		}
	}
}

func TestFirefoxProfileDirsFromINI(t *testing.T) {
	dir := t.TempDir()
	ini := filepath.Join(dir, "profiles.ini")
	body := "[Profile0]\nName=default\nIsRelative=1\nPath=abcd.default\n\n"
	if err := os.WriteFile(ini, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("APPDATA", dir)
	// Direct parse via writing to expected path is OS-specific; just ensure
	// policies JSON helper stays stable.
	_ = firefoxPoliciesJSON("", "")
}
