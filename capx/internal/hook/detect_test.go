package hook

import "testing"

func TestLookFileEmpty(t *testing.T) {
	if lookFile("") != "" {
		t.Fatal("empty path should miss")
	}
}

func TestDetectFridaCLIHonorsEnv(t *testing.T) {
	t.Setenv("CAPX_FRIDA", "")
	// Should not panic; result may be empty on CI.
	_ = detectFridaCLI()
}

func TestFileExistsMissing(t *testing.T) {
	if fileExists(filepathJoinBogus()) {
		t.Fatal("missing file reported present")
	}
}

func filepathJoinBogus() string { return "definitely-not-a-frida-binary-zzzz" }
