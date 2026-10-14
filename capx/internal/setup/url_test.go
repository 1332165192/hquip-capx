package setup

import "testing"

func TestSanitizeStartURL(t *testing.T) {
	cases := map[string]string{
		"":                      "https://example.com",
		"   ":                   "https://example.com",
		"example.com":           "https://example.com",
		"https://target.test/":  "https://target.test/",
		"http://127.0.0.1:8080": "http://127.0.0.1:8080",
		"javascript:alert(1)":   "https://example.com",
		"file:///c:/windows":    "https://example.com",
	}
	for in, want := range cases {
		if got := sanitizeStartURL(in); got != want {
			t.Errorf("sanitizeStartURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShouldSkipBrowserRestart(t *testing.T) {
	skip := []string{
		`chrome.exe --user-data-dir=C:\Users\a\AppData\Local\capx\chrome-capture-profile`,
		`msedge.exe --user-data-dir=C:\Users\a\AppData\Local\capx-desktop\profile --app=http://127.0.0.1:9`,
		`chrome.exe --app=http://127.0.0.1:19091/`,
	}
	for _, cmd := range skip {
		if !shouldSkipBrowserRestart(cmd) {
			t.Errorf("should skip %q", cmd)
		}
	}
	keep := `chrome.exe --user-data-dir=C:\Users\a\AppData\Local\Google\Chrome\User Data`
	if shouldSkipBrowserRestart(keep) {
		t.Errorf("should not skip daily chrome: %q", keep)
	}
}

func TestExtractUserDataDir(t *testing.T) {
	cmd := `C:\Program Files\Google\Chrome\Application\chrome.exe --user-data-dir="C:\Users\a\AppData\Local\Google\Chrome\User Data" --restore-last-session`
	got := extractUserDataDir(cmd)
	want := `C:\Users\a\AppData\Local\Google\Chrome\User Data`
	if got != want {
		t.Fatalf("extractUserDataDir = %q, want %q", got, want)
	}
	if extractUserDataDir("chrome.exe") != "" {
		t.Fatal("expected empty user-data-dir")
	}
}
