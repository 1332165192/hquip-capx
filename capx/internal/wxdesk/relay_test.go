package wxdesk

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readyRelay(t *testing.T) (*relayBackend, relayStatus) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"channel/requests", "channel/responses"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	status := relayStatus{Session: strings.Repeat("a", 32), UpdatedAt: time.Now().UTC(), Mode: "windows-sandbox", Protocol: 2}
	writeTestJSON(t, filepath.Join(root, "channel", "ready.json"), status)
	return &relayBackend{root: root}, status
}
func writeTestJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestRelayHasNoHostFallbackAndRejectsStaleSessions(t *testing.T) {
	b := &relayBackend{root: t.TempDir()}
	if b.Available() {
		t.Fatal("unconnected relay reported available")
	}
	if _, err := b.Windows(); err == nil {
		t.Fatal("must not enumerate host WeChat when isolated relay is absent")
	}
	b, status := readyRelay(t)
	if !b.Available() {
		t.Fatal("fresh relay should be available")
	}
	for _, change := range []func(*relayStatus){func(s *relayStatus) { s.Mode = "host" }, func(s *relayStatus) { s.Protocol = 1 }, func(s *relayStatus) { s.UpdatedAt = time.Now().Add(-time.Minute) }, func(s *relayStatus) { s.Session = "short" }, func(s *relayStatus) { s.UpdatedAt = time.Now().Add(time.Hour) }} {
		invalid := status
		change(&invalid)
		writeTestJSON(t, filepath.Join(b.root, "channel", "ready.json"), invalid)
		if b.Available() {
			t.Fatalf("invalid session accepted: %+v", invalid)
		}
	}
}

func TestRelayTargetsSandboxAndReturnsPixels(t *testing.T) {
	b, status := readyRelay(t)
	requestSeen := make(chan relayRequest, 1)
	workerErr := make(chan error, 1)
	picture := []byte("\x89PNG\r\n\x1a\nfixture")
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(filepath.Join(b.root, "channel", "request.json"))
			if err == nil && len(data) > 2 {
				var req relayRequest
				if err = json.Unmarshal(data, &req); err != nil {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				requestSeen <- req
				response := relayResponse{Session: status.Session, Status: 200, Image: base64.StdEncoding.EncodeToString(picture)}
				data, err = json.Marshal(response)
				if err == nil {
					err = os.WriteFile(filepath.Join(b.root, "channel", "responses", req.ID+".json"), data, 0600)
				}
				workerErr <- err
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		workerErr <- os.ErrDeadlineExceeded
	}()
	got, err := b.Screenshot("ff:12:34")
	if err != nil || string(got) != string(picture) {
		t.Fatalf("image=%q err=%v", got, err)
	}
	req := <-requestSeen
	if req.Session != status.Session || req.Method != "GET" || req.Path != "/api/wxdesk/screenshot?window_id=ff%3A12%3A34" {
		t.Fatalf("unexpected request: %+v", req)
	}
	if err := <-workerErr; err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(b.root, "channel", "request.json")); err != nil || string(data) != "{}" {
		t.Fatalf("mailbox not cleared: %q %v", data, err)
	}
	for _, folder := range []string{"requests", "responses"} {
		files, _ := filepath.Glob(filepath.Join(b.root, "channel", folder, "*.json"))
		if len(files) != 0 {
			t.Fatalf("request/response not consumed: %v", files)
		}
	}
}

func TestPackageMapsOnlyBinariesAndDedicatedChannel(t *testing.T) {
	base := t.TempDir()
	sourceDir := filepath.Join(base, "official-binaries")
	root := filepath.Join(base, "box")
	if err := os.MkdirAll(sourceDir, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(sourceDir, "Weixin.exe")
	backend := filepath.Join(base, "captured.exe")
	for _, path := range []string{source, backend} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := writePackage(root, source, backend, false)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(result.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	var config sandboxConfig
	if err = xml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.MappedFolders) != 3 || !config.MappedFolders[0].ReadOnly || !config.MappedFolders[1].ReadOnly || config.MappedFolders[2].ReadOnly {
		t.Fatalf("invalid mapping: %+v", config.MappedFolders)
	}
	if config.MappedFolders[1].HostFolder != sourceDir || config.MappedFolders[2].HostFolder != filepath.Join(root, "channel") {
		t.Fatalf("unexpected shared host data: %+v", config.MappedFolders)
	}
	if config.ClipboardRedirection != "Disable" || config.AudioInput != "Disable" || config.VideoInput != "Disable" {
		t.Fatal("unexpected sharing")
	}
	for _, name := range []string{"capx-captured.exe", "Relay.ps1", "Start-Environment.ps1", "environment.json"} {
		if _, err = os.Stat(filepath.Join(root, "assets", name)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = writePackage(root, filepath.Join(sourceDir, "WeChatAppEx.exe"), backend, false); err == nil {
		t.Fatal("standalone AppEx cannot be accepted as a login client")
	}
}

func TestInstallerPackageNeedsNoInstalledClientOrHostFolderMapping(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "下载 & official setup.exe")
	backend := filepath.Join(base, "captured.exe")
	root := filepath.Join(base, "box")
	if err := os.WriteFile(source, []byte("signed installer fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backend, []byte("backend fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	verified := ""
	result, err := writeSourcePackage(root, source, backend, false, true, func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if string(data) != "signed installer fixture" {
			t.Fatal("not verifying copied installer bytes")
		}
		verified = path
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SourceMode != "installer" || !result.InstallerVerified || verified == source {
		t.Fatalf("installer metadata/verification incorrect: %+v verified=%q", result, verified)
	}
	data, err := os.ReadFile(result.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	var config sandboxConfig
	if err = xml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.MappedFolders) != 2 || !config.MappedFolders[0].ReadOnly || config.MappedFolders[1].ReadOnly {
		t.Fatalf("wrong installer mapping: %+v", config.MappedFolders)
	}
	if strings.Contains(string(data), "WeChatSource") || strings.Contains(string(data), filepath.Dir(source)+"</HostFolder>") {
		t.Fatal("installer mode exposed host installation or Downloads")
	}
	metadata, err := os.ReadFile(filepath.Join(root, "assets", "environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(metadata), `"source_mode": "installer"`) || !strings.Contains(string(metadata), `"installer_verified": true`) {
		t.Fatalf("wrong bootstrap configuration: %s", metadata)
	}
	if _, err = os.Stat(filepath.Join(root, "assets", "WeChatSetup.exe")); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(verified); !os.IsNotExist(err) {
		t.Fatal("staged installer was not cleaned")
	}
}

func TestInvalidInstallerIsNotPackagedForExecution(t *testing.T) {
	base := t.TempDir()
	source := filepath.Join(base, "setup.exe")
	backend := filepath.Join(base, "captured.exe")
	root := filepath.Join(base, "box")
	for _, path := range []string{source, backend} {
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := writeSourcePackage(root, source, backend, false, true, func(string) error { return os.ErrPermission })
	if err == nil {
		t.Fatal("invalid signature accepted")
	}
	for _, path := range []string{filepath.Join(root, "assets", "WeChatSetup.exe"), filepath.Join(root, "assets", "environment.json"), filepath.Join(root, "WeChat-Test.wsb")} {
		if _, err = os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("unverified installer became runnable: %s", path)
		}
	}
	files, _ := filepath.Glob(filepath.Join(root, "assets", "wechat-setup-*.exe"))
	if len(files) != 0 {
		t.Fatalf("unverified staged installer left behind: %v", files)
	}
}

func TestOnlyValidTencentInstallerSignatureIsAccepted(t *testing.T) {
	for _, caseValue := range []struct {
		status, subject string
		valid           bool
	}{
		{"Valid", "CN=Tencent Technology (Shenzhen) Company Limited, O=Tencent Technology (Shenzhen) Company Limited, C=CN", true},
		{"Valid", "O=Tencent Technology(Shenzhen) Company Limited, C=CN", true},
		{"NotSigned", "O=Tencent Technology (Shenzhen) Company Limited", false},
		{"HashMismatch", "O=Tencent Technology (Shenzhen) Company Limited", false},
		{"Valid", "CN=Tencent, O=Unrelated Company", false},
		{"Valid", "O=Tencent Technology (Shenzhen) Company Limited Evil, C=CN", false},
	} {
		if got := validateTencentSignature(caseValue.status, caseValue.subject) == nil; got != caseValue.valid {
			t.Fatalf("signature %q %q accepted=%v", caseValue.status, caseValue.subject, got)
		}
	}
}
