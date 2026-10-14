package main

import (
	"net/http"
	"net/http/httptest"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestRenderSRCTemplateUsesDynamicConnectionAndCompleteHuntingQueue(t *testing.T) {
	text, err := renderSRCTemplate(srcTemplateData{
		Source:       "runtime",
		InstanceID:   "src_demo",
		ProjectRoot:  `F:\111\src_demo`,
		JADXDir:      `F:\tools\jadx`,
		APIPort:      19086,
		ProxyPort:    18076,
		CDPPort:      9349,
		StateDir:     `C:\state\src_demo`,
		TokenFile:    `C:\state\src_demo\token`,
		Token:        "token-value",
		ManifestPath: `C:\instances\src_demo.json`,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{
		"Capx SRC 完整挖掘会话模板",
		`CAPX_INSTANCE_ID = "src_demo"`,
		"ByteSRC 公开规则",
	}
	if runtime.GOOS == "windows" {
		expected = append(expected,
			`$ManifestPath = Join-Path`,
			`$env:CAPX_TOKEN = $Token`,
			`base_url: "$env:CAPX_API_BASE"`,
			`proxy_addr: "$env:CAPX_PROXY_HOST`,
		)
	} else {
		expected = append(expected,
			`export CAPX_INSTANCE_ID='src_demo'`,
			`base_url: "$CAPX_API_BASE"`,
			`proxy_addr: "$CAPX_PROXY_HOST:$CAPX_PROXY_PORT"`,
		)
	}
	for _, want := range expected {
		if !strings.Contains(text, want) {
			t.Fatalf("template is missing %q\n%s", want, text)
		}
	}
	for _, forbidden := range []string{
		"token-value",
		"19086",
		"18076",
		"9349",
		`F:\tools\jadx`,
		`C:\state\src_demo`,
		`C:\instances\src_demo.json`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("template contains runtime-specific value %q\n%s", forbidden, text)
		}
	}
	if len(text) < 3000 {
		t.Fatalf("complete template is unexpectedly short: %d bytes", len(text))
	}
}

func TestRenderSRCTemplateUsesPendingValuesBeforeStart(t *testing.T) {
	text, err := renderSRCTemplate(srcTemplateData{
		Source:     "form",
		InstanceID: "src_19086",
		APIPort:    19086,
		ProxyPort:  18076,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "阶段：启动前") ||
		!strings.Contains(text, "模式：legacy") ||
		!strings.Contains(text, "legacy 实例没有项目 manifest") ||
		!strings.Contains(text, "ByteSRC 公开规则") ||
		strings.Contains(text, "127.0.0.1:19086") ||
		strings.Contains(text, "127.0.0.1:18076") {
		t.Fatalf("pre-start template does not expose pending runtime values:\n%s", text)
	}
}

func TestResolveSRCTemplateAllowsAutomaticManagedPorts(t *testing.T) {
	data, err := resolveSRCTemplateData(srcTemplateRequest{
		InstanceID: "src_demo", ProjectRoot: `F:\111\src_demo`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if data.Mode != "managed" || data.APIPort != 0 || data.ProxyPort != 0 || data.CDPPort != 0 {
		t.Fatalf("unexpected automatic managed template data: %+v", data)
	}
}

func TestGeneratedManagedPowerShellParses(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell syntax check is Windows-specific")
	}
	powerShell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("powershell.exe is not available")
	}
	text, err := renderSRCTemplate(srcTemplateData{
		Source:      "form",
		Mode:        "managed",
		InstanceID:  "src_demo",
		ProjectRoot: `F:\111\src_demo`,
	})
	if err != nil {
		t.Fatal(err)
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	const opening = "```powershell\n"
	start := strings.Index(text, opening)
	if start < 0 {
		t.Fatal("managed PowerShell block is missing")
	}
	remainder := text[start+len(opening):]
	end := strings.Index(remainder, "\n```")
	if end < 0 {
		t.Fatal("managed PowerShell block is not closed")
	}
	script := remainder[:end]
	command := exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-Command",
		"$source=[Console]::In.ReadToEnd(); [ScriptBlock]::Create($source) | Out-Null")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated PowerShell does not parse: %v\n%s\n%s", err, output, script)
	}
}

func TestGeneratedManagedBashParses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash template is generated on non-Windows platforms only")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not available")
	}
	text, err := renderSRCTemplate(srcTemplateData{
		Source:      "form",
		Mode:        "managed",
		InstanceID:  "src_demo",
		ProjectRoot: "/srv/src_demo",
	})
	if err != nil {
		t.Fatal(err)
	}
	const opening = "```bash\n"
	start := strings.Index(text, opening)
	if start < 0 {
		t.Fatal("managed bash block is missing")
	}
	remainder := text[start+len(opening):]
	end := strings.Index(remainder, "\n```")
	if end < 0 {
		t.Fatal("managed bash block is not closed")
	}
	script := remainder[:end]
	command := exec.Command(bash, "-n")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated bash does not parse: %v\n%s\n%s", err, output, script)
	}
}

func TestNormalizeSRCTemplateRejectsConflictingPorts(t *testing.T) {
	_, err := normalizeSRCTemplateData(srcTemplateData{
		InstanceID: "src_demo",
		APIPort:    19086,
		ProxyPort:  19086,
	})
	if err == nil || !strings.Contains(err.Error(), "彼此独立") {
		t.Fatalf("expected independent-port error, got %v", err)
	}
}

func TestResolveSRCTemplateUsesSelectedRuntime(t *testing.T) {
	original := srcTemplateInstanceLister
	t.Cleanup(func() { srcTemplateInstanceLister = original })
	srcTemplateInstanceLister = func(string, bool) ([]instance, error) {
		return []instance{{
			InstanceID: "runtime_src", ProjectDir: `F:\111\runtime_src`,
			APIPort: 19086, ProxyPort: 18076, CDPPort: 9349,
			StateDir: `C:\state\runtime_src`, Token: "runtime-token",
		}}, nil
	}
	data, err := resolveSRCTemplateData(srcTemplateRequest{RuntimeAPIPort: 19086})
	if err != nil {
		t.Fatal(err)
	}
	if data.Source != "runtime" || data.Token != "runtime-token" || data.InstanceID != "runtime_src" {
		t.Fatalf("unexpected runtime template data: %+v", data)
	}
}

func TestResolveSRCTemplateRequiresCompleteManagedIdentity(t *testing.T) {
	_, err := resolveSRCTemplateData(srcTemplateRequest{
		InstanceID: "src_demo", APIPort: 19086, ProxyPort: 18076, CDPPort: 9349,
	})
	if err == nil || !strings.Contains(err.Error(), "同时填写") {
		t.Fatalf("expected incomplete managed identity error, got %v", err)
	}

	legacy, err := resolveSRCTemplateData(srcTemplateRequest{
		APIPort: 19086, ProxyPort: 18076, CDPPort: 9349,
	})
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Mode != "legacy" || legacy.CDPPort != 0 {
		t.Fatalf("legacy template exposed a managed CDP: %+v", legacy)
	}
}

func TestHandleSRCTemplateReturnsUTF8JSON(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/src-template", strings.NewReader(
		`{"instance_id":"src_demo","project_root":"F:\\111\\src_demo","api_port":19086,"proxy_port":18076,"cdp_port":9349}`,
	))
	recorder := httptest.NewRecorder()
	handleSRCTemplate(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if contentType := recorder.Header().Get("Content-Type"); !strings.Contains(contentType, "charset=utf-8") {
		t.Fatalf("content type does not declare UTF-8: %q", contentType)
	}
	for _, expected := range []string{"SRC 模板已生成", "Capx SRC 完整挖掘会话模板", `"token_ready":false`} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("response is missing %q: %s", expected, recorder.Body.String())
		}
	}
}
