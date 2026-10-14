package main

import (
	"strings"
	"testing"
)

func TestManagedUIIsInjected(t *testing.T) {
	var page strings.Builder
	if err := renderManagerIndex(&page); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"instanceId",
		"projectRoot",
		"cdpPort",
		"autoPorts",
		"generateSRCTemplate",
		"srcTemplatePanel",
		"showRuntimeSRCTemplate",
		"selectProjectDirectory",
		"selectJADXDirectory",
		"jadxDir",
		"只显示所选项目实例",
		"SRC模板",
		"复制全部",
		"instance_id",
		"min-width: 0",
		".check > input",
		"停止全部服务",
		"停止全部 Capx、Ghost、ADB 和代理浏览器",
		"@media(max-width:600px)",
		"grid-template-columns:repeat(2,minmax(0,1fr))",
		"selectCustomPorts",
		"capx.autoPorts",
		"使用表单中的自定义端口",
	} {
		if !strings.Contains(page.String(), expected) {
			t.Fatalf("rendered manager UI is missing %q", expected)
		}
	}
}

func TestManagerUIEmbedsModernWorkspaceAssets(t *testing.T) {
	var page strings.Builder
	if err := renderManagerIndex(&page); err != nil {
		t.Fatal(err)
	}
	html := page.String()
	for _, expected := range []string{
		"CAPX · 实例管理",
		"--bg: #f4f6f8",
		"--acc: #0c8c81",
		`id="launchConfig"`,
		`id="instancesPanel"`,
		`id="usageGuide"`,
		`class="integrations"`,
		`class="instance-toolbar"`,
		`aria-live="polite"`,
		`for="apiPort"`,
		`for="instanceId"`,
		`for="projectRoot"`,
		`for="cdpPort"`,
		"prefers-reduced-motion",
		"还没有运行中的实例",
		"/api/instances",
	} {
		if !strings.Contains(html, expected) {
			t.Errorf("rendered manager workspace is missing %q", expected)
		}
	}
	for _, obsolete := range []string{
		"/* manager styles */",
		"/* manager script */",
		"responsiveStyle.textContent",
		"linear-gradient(",
		"radial-gradient(",
	} {
		if strings.Contains(html, obsolete) {
			t.Errorf("rendered manager workspace still contains %q", obsolete)
		}
	}
}

func TestManagerUIKeepsRuntimeControls(t *testing.T) {
	var page strings.Builder
	if err := renderManagerIndex(&page); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"capturedPath", "ghostPath", "adbPath", "adbSerial", "apiPort", "proxyPort",
		"count", "autoProxy", "allowActive", "openAfterStart", "showOnlyPath",
		"instanceId", "projectRoot", "jadxDir", "cdpPort", "autoPorts",
		"srcTemplatePanel", "srcTemplateMeta", "srcTemplateOutput",
		"btnOpenAll", "btnOpenAllBrowsers", "status", "tbody", "mCount", "mApi",
		"mProxy", "mapHint", "toast", "clock",
	} {
		if !strings.Contains(page.String(), `id="`+id+`"`) {
			t.Errorf("runtime control %q is missing", id)
		}
	}
}
