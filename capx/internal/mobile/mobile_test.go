package mobile

import (
	"strings"
	"testing"
)

const sampleDump = `<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>
<hierarchy rotation="0">
  <node index="0" text="" resource-id="" class="android.widget.FrameLayout" package="com.tencent.mm" content-desc="" clickable="false" scrollable="false" focused="false" bounds="[0,0][1080,2340]">
    <node index="0" text="微信" resource-id="android:id/text1" class="android.widget.TextView" package="com.tencent.mm" content-desc="" clickable="true" scrollable="false" focused="false" bounds="[40,100][240,180]" />
    <node index="1" text="" resource-id="com.tencent.mm:id/search" class="android.widget.ImageView" package="com.tencent.mm" content-desc="搜索" clickable="true" scrollable="false" focused="false" bounds="[900,90][1000,190]" />
    <node index="2" text="" resource-id="" class="android.widget.LinearLayout" package="com.tencent.mm" content-desc="" clickable="false" scrollable="true" focused="false" bounds="[0,200][1080,2200]" />
  </node>
</hierarchy>
UI hierchary dumped to: /sdcard/capx_ui_dump.xml`

func TestParseUIDumpInteractable(t *testing.T) {
	els, err := parseUIDump(stripDumpNoise([]byte(sampleDump)), true)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The bare root FrameLayout has no text/desc/id and isn't clickable, so it
	// is dropped; the three meaningful nodes remain.
	if len(els) != 3 {
		t.Fatalf("want 3 interactable elements, got %d: %+v", len(els), els)
	}
	first := els[0]
	if first.Text != "微信" || !first.Clickable {
		t.Fatalf("unexpected first element: %+v", first)
	}
	if first.X != 140 || first.Y != 140 {
		t.Fatalf("center = (%d,%d), want (140,140)", first.X, first.Y)
	}
	if first.Width != 200 || first.Height != 80 {
		t.Fatalf("size = (%d,%d), want (200,80)", first.Width, first.Height)
	}
}

func TestLocatorMatch(t *testing.T) {
	els, err := parseUIDump(stripDumpNoise([]byte(sampleDump)), false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	find := func(l Locator) (Element, bool) {
		for _, e := range els {
			if e.Width > 0 && e.Height > 0 && l.matches(e) {
				return e, true
			}
		}
		return Element{}, false
	}

	if e, ok := find(Locator{Text: "微信"}); !ok || e.X != 140 {
		t.Fatalf("text locator failed: %+v ok=%v", e, ok)
	}
	if e, ok := find(Locator{Desc: "搜索"}); !ok || e.X != 950 {
		t.Fatalf("desc locator failed: %+v ok=%v", e, ok)
	}
	if e, ok := find(Locator{ResourceID: "search"}); !ok || e.Desc != "搜索" {
		t.Fatalf("resource-id locator failed: %+v ok=%v", e, ok)
	}
	if _, ok := find(Locator{Text: "不存在"}); ok {
		t.Fatalf("expected no match for missing text")
	}
	if l := (Locator{}); !l.empty() {
		t.Fatalf("empty locator should report empty")
	}
}

const sampleDumpsys = `  ACTIVITY com.miui.home/.launcher.Launcher 1234 pid=5678
    mCurrentConfig={1.0 ?mcc?mnc [zh_CN] ldltr ...}
    View Hierarchy:
      DecorView{a1 V.E...... .......D 0,0-1080,2280}
        FrameLayout{b2 V.E...... .......D 0,82-1080,2236 #7f0a0001 android:id/content}
          LinearLayout{c3 V.ED..... ......ID 65,52-255,236 #7f0a0002 app:id/icon_container}
            ImageView{d4 V.ED..... ......ID 11,16-179,184 #7f0a0003 app:id/icon_icon}
          TextView{e5 G.ED..... ........ 0,0-100,50 #7f0a0004 app:id/hidden_label}`

func TestParseDumpsysAbsoluteCoords(t *testing.T) {
	all := parseDumpsysTop([]byte(sampleDumpsys), false)
	// DecorView + content + container + icon are visible; hidden_label is GONE.
	if len(all) != 4 {
		t.Fatalf("want 4 visible elements, got %d: %+v", len(all), all)
	}
	var icon *Element
	for i := range all {
		if strings.Contains(all[i].ResourceID, "icon_icon") {
			icon = &all[i]
		}
	}
	if icon == nil {
		t.Fatalf("icon_icon not found in %+v", all)
	}
	// Absolute = DecorView(0,0) + content(0,82) + container(65,52) + icon(11,16).
	if icon.X != 160 || icon.Y != 234 {
		t.Fatalf("icon center = (%d,%d), want (160,234)", icon.X, icon.Y)
	}
	if icon.Width != 168 || icon.Height != 168 {
		t.Fatalf("icon size = (%d,%d), want (168,168)", icon.Width, icon.Height)
	}
	if icon.Bounds != "[76,150][244,318]" {
		t.Fatalf("icon bounds = %q, want [76,150][244,318]", icon.Bounds)
	}
	// The resource id must not carry the view line's trailing brace.
	if icon.ResourceID != "app:id/icon_icon" {
		t.Fatalf("icon resource id = %q, want app:id/icon_icon", icon.ResourceID)
	}

	// interactableOnly drops the DecorView (no resource id) and GONE label.
	inter := parseDumpsysTop([]byte(sampleDumpsys), true)
	if len(inter) != 3 {
		t.Fatalf("want 3 interactable elements, got %d: %+v", len(inter), inter)
	}
	if _, ok := findByResID(inter, "icon_container"); !ok {
		t.Fatalf("expected icon_container in interactable set")
	}
}

func findByResID(els []Element, want string) (Element, bool) {
	for _, e := range els {
		if strings.Contains(e.ResourceID, want) {
			return e, true
		}
	}
	return Element{}, false
}

func TestControllerSerialResolution(t *testing.T) {
	c := &Controller{run: func(serial string, args ...string) (string, error) {
		return "List of devices attached\nABC123\tdevice product:x model:Pixel\n", nil
	}}
	s, err := c.Serial()
	if err != nil || s != "ABC123" {
		t.Fatalf("serial = %q err = %v, want ABC123", s, err)
	}

	c.Use("PINNED")
	if s, _ := c.Serial(); s != "PINNED" {
		t.Fatalf("pinned serial = %q, want PINNED", s)
	}
}

func TestDevicesParsesModel(t *testing.T) {
	c := &Controller{run: func(serial string, args ...string) (string, error) {
		return "List of devices attached\nABC123\tdevice product:sirius model:MI_8_Lite device:platina\nXYZ\tunauthorized\n", nil
	}}
	devs, err := c.Devices()
	if err != nil {
		t.Fatalf("devices: %v", err)
	}
	if len(devs) != 2 {
		t.Fatalf("want 2 devices, got %d", len(devs))
	}
	if devs[0].Model != "MI_8_Lite" || devs[0].State != "device" {
		t.Fatalf("unexpected device[0]: %+v", devs[0])
	}
	if devs[1].State != "unauthorized" {
		t.Fatalf("unexpected device[1]: %+v", devs[1])
	}
}
