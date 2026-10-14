package wxapkg

// Best-effort source reconstruction from an unpacked bundle (the "B" depth):
//   - app.json + per-page .json   (split from app-config.json)
//   - per-page .js                (define("path", function(){...}) blocks)
//   - .wxss                       (parsed from setCssToHead([...]) literals)
// Compiled WXML uses version-specific view-layer functions. Recovering those
// templates is outside this static reconstructor; bundle JS is never executed.

import (
	"encoding/json"
	"strings"
)

// Reconstruct returns recovered files plus human-readable notes.
func Reconstruct(files []File) (extra []File, notes []string) {
	byName := map[string][]byte{}
	for _, f := range files {
		byName[strings.TrimLeft(filepathSlash(f.Name), "/")] = f.Data
	}

	if ac := byName["app-config.json"]; ac != nil {
		cf, n := splitConfig(ac)
		extra = append(extra, cf...)
		notes = append(notes, n)
	} else {
		notes = append(notes, "未找到 app-config.json，跳过配置还原")
	}

	jsCount, wxssCount, skipped := 0, 0, 0
	var modules, styles []File
	for _, f := range files {
		if !strings.HasSuffix(f.Name, ".js") {
			continue
		}
		d, c, n := reconstructJS(string(f.Data))
		modules = append(modules, d...)
		styles = append(styles, c...)
		skipped += n
	}
	extra = append(extra, modules...)
	extra = append(extra, styles...)
	jsCount, wxssCount = len(modules), len(styles)
	notes = append(notes, sprintf("拆分出 %d 个 JS 模块", jsCount))
	notes = append(notes, sprintf("还原出 %d 个 WXSS", wxssCount))
	if skipped > 0 {
		notes = append(notes, sprintf("跳过 %d 处未闭合、动态或不支持的静态结构；原始脚本仍保留", skipped))
	}
	notes = append(notes, "编译 WXML 未还原；本档仅静态解析，不执行视图层 JavaScript")
	return extra, notes
}

func filepathSlash(s string) string { return strings.ReplaceAll(s, "\\", "/") }

func sprintf(f string, a ...any) string {
	// tiny local helper to avoid importing fmt just for two calls
	out := f
	for _, v := range a {
		out = strings.Replace(out, "%d", itoa(v), 1)
	}
	return out
}
func itoa(v any) string {
	switch n := v.(type) {
	case int:
		return intToStr(n)
	default:
		return ""
	}
}
func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// splitConfig turns app-config.json into app.json + per-page .json.
func splitConfig(appConfig []byte) ([]File, string) {
	var cfg map[string]any
	if err := json.Unmarshal(appConfig, &cfg); err != nil {
		return nil, "app-config.json 解析失败"
	}
	var out []File
	pages := 0
	if page, ok := cfg["page"].(map[string]any); ok {
		for k, v := range page {
			name := strings.TrimSuffix(k, ".html") + ".json"
			pj := map[string]any{}
			if pm, ok := v.(map[string]any); ok {
				if win, ok := pm["window"].(map[string]any); ok {
					for wk, wv := range win {
						pj[wk] = wv
					}
				}
				for pk, pv := range pm {
					if pk == "window" {
						continue
					}
					if _, exists := pj[pk]; !exists {
						pj[pk] = pv
					}
				}
			}
			b, _ := json.MarshalIndent(pj, "", "  ")
			out = append(out, File{Name: "/" + name, Data: b})
			pages++
		}
	}
	app := map[string]any{}
	for k, v := range cfg {
		if k == "page" {
			continue
		}
		app[k] = v
	}
	b, _ := json.MarshalIndent(app, "", "  ")
	out = append(out, File{Name: "/app.json", Data: b})
	return out, sprintf("配置还原: app.json + %d 个页面 json", pages)
}

// splitDefines extracts only complete, statically identifiable module wrappers.
func splitDefines(src string) []File {
	modules, _, _ := reconstructJS(src)
	return modules
}

// extractWXSS never reads path metadata outside the same call expression.
func extractWXSS(src string) []File {
	_, styles, _ := reconstructJS(src)
	return styles
}

// evalCssArray accepts literal CSS and the known [0, N] rpx encoding only.
// Dynamic expressions and other opcodes must not be fabricated into CSS.
func evalCssArray(arr string) string {
	css, ok := literalCSS(arr)
	if !ok {
		return ""
	}
	return css
}

func unquoteJS(src string) string {
	decoded, ok := decodeJSString(src)
	if !ok {
		return ""
	}
	return decoded
}
