package api

// WeChat mini-program (.wxapkg) unpacker endpoints. Auto-detects PC-encrypted
// packages and decrypts them (appId-keyed), then extracts the bundle to disk so
// the JS/JSON/WXML/WXSS can be searched for endpoints and secrets.

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/hquip/capx/internal/wxapkg"
)

// wxDetectRoot returns the first existing WeChat applet cache directory.
func wxDetectRoot() string {
	cands := []string{
		filepath.Join(os.Getenv("APPDATA"), "Tencent", "xwechat", "radium", "Applet", "packages"),
		filepath.Join(os.Getenv("APPDATA"), "Tencent", "xwechat", "radium", "Applet"),
		filepath.Join(os.Getenv("USERPROFILE"), "Documents", "WeChat Files", "Applet"),
		filepath.Join(os.Getenv("APPDATA"), "Tencent", "WeChat", "Applet"),
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c
		}
	}
	return ""
}

// wxDeriveName best-effort recovers a display name from app-config.json's
// global navigationBarTitleText (usually the mini-program's title).
func wxDeriveName(files []wxapkg.File) string {
	for _, f := range files {
		if strings.TrimLeft(filepath.ToSlash(f.Name), "/") != "app-config.json" {
			continue
		}
		var cfg map[string]any
		if json.Unmarshal(f.Data, &cfg) != nil {
			return ""
		}
		if g, ok := cfg["global"].(map[string]any); ok {
			if win, ok := g["window"].(map[string]any); ok {
				if t, ok := win["navigationBarTitleText"].(string); ok && t != "" {
					return t
				}
			}
		}
		if win, ok := cfg["window"].(map[string]any); ok {
			if t, ok := win["navigationBarTitleText"].(string); ok && t != "" {
				return t
			}
		}
	}
	return ""
}

// wxapkgScan enumerates cached mini-programs and resolves each one's name.
func (s *Server) wxapkgScan(w http.ResponseWriter, r *http.Request) {
	root := strings.TrimSpace(r.URL.Query().Get("root"))
	if root == "" {
		root = wxDetectRoot()
	}
	if root == "" {
		writeErr(w, http.StatusNotFound, "未找到微信 Applet 缓存目录，请手动指定 root")
		return
	}
	appDirs, err := os.ReadDir(root)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取目录失败: "+err.Error())
		return
	}
	apps := make([]map[string]any, 0, len(appDirs))
	for _, ad := range appDirs {
		if !ad.IsDir() || !strings.HasPrefix(ad.Name(), "wx") {
			continue
		}
		appID := ad.Name()
		appPath := filepath.Join(root, appID)
		vers, _ := os.ReadDir(appPath)
		bestVer, bestN := "", -1
		for _, vd := range vers {
			if vd.IsDir() {
				if n, e := strconv.Atoi(vd.Name()); e == nil && n >= bestN {
					bestN, bestVer = n, vd.Name()
				} else if bestVer == "" {
					bestVer = vd.Name()
				}
			}
		}
		if bestVer == "" {
			continue
		}
		verPath := filepath.Join(appPath, bestVer)
		pkgs, _ := os.ReadDir(verPath)
		mainPkg, anyPkg := "", ""
		for _, p := range pkgs {
			if strings.HasSuffix(p.Name(), ".wxapkg") {
				full := filepath.Join(verPath, p.Name())
				anyPkg = full
				if strings.Contains(strings.ToUpper(p.Name()), "APP") {
					mainPkg = full
				}
			}
		}
		pkg := mainPkg
		if pkg == "" {
			pkg = anyPkg
		}
		if pkg == "" {
			continue
		}
		fi, _ := os.Stat(pkg)
		name := ""
		if mainPkg != "" && fi != nil && fi.Size() < 12<<20 {
			if data, e := os.ReadFile(mainPkg); e == nil {
				if files, _, e2 := wxapkg.Process(appID, data); e2 == nil {
					name = wxDeriveName(files)
				}
			}
		}
		mt := ""
		var sz int64
		if fi != nil {
			mt = fi.ModTime().Format("2006-01-02 15:04")
			sz = fi.Size()
		}
		apps = append(apps, map[string]any{"appid": appID, "name": name, "version": bestVer, "path": pkg, "size": sz, "mtime": mt})
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i]["mtime"].(string) > apps[j]["mtime"].(string) })
	writeJSON(w, http.StatusOK, map[string]any{"root": root, "count": len(apps), "apps": apps})
}

// wxapkgUnpack reads a .wxapkg from a local path, decrypts if needed, and
// extracts its members into an output directory.

var reAppID = regexp.MustCompile(`wx[0-9a-fA-F]{15,17}`)

func wxIsTextName(n string) bool {
	n = strings.ToLower(n)
	for _, ext := range []string{".js", ".json", ".wxml", ".wxss", ".wxs", ".html", ".htm", ".txt", ".xml", ".css", ".ts", ".map", ".svg"} {
		if strings.HasSuffix(n, ext) {
			return true
		}
	}
	return false
}

func wxIsStaticName(n string) bool {
	n = strings.ToLower(n)
	for _, e := range []string{".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp", ".mp3", ".mp4", ".ttf", ".woff", ".woff2", ".otf"} {
		if strings.HasSuffix(n, e) {
			return true
		}
	}
	return false
}

func wxLikelyAPI(p string) bool {
	if strings.HasPrefix(p, "/pages/") || strings.HasPrefix(p, "/components/") || strings.HasPrefix(p, "./") || len(p) < 3 {
		return false
	}
	low := strings.ToLower(p)
	for _, e := range []string{".js", ".png", ".jpg", ".gif", ".svg", ".css", ".wxss", ".wxml", ".html", ".json", ".ttf", ".woff"} {
		if strings.HasSuffix(low, e) {
			return false
		}
	}
	return true
}

//go:embed wxapkg_rules.json
var wxDefaultRulesJSON []byte

type wxRuleSet map[string][]*regexp.Regexp

var (
	wxDefaultRules     wxRuleSet
	wxDefaultRulesOnce sync.Once
)

// wxCompileRules compiles a category->patterns map, silently skipping any
// pattern that fails to compile (so one bad rule never breaks the rest).
func wxCompileRules(src map[string][]string) wxRuleSet {
	rs := wxRuleSet{}
	for cat, pats := range src {
		for _, p := range pats {
			if re, err := regexp.Compile(p); err == nil {
				rs[cat] = append(rs[cat], re)
			}
		}
	}
	return rs
}

// wxapkgRules returns the embedded default extraction ruleset (editable in UI).
func (s *Server) wxapkgRules(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(wxDefaultRulesJSON)
}

func wxGetDefaultRules() wxRuleSet {
	wxDefaultRulesOnce.Do(func() {
		var m map[string][]string
		if json.Unmarshal(wxDefaultRulesJSON, &m) == nil {
			wxDefaultRules = wxCompileRules(m)
		} else {
			wxDefaultRules = wxRuleSet{}
		}
	})
	return wxDefaultRules
}

// wxExtract categorizes endpoints/secrets/static using the rule set (custom
// overrides the embedded default when provided).
func wxExtract(files []wxapkg.File, custom map[string][]string) map[string][]string {
	rules := wxGetDefaultRules()
	if len(custom) > 0 {
		rules = wxCompileRules(custom)
	}
	order := map[string]*[]string{}
	seen := map[string]map[string]struct{}{}
	ensure := func(cat string) {
		if order[cat] == nil {
			s := []string{}
			order[cat] = &s
			seen[cat] = map[string]struct{}{}
		}
	}
	for _, c := range []string{"api", "url", "cred", "key", "sensitive", "appid", "cloud", "jdbc", "static"} {
		ensure(c)
	}
	add := func(cat, v string) {
		ensure(cat)
		if v == "" || len(*order[cat]) >= 1000 {
			return
		}
		if _, ok := seen[cat][v]; ok {
			return
		}
		seen[cat][v] = struct{}{}
		*order[cat] = append(*order[cat], v)
	}
	for _, f := range files {
		if wxIsStaticName(f.Name) {
			add("static", f.Name)
			continue
		}
		if !wxIsTextName(f.Name) || len(f.Data) > 8<<20 {
			continue
		}
		s := string(f.Data)
		for cat, res := range rules {
			for _, re := range res {
				for _, m := range re.FindAllStringSubmatch(s, -1) {
					v := m[0]
					if len(m) > 1 && strings.TrimSpace(m[1]) != "" {
						v = m[1]
					}
					v = strings.TrimSpace(v)
					if cat == "api" && !wxLikelyAPI(v) {
						continue
					}
					add(cat, v)
				}
			}
		}
	}
	out := map[string][]string{}
	for cat, lst := range order {
		out[cat] = *lst
	}
	return out
}

// wxapkgUnpack reads a .wxapkg from a local path, decrypts if needed, and
// extracts its members into an output directory.
func (s *Server) wxapkgUnpack(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path        string              `json:"path"`
		AppID       string              `json:"appid"`
		OutDir      string              `json:"outdir"`
		Reconstruct bool                `json:"reconstruct"`
		Rules       map[string][]string `json:"rules"`
	}
	if err := decodeBody(r, &req); err != nil || strings.TrimSpace(req.Path) == "" {
		writeErr(w, http.StatusBadRequest, "缺少 path")
		return
	}
	const maxPackageBytes = 64 << 20
	packageFile, err := os.Open(req.Path)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取失败: "+err.Error())
		return
	}
	defer packageFile.Close()
	raw, err := io.ReadAll(io.LimitReader(packageFile, maxPackageBytes+1))
	if err != nil || len(raw) > maxPackageBytes {
		writeErr(w, http.StatusBadRequest, "读取包失败或包超过 64 MiB 限制")
		return
	}
	appID := strings.TrimSpace(req.AppID)
	if appID == "" {
		appID = reAppID.FindString(filepath.ToSlash(req.Path))
	}
	files, enc, err := wxapkg.Process(appID, raw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	base := strings.TrimSuffix(filepath.Base(req.Path), filepath.Ext(req.Path))
	out := strings.TrimSpace(req.OutDir)
	if out == "" {
		out, err = os.MkdirTemp(filepath.Dir(req.Path), base+"_unpacked-")
		if err != nil {
			writeErr(w, http.StatusBadRequest, "无法创建解包目录")
			return
		}
	}
	if err = os.MkdirAll(out, 0700); err != nil {
		writeErr(w, http.StatusBadRequest, "无法打开解包目录")
		return
	}
	root, err := os.OpenRoot(out)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "无法打开解包目录")
		return
	}
	defer root.Close()
	list := make([]map[string]any, 0, len(files))
	written := 0
	for _, f := range files {
		if err := wxWriteFile(root, f.Name, f.Data); err != nil {
			writeErr(w, http.StatusBadRequest, "解包文件被拒绝："+err.Error())
			return
		}
		written++
		list = append(list, map[string]any{"name": f.Name, "size": len(f.Data), "text": wxIsTextName(f.Name)})
	}
	var notes []string
	if req.Reconstruct {
		extra, ns := wxapkg.Reconstruct(files)
		notes = ns
		for _, f := range extra {
			if err := wxWriteFile(root, f.Name, f.Data); err != nil {
				writeErr(w, http.StatusBadRequest, "还原文件被拒绝："+err.Error())
				return
			}
			written++
			list = append(list, map[string]any{"name": f.Name, "size": len(f.Data), "text": wxIsTextName(f.Name)})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"encrypted": enc, "appid": appID, "count": len(list), "written": written, "outdir": out, "files": list, "notes": notes,
		"extracted": wxExtract(files, req.Rules),
	})
}

func wxRelativeName(name string) (string, error) {
	name = strings.TrimLeft(strings.ReplaceAll(name, "\\", "/"), "/")
	if name == "" || strings.ContainsAny(name, ":\x00") {
		return "", fmt.Errorf("非法文件名")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." || part == "." || part == "" {
			return "", fmt.Errorf("非法路径")
		}
	}
	rel := filepath.FromSlash(name)
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("非法路径")
	}
	return rel, nil
}

func wxWriteFile(root *os.Root, name string, data []byte) error {
	rel, err := wxRelativeName(name)
	if err != nil {
		return err
	}
	if err = root.MkdirAll(filepath.Dir(rel), 0700); err != nil {
		return err
	}
	file, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// wxapkgRead returns the text content of one extracted file (sandboxed to dir).
func (s *Server) wxapkgRead(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	name := r.URL.Query().Get("name")
	if dir == "" || name == "" {
		writeErr(w, http.StatusBadRequest, "缺少 dir/name")
		return
	}
	rel, err := wxRelativeName(name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "非法路径")
		return
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "无法打开解包目录")
		return
	}
	defer root.Close()
	file, err := root.Open(rel)
	if err != nil {
		writeErr(w, http.StatusForbidden, "文件不存在或超出解包目录")
		return
	}
	defer file.Close()
	const cap = 2 << 20
	data, err := io.ReadAll(io.LimitReader(file, cap+1))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	truncated := false
	if len(data) > cap {
		data = data[:cap]
		truncated = true
	}
	writeJSON(w, http.StatusOK, map[string]any{"name": name, "size": len(data), "truncated": truncated, "content": string(data)})
}
