package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWXPackageNamesAndNoOverwrite(t *testing.T) {
	for _, name := range []string{"../outside", "a/../../outside", `a\..\outside`, "C:/outside", "a//b", "a/./b", "file:stream", "\x00"} {
		if _, err := wxRelativeName(name); err == nil {
			t.Errorf("accepted %q", name)
		}
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := wxWriteFile(root, "/sub/file.txt", []byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := wxWriteFile(root, "/sub/file.txt", []byte("replacement")); err == nil {
		t.Fatal("overwrote existing file")
	}
	data, err := os.ReadFile(filepath.Join(dir, "sub", "file.txt"))
	if err != nil || string(data) != "original" {
		t.Fatal("existing content changed", err)
	}
}

func TestWXPackageDirectoryLinkCannotEscape(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("self-owned-marker"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	var err error
	if runtime.GOOS == "windows" {
		err = exec.Command("cmd", "/c", "mklink", "/J", link, outside).Run()
	} else {
		err = os.Symlink(outside, link)
	}
	if err != nil {
		t.Fatal("cannot create regression fixture", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := wxWriteFile(root, "link/new.txt", []byte("must stay inside")); err == nil {
		t.Fatal("write escaped root")
	}
	if _, err := os.Stat(filepath.Join(outside, "new.txt")); !os.IsNotExist(err) {
		t.Fatal("outside file was created", err)
	}
	req := httptest.NewRequest("GET", "/api/wxapkg/read?"+url.Values{"dir": {dir}, "name": {"link/secret.txt"}}.Encode(), nil)
	rec := httptest.NewRecorder()
	new(Server).wxapkgRead(rec, req)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "self-owned-marker") {
		t.Fatal("read escaped root", rec.Code)
	}
}

func TestWXUnpackAndLANRequireActivePermission(t *testing.T) {
	for _, route := range []string{"/api/wxapkg/unpack", "/api/proxy/lan/start"} {
		guard := newTestGuard()
		h := guard.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("active handler reached") }))
		req := httptest.NewRequest("POST", "http://127.0.0.1:19091"+route, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer secret")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatal(route, rec.Code)
		}
	}
}
