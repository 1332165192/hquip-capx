package mobile

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

//go:embed ios_tool_license.txt
var iosToolLicense []byte

// Pinned official go-ios v1.3.2 assets. SHA-256 values are from the release's
// GitHub asset digests, not data returned by a download mirror at runtime.
var iosToolAssets = map[string]struct{ Name, SHA256 string }{
	"windows/amd64": {"go-ios-win.zip", "939c6bcaafed183a92afb9f79cc11b1f935fa6389bfc94d3902e3f52c4dff3fe"},
	"linux/amd64":   {"go-ios-linux.zip", "a55fdb4c507391c0548252e01d1deb6ae3c7fd99cfbce842c6f80569cc125604"},
	"darwin/amd64":  {"go-ios-mac.zip", "100f225bfdd039081bcbdaf45029df3e67032673f3e0ca1fa3c050898c230c57"},
}

func ensureIOSTool(ctx context.Context) (string, error) {
	if path := iosToolPath(); path != "" {
		return path, nil
	}
	if strings.TrimSpace(os.Getenv("CAPX_IOS_TOOL")) != "" {
		return "", errors.New("configured go-ios executable was not found")
	}
	asset, ok := iosToolAssets[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return "", errors.New("this architecture requires CAPX_IOS_TOOL to point to a native go-ios build")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://github.com/danielpaulus/go-ios/releases/download/v1.3.2/"+asset.Name, nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" {
			return errors.New("unsafe tool redirect")
		}
		return nil
	}}
	response, err := client.Do(request)
	if err != nil {
		return "", errors.New("cannot download official go-ios")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("official go-ios download failed")
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, (64<<20)+1))
	if err != nil || len(archive) > 64<<20 {
		return "", errors.New("go-ios archive exceeds limit or could not be read")
	}
	return installIOSToolArchive(archive, asset.SHA256)
}

func installIOSToolArchive(archive []byte, wantHash string) (string, error) {
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != wantHash {
		return "", errors.New("go-ios checksum mismatch")
	}
	z, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return "", errors.New("invalid go-ios zip")
	}
	var candidate *zip.File
	for _, f := range z.File {
		name := filepath.Base(strings.ReplaceAll(f.Name, "\\", "/"))
		if name == "ios" || name == "ios.exe" {
			if candidate != nil || !f.Mode().IsRegular() || f.UncompressedSize64 > 200<<20 {
				return "", errors.New("ambiguous or invalid go-ios executable")
			}
			candidate = f
		}
	}
	if candidate == nil {
		return "", errors.New("go-ios executable not present in archive")
	}
	r, err := candidate.Open()
	if err != nil {
		return "", err
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, (200<<20)+1))
	if err != nil || len(data) > 200<<20 {
		return "", errors.New("go-ios executable exceeds limit")
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cache, "capx", "tools", "go-ios")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	name := "ios"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	target := filepath.Join(dir, name)
	f, err := os.CreateTemp(dir, "ios-download-*.part")
	if err != nil {
		return "", errors.New("cannot create private tool download file")
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0700); err != nil {
		f.Close()
		return "", errors.New("cannot protect downloaded tool")
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return "", errors.New("cannot save go-ios executable")
	}
	// Atomic create without replacing an existing operator-supplied tool.
	if err := os.Link(f.Name(), target); err != nil {
		return "", errors.New("tool already exists or cannot be installed atomically; it was not overwritten")
	}
	if err := os.WriteFile(filepath.Join(dir, "LICENSE-go-ios.txt"), iosToolLicense, 0600); err != nil {
		os.Remove(target)
		return "", errors.New("cannot retain go-ios license")
	}
	return target, nil
}
