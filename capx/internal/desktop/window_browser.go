// Package desktop turns the capx web console into a standalone desktop
// application window. It opens a chromeless Chromium "app" window (Edge/Chrome
// --app), which behaves like a native application window with no browser chrome,
// tabs, or address bar. It is pure Go (no cgo) and works wherever Chrome or Edge
// is installed; closing the window quits the app.
package desktop

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// Mode reports which window backend is active.
func Mode() string { return "browser-app" }

// Open launches the console at url as a standalone application window and blocks
// until that window is closed (or ctx is cancelled), then returns. If no
// Chromium-family browser is found it returns an error so the caller can fall
// back to printing the URL.
func Open(ctx context.Context, url string) error {
	return OpenWithProfile(ctx, url, profileDir())
}

// OpenWithProfile binds the browser singleton to the same isolated state
// directory as the backend. Distinct instances must not share a Chromium
// profile: a second launcher otherwise exits while its window remains open.
func OpenWithProfile(ctx context.Context, url, profile string) error {
	bin := findBrowser()
	if bin == "" {
		return fmt.Errorf("no Chrome/Edge browser found to host the desktop window")
	}

	if err := os.MkdirAll(profile, 0o700); err != nil {
		return err
	}

	args := []string{
		"--app=" + url,
		"--user-data-dir=" + profile,
		"--no-first-run",
		"--no-default-browser-check",
		"--window-size=1280,860",
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch desktop window: %w", err)
	}
	// Block until the app window is closed by the user.
	return cmd.Wait()
}

// profileDir is a persistent, app-private browser profile so the desktop window
// stays isolated from the user's normal browsing session.
func profileDir() string {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, "capx-desktop", "profile")
		}
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(os.TempDir(), "capx-desktop-profile")
	}
	return filepath.Join(home, ".capx-desktop", "profile")
}

// findBrowser locates a Chromium-family browser able to host an --app window.
func findBrowser() string {
	// Honour an explicit override first.
	if p := os.Getenv("CAPX_BROWSER"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	var candidates []string
	if runtime.GOOS == "windows" {
		pf := os.Getenv("ProgramFiles")
		pf86 := os.Getenv("ProgramFiles(x86)")
		local := os.Getenv("LOCALAPPDATA")
		for _, base := range []string{pf, pf86, local} {
			if base == "" {
				continue
			}
			candidates = append(candidates,
				filepath.Join(base, "Google", "Chrome", "Application", "chrome.exe"),
				filepath.Join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
			)
		}
		// Common Devin/CI Chrome drop location.
		candidates = append(candidates, `C:\devin\chrome\chrome-win64\chrome.exe`)
	} else {
		candidates = append(candidates,
			"/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
			"/usr/bin/microsoft-edge",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		)
	}

	for _, c := range candidates {
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Last resort: rely on PATH.
	for _, name := range []string{"chrome", "google-chrome", "chromium", "msedge"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}
