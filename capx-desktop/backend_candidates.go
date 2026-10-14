package main

import "path/filepath"

// backendCandidates supports both developer builds and CI application bundles.
// macOS bundles keep the backend beside the GUI executable in Contents/MacOS.
func backendCandidates(goos, executable, cwd string) []string {
	names := []string{"capx-captured", "captured"}
	if goos == "windows" {
		names = []string{"capx-captured.exe", "captured.exe"}
	}
	dir := filepath.Dir(executable)
	bases := []string{dir, filepath.Join(dir, "capx"), filepath.Join(dir, "..", "..", "..", "capx"), filepath.Join(dir, "..", "..", "..", "capx", "dist"), filepath.Join(cwd, "capx"), filepath.Join(cwd, "capx", "dist"), filepath.Join(cwd, "..", "capx"), filepath.Join(cwd, "..", "capx", "dist")}
	var paths []string
	for _, base := range bases {
		for _, name := range names {
			paths = append(paths, filepath.Join(base, name))
		}
	}
	return paths
}
