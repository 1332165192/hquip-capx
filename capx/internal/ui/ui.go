// Package ui serves the capx local web console: a responsive capture workspace that
// runs in the browser against the capx daemon (captures, live event stream,
// and CE-style memory scanning). It is embedded into the binary so `captured`
// is a single self-contained executable.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static
var assets embed.FS

// Handler serves the console at "/" and its assets under "/".
func Handler() http.Handler {
	sub, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".html") || strings.HasSuffix(r.URL.Path, ".css") || strings.HasSuffix(r.URL.Path, ".js") || r.URL.Path == "/" {
			w.Header().Set("Cache-Control", "no-store, max-age=0")
		}
		files.ServeHTTP(w, r)
	})
}
