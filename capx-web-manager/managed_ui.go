package main

import (
	"bytes"
	_ "embed"
	"html/template"
	"io"
	"strings"
)

func renderManagerIndex(w io.Writer) error {
	var page bytes.Buffer
	if err := indexTpl.Execute(&page, nil); err != nil {
		return err
	}
	html := strings.Replace(page.String(), "</body>", managedUIInjection+"</body>", 1)
	_, err := io.WriteString(w, html)
	return err
}

//go:embed ui/index.html
var managerHTML string

//go:embed ui/manager.css
var managerStyles string

//go:embed ui/manager.js
var managerScript string

//go:embed ui/managed.js
var managedScript string

// The assets are embedded in the executable, so the manager remains a single-file app.
var indexTpl = template.Must(template.New("index").Parse(strings.NewReplacer(
	"/* manager styles */", managerStyles,
	"/* manager script */", managerScript,
).Replace(managerHTML)))

var managedUIInjection = "<script>\n" + managedScript + "\n</script>"
