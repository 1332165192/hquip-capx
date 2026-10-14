//go:build windows

package main

import _ "embed"

// srcSessionTemplateText embeds the Windows/PowerShell SRC session template.
//
//go:embed src_session_template.md.tmpl
var srcSessionTemplateText string
