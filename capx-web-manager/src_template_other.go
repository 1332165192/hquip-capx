//go:build !windows

package main

import _ "embed"

// srcSessionTemplateText embeds the Linux/bash SRC session template.
//
//go:embed src_session_template_unix.md.tmpl
var srcSessionTemplateText string
