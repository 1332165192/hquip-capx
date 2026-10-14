// Command capx-mcp is a stdio MCP server that talks to a running captured
// daemon over its REST API. Point Claude / Cursor / Codex at this binary.
//
//	CAPX_API=http://127.0.0.1:19091
//	CAPX_TOKEN from the environment or ~/.capx/token
//	CAPX_MCP_ACTIVE=1 to allow Repeater PUT/PATCH/DELETE (POST is allowed by default)
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hquip/capx/internal/mcp"
)

func main() {
	showVersion := flag.Bool("version", false, "print capx MCP adapter version")
	flag.Parse()
	if *showVersion {
		fmt.Printf("capx-mcp %s\n", mcp.Version)
		return
	}
	if err := mcp.New().Serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "capx-mcp: %v\n", err)
		os.Exit(1)
	}
}
