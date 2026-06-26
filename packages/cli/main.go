package main

import "github.com/abhijitdalal26/MCP-Audit/cli/cmd"

// Version is set at build time via -ldflags.
var Version = "0.1.0"

func main() {
	cmd.Execute(Version)
}
