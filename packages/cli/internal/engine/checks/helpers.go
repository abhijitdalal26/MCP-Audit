// Package checks contains all 51 MCPAudit security checks ported from Python.
// Each check function takes an *MCPServer (or *MCPConfig for cross-server checks)
// and returns a slice of Finding. Checks are pure functions — no global state, no I/O
// except CheckOSV which makes a single outbound HTTP call.
package checks

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// placeholderRE matches values that are clearly template placeholders, not real secrets.
// Mirrors Python's _PLACEHOLDER_RE — used in secrets + supply_chain checks.
var placeholderRE = regexp.MustCompile(
	`(?i)^\s*(\$\{[^}]+\}|<[^>]+>|your[-_\s].+|xxx+|placeholder|changeme|todo|example|insert[-_]here|replace[-_]me)\s*$`,
)

// mask returns a redacted version of a credential value — safe to include in reports.
func mask(val string) string {
	if len(val) <= 8 {
		return "***"
	}
	return val[:4] + "..." + val[len(val)-4:]
}

// CmdBasename is the exported version used by scanner.go.
func CmdBasename(server *parser.MCPServer) string { return cmdBasename(server) }

// cmdBasename returns the lowercase base name of the server command without extension.
// e.g. "/usr/bin/node.exe" → "node", "C:\\tools\\npx.cmd" → "npx"
func cmdBasename(server *parser.MCPServer) string {
	if server.Command == "" {
		return ""
	}
	base := filepath.Base(server.Command)
	base = strings.ToLower(base)
	// Strip known extensions
	for _, ext := range []string{".exe", ".cmd", ".bat", ".sh"} {
		base = strings.TrimSuffix(base, ext)
	}
	return base
}

// isNodeLikeCommand returns true if the server's command is a known script runner.
func isNodeLikeCommand(server *parser.MCPServer) bool {
	base := cmdBasename(server)
	switch base {
	case "npx", "node", "uvx", "uv", "python", "python3", "deno", "bun":
		return true
	}
	return false
}

// joinArgs returns all args joined by a space, lowercased — handy for pattern matching.
func joinArgsLower(server *parser.MCPServer) string {
	return strings.ToLower(strings.Join(server.Args, " "))
}
