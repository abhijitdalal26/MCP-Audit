package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckLifecycle_LF001_NpxNoIgnoreScripts(t *testing.T) {
	s := &parser.MCPServer{
		Name: "pkg", Command: "npx",
		Args: []string{"-y", "some-package@1.0"},
	}
	if !hasCheckID(CheckLifecycle(s), "LF-001") {
		t.Error("want LF-001 for npx -y without --ignore-scripts")
	}
}

func TestCheckLifecycle_LF001_NpxWithIgnoreScripts(t *testing.T) {
	s := &parser.MCPServer{
		Name: "pkg", Command: "npx",
		Args: []string{"--ignore-scripts", "-y", "some-package@1.0"},
	}
	if hasCheckID(CheckLifecycle(s), "LF-001") {
		t.Error("npx with --ignore-scripts should NOT trigger LF-001")
	}
}

func TestCheckLifecycle_LF001_NpmYes(t *testing.T) {
	// npm with -y (--yes) flag and no --ignore-scripts fires LF-001
	s := &parser.MCPServer{
		Name: "pkg", Command: "npm",
		Args: []string{"-y", "some-package@1.0"},
	}
	if !hasCheckID(CheckLifecycle(s), "LF-001") {
		t.Error("want LF-001 for npm -y without --ignore-scripts")
	}
}

func TestCheckLifecycle_LF001_NpmYesWithIgnoreScripts(t *testing.T) {
	// LF-001 requires -y AND no --ignore-scripts; with both flags it's safe
	s := &parser.MCPServer{
		Name: "pkg", Command: "npm",
		Args: []string{"-y", "--ignore-scripts", "some-package@1.0"},
	}
	if hasCheckID(CheckLifecycle(s), "LF-001") {
		t.Error("npm -y with --ignore-scripts should NOT trigger LF-001")
	}
}

func TestCheckLifecycle_LF001_Node_NoFire(t *testing.T) {
	// Plain node execution doesn't go through npm lifecycle
	s := &parser.MCPServer{
		Name: "node-server", Command: "node",
		Args: []string{"server.js"},
	}
	if hasCheckID(CheckLifecycle(s), "LF-001") {
		t.Error("plain node server should not trigger LF-001")
	}
}

func TestCheckLifecycle_LF001_Python_NoFire(t *testing.T) {
	// Python execution doesn't have npm lifecycle scripts
	s := &parser.MCPServer{
		Name: "py-server", Command: "python3",
		Args: []string{"server.py"},
	}
	if hasCheckID(CheckLifecycle(s), "LF-001") {
		t.Error("python server should not trigger LF-001")
	}
}

func TestCheckLifecycle_LF001_UVX(t *testing.T) {
	// uvx runs Python packages but doesn't have npm lifecycle scripts
	s := &parser.MCPServer{
		Name: "uvx-pkg", Command: "uvx",
		Args: []string{"mcp-server-fetch@1.0"},
	}
	// uvx doesn't go through npm lifecycle, so LF-001 should NOT fire
	findings := CheckLifecycle(s)
	for _, f := range findings {
		if f.CheckID == "LF-001" {
			t.Error("uvx server should not trigger LF-001 (no npm lifecycle)")
		}
	}
}

func TestCheckLifecycle_LF001_OfficialMCPPackage(t *testing.T) {
	// Official @modelcontextprotocol packages still trigger LF-001 without --ignore-scripts
	s := &parser.MCPServer{
		Name: "fs", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"},
	}
	if !hasCheckID(CheckLifecycle(s), "LF-001") {
		t.Error("want LF-001 even for official packages without --ignore-scripts")
	}
}
