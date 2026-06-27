package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckShadow_KnownGood(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "filesystem",
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
	}
	findings := CheckShadow(s)
	for _, f := range findings {
		if f.CheckID == "SH-001" {
			t.Errorf("SH-001 should not fire for verified @modelcontextprotocol package")
		}
	}
}

// SH-001 fires when npx/npm/uvx installs a package not in the known-good list.
func TestCheckShadow_SH001_UnverifiedNPMPackage(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "mystery",
		Command: "npx",
		Args:    []string{"-y", "totally-unknown-mcp-package@1.0"},
	}
	findings := CheckShadow(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "SH-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SH-001 for unverified npm package, got: %v", findings)
	}
}

func TestCheckShadow_SH002_PlainHTTP(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "remote",
		Command: "",
		URL:     "http://api.example.com/mcp",
	}
	findings := CheckShadow(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "SH-002" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SH-002 for plain HTTP URL, got: %v", findings)
	}
}

func TestCheckShadow_SH003_LocalhostNpmRemote(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "local-remote",
		Command: "npx",
		Args:    []string{"-y", "totally-unknown-mcp-package@1.0"},
		URL:     "http://localhost:3000/mcp",
	}
	findings := CheckShadow(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "SH-003" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SH-003 for localhost with npm package, got: %v", findings)
	}
}

func TestCheckShadow_SH004_HomoglyphServerName(t *testing.T) {
	// "filesysteм" — last character is Cyrillic 'м' (U+043C), not Latin 'm'
	s := &parser.MCPServer{
		Name:    "filesysteм",
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
	}
	findings := CheckShadow(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "SH-004" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SH-004 for homoglyph server name, got: %v", findings)
	}
}

func TestCheckShadow_SH006_NoAuthHTTP(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "unauthed",
		Command: "",
		URL:     "https://api.example.com/mcp",
	}
	findings := CheckShadow(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "SH-006" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SH-006 for HTTP server without auth headers, got: %v", findings)
	}
}
