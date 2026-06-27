package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckLifecycle_Clean_PinnedWithY(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "clean",
		Command: "npx",
		Args:    []string{"-y", "--ignore-scripts", "@modelcontextprotocol/server-filesystem@1.2.3"},
	}
	findings := CheckLifecycle(s)
	for _, f := range findings {
		if f.CheckID == "LF-001" {
			t.Errorf("LF-001 should not fire with --ignore-scripts")
		}
	}
}

func TestCheckLifecycle_LF001_NpxY(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "risky",
		Command: "npx",
		Args:    []string{"-y", "some-package@latest"},
	}
	findings := CheckLifecycle(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "LF-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected LF-001 for npx -y without --ignore-scripts, got: %v", findings)
	}
}

func TestCheckLifecycle_LF001_NpxYesFlag(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "risky",
		Command: "npx",
		Args:    []string{"--yes", "some-package@1.0.0"},
	}
	findings := CheckLifecycle(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "LF-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected LF-001 for npx --yes without --ignore-scripts, got: %v", findings)
	}
}

func TestCheckLifecycle_NpxWithIgnoreScripts(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "safe",
		Command: "npx",
		Args:    []string{"-y", "--ignore-scripts", "some-package@1.0.0"},
	}
	findings := CheckLifecycle(s)
	for _, f := range findings {
		if f.CheckID == "LF-001" {
			t.Errorf("LF-001 should not fire when --ignore-scripts is present")
		}
	}
}
