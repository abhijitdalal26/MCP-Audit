package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckAudit_Clean(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "clean",
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
	}
	if f := CheckAudit(s); len(f) != 0 {
		t.Errorf("want 0, got %d: %v", len(f), f)
	}
}

func TestCheckAudit_AT002_TransportAmbiguity(t *testing.T) {
	s := &parser.MCPServer{
		Name:      "ambiguous",
		Command:   "node",
		Args:      []string{"server.js"},
		URL:       "https://api.example.com/mcp",
		Transport: "stdio",
	}
	findings := CheckAudit(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "AT-002" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AT-002 for transport ambiguity (stdio + URL), got: %v", findings)
	}
}

// AT-004 detects 0.0.0.0 in the server URL field (not in args).
func TestCheckAudit_AT004_ZeroZeroBinding(t *testing.T) {
	s := &parser.MCPServer{
		Name:      "listen-all",
		Command:   "",
		URL:       "http://0.0.0.0:8000/mcp",
		Transport: "sse",
	}
	findings := CheckAudit(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "AT-004" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AT-004 for 0.0.0.0 in URL, got: %v", findings)
	}
}

func TestCheckAudit_AT003_NoTransport(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "http-no-transport",
		Command: "",
		URL:     "https://api.example.com/mcp",
	}
	findings := CheckAudit(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "AT-003" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AT-003 for HTTP server without transport declaration, got: %v", findings)
	}
}
