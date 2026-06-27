package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// buildConfig is a helper for chain analysis tests.
func buildConfig(servers ...parser.MCPServer) *parser.MCPConfig {
	cfg := &parser.MCPConfig{}
	cfg.Servers = append(cfg.Servers, servers...)
	return cfg
}

func TestCheckCrossServerChains_Empty(t *testing.T) {
	cfg := buildConfig()
	findings := CheckCrossServerChains(cfg, map[string][]models.Finding{})
	if len(findings) != 0 {
		t.Errorf("empty config should produce no chain findings, got %d", len(findings))
	}
}

func TestCheckCrossServerChains_SingleServer_NoChain(t *testing.T) {
	fs := parser.MCPServer{
		Name: "fs", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"},
	}
	cfg := buildConfig(fs)
	findings := CheckCrossServerChains(cfg, map[string][]models.Finding{})
	for _, f := range findings {
		if f.CheckID == "CHAIN-001" {
			t.Error("single server should not produce CHAIN-001")
		}
	}
}

func TestCheckCrossServerChains_CHAIN001_WriterAndExecutor(t *testing.T) {
	// A filesystem writer + a shell executor = CHAIN-001 gadget pair
	fs := parser.MCPServer{
		Name: "file-writer", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"},
	}
	shell := parser.MCPServer{
		Name: "shell-exec", Command: "npx",
		Args: []string{"-y", "mcp-shell-server@1.0"},
	}
	cfg := buildConfig(fs, shell)
	// shell-exec gets an EX-001 finding to mark it as shell executor
	perServer := map[string][]models.Finding{
		"shell-exec": {{CheckID: "EX-001", ServerName: "shell-exec"}},
	}
	findings := CheckCrossServerChains(cfg, perServer)
	found := false
	for _, f := range findings {
		if f.CheckID == "CHAIN-001" {
			found = true
		}
	}
	if !found {
		t.Error("want CHAIN-001 for filesystem-writer + shell-executor pair")
	}
}

func TestCheckCrossServerChains_CHAIN002_SecretHolder_HTTPOutbound(t *testing.T) {
	// A server with a secret + a server that makes HTTP outbound calls = CHAIN-002
	secretServer := parser.MCPServer{
		Name: "secret-holder", Command: "node",
		Args: []string{"server.js"},
		Env:  map[string]string{"OPENAI_API_KEY": "anthropic-test-value"},
	}
	httpServer := parser.MCPServer{
		Name: "http-fetch", Command: "npx",
		Args: []string{"-y", "mcp-server-fetch@1.0"},
	}
	cfg := buildConfig(secretServer, httpServer)
	perServer := map[string][]models.Finding{
		"secret-holder": {{CheckID: "SEC-004", ServerName: "secret-holder"}},
	}
	findings := CheckCrossServerChains(cfg, perServer)
	found := false
	for _, f := range findings {
		if f.CheckID == "CHAIN-002" {
			found = true
		}
	}
	if !found {
		t.Error("want CHAIN-002 for secret-holder + http-outbound pair")
	}
}

func TestCheckCrossServerChains_CHAIN003_MultipleWriters(t *testing.T) {
	// 3+ filesystem servers = CHAIN-003 (excessive write surface)
	servers := make([]parser.MCPServer, 3)
	for i := range servers {
		servers[i] = parser.MCPServer{
			Name:    "fs-" + string(rune('a'+i)),
			Command: "npx",
			Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp/dir" + string(rune('a'+i))},
		}
	}
	cfg := buildConfig(servers...)
	findings := CheckCrossServerChains(cfg, map[string][]models.Finding{})
	found := false
	for _, f := range findings {
		if f.CheckID == "CHAIN-003" {
			found = true
		}
	}
	if !found {
		t.Error("want CHAIN-003 for 3+ filesystem writer servers")
	}
}

func TestCheckCrossServerChains_CHAIN003_TwoWriters_NoFire(t *testing.T) {
	// Only 2 filesystem servers — should NOT trigger CHAIN-003
	servers := []parser.MCPServer{
		{Name: "fs-a", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp/a"}},
		{Name: "fs-b", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp/b"}},
	}
	cfg := buildConfig(servers...)
	findings := CheckCrossServerChains(cfg, map[string][]models.Finding{})
	for _, f := range findings {
		if f.CheckID == "CHAIN-003" {
			t.Error("2 filesystem servers should NOT trigger CHAIN-003 (threshold is 3)")
		}
	}
}

func TestCheckCrossServerChains_DisabledServer_Excluded(t *testing.T) {
	// A disabled server should not participate in chain analysis
	fs := parser.MCPServer{
		Name: "fs", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"},
	}
	disabledShell := parser.MCPServer{
		Name: "shell-exec", Command: "npx",
		Args:     []string{"-y", "mcp-shell-server@1.0"},
		Disabled: true,
	}
	cfg := buildConfig(fs, disabledShell)
	perServer := map[string][]models.Finding{
		"shell-exec": {{CheckID: "EX-001", ServerName: "shell-exec"}},
	}
	findings := CheckCrossServerChains(cfg, perServer)
	for _, f := range findings {
		if f.CheckID == "CHAIN-001" {
			t.Error("disabled shell-exec should not create CHAIN-001 gadget pair")
		}
	}
}
