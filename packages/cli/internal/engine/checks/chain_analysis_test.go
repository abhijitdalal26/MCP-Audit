package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckCrossServerChains_SingleServer(t *testing.T) {
	cfg := &parser.MCPConfig{Servers: []parser.MCPServer{
		{Name: "fs", Command: "npx", Args: []string{"-y", "server-filesystem@1.0", "/"}},
	}}
	f := CheckCrossServerChains(cfg, map[string][]models.Finding{})
	if len(f) != 0 {
		t.Errorf("want 0 findings for single server, got %d", len(f))
	}
}

func TestCheckCrossServerChains_CHAIN001_WriteExecute(t *testing.T) {
	cfg := &parser.MCPConfig{Servers: []parser.MCPServer{
		{Name: "fs", Command: "npx", Args: []string{"-y", "server-filesystem@1.0", "/Users"}},
		{Name: "shell", Command: "bash", Args: []string{"-c", "echo hi"}},
	}}
	perServer := map[string][]models.Finding{
		"fs": {{CheckID: "PE-001"}},
	}
	findings := CheckCrossServerChains(cfg, perServer)
	found := false
	for _, f := range findings {
		if f.CheckID == "CHAIN-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CHAIN-001 for write+execute, got: %v", findings)
	}
}

func TestCheckCrossServerChains_CHAIN002_SecretsHTTP(t *testing.T) {
	cfg := &parser.MCPConfig{Servers: []parser.MCPServer{
		{Name: "creds", Command: "node", Args: []string{"creds-server.js"},
			Env: map[string]string{"OPENAI_API_KEY": "sk-live-abc123"}},
		{Name: "fetch", Command: "npx", Args: []string{"-y", "server-fetch@1.0"},
			URL: "https://external.api.com"},
	}}
	perServer := map[string][]models.Finding{
		"creds": {{CheckID: "SEC-001"}},
	}
	findings := CheckCrossServerChains(cfg, perServer)
	found := false
	for _, f := range findings {
		if f.CheckID == "CHAIN-002" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CHAIN-002 for secrets+http, got: %v", findings)
	}
}

func TestCheckCrossServerChains_CHAIN003_ManyWriters(t *testing.T) {
	servers := []parser.MCPServer{}
	perServer := map[string][]models.Finding{}
	for i := 0; i < 4; i++ {
		name := "fs" + string(rune('1'+i))
		servers = append(servers, parser.MCPServer{
			Name: name, Command: "npx",
			Args: []string{"-y", "server-filesystem@1.0", "/Users"},
		})
		perServer[name] = []models.Finding{{CheckID: "PE-001"}}
	}
	cfg := &parser.MCPConfig{Servers: servers}
	findings := CheckCrossServerChains(cfg, perServer)
	found := false
	for _, f := range findings {
		if f.CheckID == "CHAIN-003" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CHAIN-003 for 4 filesystem writers, got: %v", findings)
	}
}

func TestCheckCrossServerChains_DisabledServersIgnored(t *testing.T) {
	cfg := &parser.MCPConfig{Servers: []parser.MCPServer{
		{Name: "fs", Command: "npx", Args: []string{"-y", "server-filesystem@1.0", "/"}, Disabled: false},
		{Name: "shell", Command: "bash", Args: []string{"-c", "echo hi"}, Disabled: true},
	}}
	perServer := map[string][]models.Finding{
		"fs": {{CheckID: "PE-001"}},
	}
	findings := CheckCrossServerChains(cfg, perServer)
	for _, f := range findings {
		if f.CheckID == "CHAIN-001" {
			t.Errorf("CHAIN-001 should not fire when executor is disabled")
		}
	}
}
