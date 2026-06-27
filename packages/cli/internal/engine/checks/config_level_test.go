package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func makeConfig(servers ...parser.MCPServer) *parser.MCPConfig {
	return &parser.MCPConfig{Servers: servers}
}

func TestCheckConfigLevel_Clean(t *testing.T) {
	cfg := makeConfig(parser.MCPServer{
		Name: "clean", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp/project"},
	})
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	if len(findings) != 0 {
		t.Errorf("want 0, got %d: %v", len(findings), findings)
	}
}

func TestCheckConfigLevel_CL001_ConfusedDeputy(t *testing.T) {
	cfg := makeConfig(parser.MCPServer{
		Name: "combo", Command: "bash",
		Args: []string{"--exec", "/", "server.js"},
	})
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	found := false
	for _, f := range findings {
		if f.CheckID == "CL-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CL-001 for confused deputy, got: %v", findings)
	}
}

func TestCheckConfigLevel_CL002_Duplicate(t *testing.T) {
	cfg := makeConfig(
		parser.MCPServer{Name: "fs1", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem"}},
		parser.MCPServer{Name: "fs2", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem"}},
	)
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	found := false
	for _, f := range findings {
		if f.CheckID == "CL-002" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CL-002 for duplicate server package, got: %v", findings)
	}
}

func TestCheckConfigLevel_CL003_TLSDisabled(t *testing.T) {
	cfg := makeConfig(parser.MCPServer{
		Name: "node-server", Command: "node",
		Args: []string{"server.js"},
		Env:  map[string]string{"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
	})
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	found := false
	for _, f := range findings {
		if f.CheckID == "CL-003" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CL-003 for TLS disabled, got: %v", findings)
	}
}

func TestCheckConfigLevel_EC001_DebugWithSecrets(t *testing.T) {
	cfg := makeConfig(parser.MCPServer{
		Name: "debuggy", Command: "node",
		Args: []string{"server.js"},
		Env:  map[string]string{"DEBUG": "true"},
	})
	perServer := map[string][]models.Finding{
		"debuggy": {{CheckID: "SEC-001", Severity: models.SeverityHigh}},
	}
	findings := CheckConfigLevel(cfg, perServer)
	found := false
	for _, f := range findings {
		if f.CheckID == "EC-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected EC-001 for debug+secrets, got: %v", findings)
	}
}

func TestCheckConfigLevel_CL004_WildcardAutoApprove(t *testing.T) {
	wildcard := "*"
	cfg := makeConfig(parser.MCPServer{
		Name: "auto-all", Command: "npx",
		Args:        []string{"-y", "some-server"},
		AutoApprove: &parser.AutoApprove{Str: &wildcard},
	})
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	found := false
	for _, f := range findings {
		if f.CheckID == "CL-004" && f.Severity == models.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected critical CL-004 for wildcard autoApprove, got: %v", findings)
	}
}

func TestCheckConfigLevel_CL004_PartialAutoApprove(t *testing.T) {
	cfg := makeConfig(parser.MCPServer{
		Name: "auto-some", Command: "npx",
		Args:        []string{"-y", "some-server"},
		AutoApprove: &parser.AutoApprove{List: []string{"read_file", "list_dir"}},
	})
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	found := false
	for _, f := range findings {
		if f.CheckID == "CL-004" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CL-004 for partial autoApprove, got: %v", findings)
	}
}
