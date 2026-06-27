package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// buildConfigFindings creates perServer findings map for config-level tests.
func buildConfigFindings(serverName string, ids ...string) map[string][]models.Finding {
	findings := make([]models.Finding, len(ids))
	for i, id := range ids {
		findings[i] = models.Finding{CheckID: id, ServerName: serverName}
	}
	return map[string][]models.Finding{serverName: findings}
}

func TestCheckConfigLevel_CL001_ConfusedDeputy_BroadFSAndShellInOneServer(t *testing.T) {
	// CL-001: ONE server has both broad FS path AND a shell keyword in its args
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "combined", Command: "node",
				Args: []string{"server.js", "/home", "--exec", "bash"}},
		},
	}
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	if !hasCheckID(findings, "CL-001") {
		t.Error("want CL-001 for single server with broad FS path AND shell keyword")
	}
}

func TestCheckConfigLevel_CL001_NoBroadFS_NoFire(t *testing.T) {
	// Server with shell keyword but a safe narrow path should NOT trigger CL-001
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "narrow", Command: "node",
				Args: []string{"server.js", "/tmp/project", "--exec", "node"}},
		},
	}
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	for _, f := range findings {
		if f.CheckID == "CL-001" {
			t.Error("narrow path + shell should NOT trigger CL-001")
		}
	}
}

func TestCheckConfigLevel_CL001_SecretsAndShell(t *testing.T) {
	// CL-001 also fires when a server has secrets AND shell capability (second condition)
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "risky", Command: "node",
				Args: []string{"server.js", "--exec", "bash"},
				Env:  map[string]string{"OPENAI_API_KEY": "anthropic-test-value-not-real"}},
		},
	}
	// SEC-004 finding simulates a detected secret
	perServer := buildConfigFindings("risky", "SEC-004")
	findings := CheckConfigLevel(cfg, perServer)
	if !hasCheckID(findings, "CL-001") {
		t.Error("want CL-001 for server with secrets AND shell keyword")
	}
}

func TestCheckConfigLevel_CL002_DuplicatePackages(t *testing.T) {
	// CL-002: same package installed in two different server entries
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "fs1", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"}},
			{Name: "fs2", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/home"}},
		},
	}
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	if !hasCheckID(findings, "CL-002") {
		t.Error("want CL-002 for duplicate package across two server entries")
	}
}

func TestCheckConfigLevel_CL002_UniquePackages_NoFire(t *testing.T) {
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "fs", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"}},
			{Name: "fetch", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-fetch@1.0.4"}},
		},
	}
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	for _, f := range findings {
		if f.CheckID == "CL-002" {
			t.Error("unique packages should not trigger CL-002")
		}
	}
}

func TestCheckConfigLevel_CL003_TLSBypass(t *testing.T) {
	// CL-003: TLS verification disabled via env var
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "srv", Command: "node", Args: []string{"server.js"},
				Env: map[string]string{"NODE_TLS_REJECT_UNAUTHORIZED": "0"}},
		},
	}
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	if !hasCheckID(findings, "CL-003") {
		t.Error("want CL-003 for NODE_TLS_REJECT_UNAUTHORIZED=0")
	}
}

func TestCheckConfigLevel_CL003_TLSEnabled_NoFire(t *testing.T) {
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "srv", Command: "node", Args: []string{"server.js"},
				Env: map[string]string{"NODE_TLS_REJECT_UNAUTHORIZED": "1"}},
		},
	}
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	for _, f := range findings {
		if f.CheckID == "CL-003" {
			t.Error("NODE_TLS_REJECT_UNAUTHORIZED=1 should NOT trigger CL-003")
		}
	}
}

func TestCheckConfigLevel_CL004_WildcardAutoApprove_Bool(t *testing.T) {
	boolTrue := true
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "srv", Command: "npx", Args: []string{"-y", "pkg@1.0"},
				AutoApprove: &parser.AutoApprove{Bool: &boolTrue}},
		},
	}
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	if !hasCheckID(findings, "CL-004") {
		t.Error("want CL-004 for autoApprove=true (wildcard approval)")
	}
}

func TestCheckConfigLevel_CL004_AutoApproveWildcardStar(t *testing.T) {
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "srv", Command: "npx", Args: []string{"-y", "pkg@1.0"},
				AutoApprove: &parser.AutoApprove{List: []string{"*"}}},
		},
	}
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	if !hasCheckID(findings, "CL-004") {
		t.Error("want CL-004 for autoApprove=[\"*\"]")
	}
}

func TestCheckConfigLevel_CL004_NoAutoApprove_NoFire(t *testing.T) {
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "srv", Command: "npx", Args: []string{"-y", "pkg@1.0"}},
		},
	}
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	for _, f := range findings {
		if f.CheckID == "CL-004" {
			t.Error("server without autoApprove should not trigger CL-004")
		}
	}
}

func TestCheckConfigLevel_EC001_DebugLoggingWithSecrets(t *testing.T) {
	// EC-001: debug logging enabled AND the server has secrets = debug logs may expose secrets
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "srv", Command: "node", Args: []string{"server.js", "--debug"},
				Env: map[string]string{"LOG_LEVEL": "debug", "API_KEY": "sk-test"}},
		},
	}
	perServer := buildConfigFindings("srv", "SEC-004")
	findings := CheckConfigLevel(cfg, perServer)
	if !hasCheckID(findings, "EC-001") {
		t.Error("want EC-001 for debug logging enabled with secrets present")
	}
}

func TestCheckConfigLevel_Empty_NoFindings(t *testing.T) {
	cfg := &parser.MCPConfig{}
	findings := CheckConfigLevel(cfg, map[string][]models.Finding{})
	if len(findings) != 0 {
		t.Errorf("empty config should produce no config-level findings, got %d", len(findings))
	}
}
