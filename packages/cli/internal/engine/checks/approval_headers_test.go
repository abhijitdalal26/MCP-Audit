package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// ── CL-004 severity tiers ─────────────────────────────────────────────────────

func TestCheckConfigLevel_CL004_WildcardSeverityIsCritical(t *testing.T) {
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "danger", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
				AutoApprove: &parser.AutoApprove{List: []string{"*"}}},
		},
	}
	for _, f := range CheckConfigLevel(cfg, map[string][]models.Finding{}) {
		if f.CheckID == "CL-004" {
			if f.Severity != models.SeverityCritical {
				t.Errorf("wildcard CL-004 should be critical, got %s", f.Severity)
			}
			return
		}
	}
	t.Error("expected CL-004 finding for wildcard autoApprove")
}

func TestCheckConfigLevel_CL004_PartialListSeverityIsMedium(t *testing.T) {
	// A small partial list (< 5 tools) should fire CL-004 at medium severity
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "partial", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
				AutoApprove: &parser.AutoApprove{List: []string{"read_file", "list_dir"}}},
		},
	}
	for _, f := range CheckConfigLevel(cfg, map[string][]models.Finding{}) {
		if f.CheckID == "CL-004" {
			if f.Severity != models.SeverityMedium {
				t.Errorf("partial autoApprove (<5 tools) should be medium, got %s", f.Severity)
			}
			return
		}
	}
	t.Error("expected CL-004 finding for partial autoApprove list")
}

func TestCheckConfigLevel_CL004_DisabledServerSkipped(t *testing.T) {
	// Disabled server with wildcard autoApprove should NOT trigger CL-004
	cfg := &parser.MCPConfig{
		Servers: []parser.MCPServer{
			{Name: "off", Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
				AutoApprove: &parser.AutoApprove{List: []string{"*"}},
				Disabled:    true},
		},
	}
	for _, f := range CheckConfigLevel(cfg, map[string][]models.Finding{}) {
		if f.CheckID == "CL-004" {
			t.Error("disabled server should not trigger CL-004")
		}
	}
}

// ── Secrets in HTTP headers ───────────────────────────────────────────────────

func TestCheckSecrets_SecretInAuthorizationHeader(t *testing.T) {
	// SEC-002: GitHub token (36+ chars after ghp_) in Authorization header value
	s := &parser.MCPServer{
		Name:    "remote",
		Command: "",
		URL:     "https://api.example.com/mcp",
		Headers: map[string]string{
			// 36 alphanumeric chars after ghp_ — matches ghp_[A-Za-z0-9]{36,}
			"Authorization": "Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		},
	}
	if !hasCheckID(CheckSecrets(s), "SEC-002") {
		t.Error("want SEC-002 for GitHub token in Authorization header")
	}
}

func TestCheckSecrets_NoSecret_CleanHeaders(t *testing.T) {
	// A server with a legitimate bearer placeholder should not fire secrets
	s := &parser.MCPServer{
		Name:    "clean",
		URL:     "https://api.example.com/mcp",
		Headers: map[string]string{"X-Request-ID": "abc-123", "Accept": "application/json"},
	}
	for _, f := range CheckSecrets(s) {
		if f.CheckID == "SEC-002" {
			t.Error("clean headers without secrets should not fire SEC-002")
		}
	}
}

// ── SEC-008: Credentials in server URL ───────────────────────────────────────

func TestCheckSecrets_SEC008_GitHubTokenInURL(t *testing.T) {
	// SEC-008: GitHub token embedded in the server URL (query param or path)
	s := &parser.MCPServer{
		Name:    "gh-url-token",
		Command: "",
		URL:     "https://api.example.com/mcp?token=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
	}
	if !hasCheckID(CheckSecrets(s), "SEC-008") {
		t.Error("want SEC-008 for GitHub token embedded in server URL")
	}
}

func TestCheckSecrets_SEC008_AWSKeyInURL(t *testing.T) {
	// SEC-008: AWS key embedded in the server URL
	s := &parser.MCPServer{
		Name: "aws-url",
		URL:  "https://api.example.com/mcp?key=AKIAIOSFODNN7EXAMPLE",
	}
	if !hasCheckID(CheckSecrets(s), "SEC-008") {
		t.Error("want SEC-008 for AWS access key ID embedded in server URL")
	}
}

func TestCheckSecrets_SEC008_CleanURL_NoFire(t *testing.T) {
	// Clean URL with no secret patterns should not fire SEC-008
	s := &parser.MCPServer{
		Name: "clean-url",
		URL:  "https://api.example.com/mcp",
	}
	for _, f := range CheckSecrets(s) {
		if f.CheckID == "SEC-008" {
			t.Error("clean HTTPS URL should not fire SEC-008")
		}
	}
}

// ── SH-001 severity ───────────────────────────────────────────────────────────

func TestCheckShadow_SH001_Severity_IsInfo(t *testing.T) {
	// SH-001 fires at INFO severity (unverified package is a warning, not a critical)
	s := &parser.MCPServer{
		Name: "unknown-pkg", Command: "npx",
		Args: []string{"-y", "my-random-mcp-server"},
	}
	for _, f := range CheckShadow(s) {
		if f.CheckID == "SH-001" {
			if f.Severity != models.SeverityInfo {
				t.Errorf("SH-001 should be info severity, got %s", f.Severity)
			}
			return
		}
	}
	t.Error("expected SH-001 finding for unknown npm package")
}
