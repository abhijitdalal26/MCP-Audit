package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func serverWith(env map[string]string) *parser.MCPServer {
	return &parser.MCPServer{Name: "test", Command: "npx", Env: env, Headers: map[string]string{}}
}

func hasCheckID(findings []models.Finding, id string) bool {
	for _, f := range findings {
		if f.CheckID == id {
			return true
		}
	}
	return false
}

func TestCheckSecrets_AWSKey(t *testing.T) {
	s := serverWith(map[string]string{"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"})
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-001") {
		t.Error("want SEC-001 for AWS key in env")
	}
}

func TestCheckSecrets_GitHubToken(t *testing.T) {
	s := serverWith(map[string]string{"TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz012345678901"})
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-002") {
		t.Error("want SEC-002 for GitHub token")
	}
}

func TestCheckSecrets_PostgresURL(t *testing.T) {
	s := serverWith(map[string]string{"DATABASE_URL": "postgresql://user:pass@host:5432/db"})
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-003") {
		t.Error("want SEC-003 for postgres URL")
	}
}

func TestCheckSecrets_OpenAIKey(t *testing.T) {
	s := serverWith(map[string]string{"OPENAI_API_KEY": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789abcdefgh"})
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-004") {
		t.Error("want SEC-004 for OpenAI key")
	}
}

func TestCheckSecrets_SSHKey(t *testing.T) {
	s := serverWith(map[string]string{"KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."})
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-005") {
		t.Error("want SEC-005 for SSH key")
	}
}

func TestCheckSecrets_PlaceholderIgnored(t *testing.T) {
	s := serverWith(map[string]string{"API_KEY": "${MY_API_KEY}"})
	findings := CheckSecrets(s)
	if hasCheckID(findings, "SEC-004") {
		t.Error("placeholder should not trigger SEC-004")
	}
}

func TestCheckSecrets_SensitiveVarName(t *testing.T) {
	// Key name is sensitive even with a non-pattern value
	s := serverWith(map[string]string{"aws_secret_access_key": "someval"})
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-001") {
		t.Error("want SEC-001 for sensitive var name aws_secret_access_key")
	}
}

func TestCheckSecrets_CloudIMDS(t *testing.T) {
	s := serverWith(map[string]string{"METADATA_URL": "http://169.254.169.254/latest/meta-data/"})
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-007") {
		t.Error("want SEC-007 for cloud metadata endpoint")
	}
}

func TestCheckSecrets_CredentialsInArgs(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", Command: "npx",
		Args:    []string{"-y", "some-server", "--api-key", "ghp_abcdefghijklmnopqrstuvwxyz012345678901"},
		Env:     map[string]string{},
		Headers: map[string]string{},
	}
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-002") {
		t.Error("want SEC-002 for GitHub token in args")
	}
}

func TestCheckSecrets_CredentialsInURL(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", URL: "https://user:AKIAIOSFODNN7EXAMPLE@api.example.com/mcp",
		Env: map[string]string{}, Headers: map[string]string{},
	}
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-008") {
		t.Error("want SEC-008 for credentials in URL")
	}
}

func TestCheckSecrets_UnpinnedPackage(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem"},
		Env:     map[string]string{},
		Headers: map[string]string{},
	}
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-006") {
		t.Error("want SEC-006 for unpinned package")
	}
}

func TestCheckSecrets_PinnedPackageNoSEC006(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
		Env:     map[string]string{},
		Headers: map[string]string{},
	}
	findings := CheckSecrets(s)
	if hasCheckID(findings, "SEC-006") {
		t.Error("pinned package should NOT trigger SEC-006")
	}
}

func TestCheckSecrets_Clean(t *testing.T) {
	s := &parser.MCPServer{
		Name: "clean", Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/home/user/projects"},
		Env:     map[string]string{"LOG_LEVEL": "debug"},
		Headers: map[string]string{},
	}
	findings := CheckSecrets(s)
	for _, f := range findings {
		if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
			t.Errorf("clean server should have no critical/high findings, got %s: %s", f.CheckID, f.Title)
		}
	}
}

func TestIsPinned(t *testing.T) {
	cases := []struct {
		arg   string
		want  bool
	}{
		{"@modelcontextprotocol/server-filesystem@1.2.3", true},
		{"@modelcontextprotocol/server-filesystem", false},
		{"@modelcontextprotocol/server-filesystem@latest", false},
		{"some-pkg@2.0.0", true},
		{"some-pkg@beta", false},
		{"some-pkg", false},
	}
	for _, tc := range cases {
		got := isPinned(tc.arg)
		if got != tc.want {
			t.Errorf("isPinned(%q) = %v, want %v", tc.arg, got, tc.want)
		}
	}
}
