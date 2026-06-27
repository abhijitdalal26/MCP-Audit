package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// ── CWE ID presence on findings ──────────────────────────────────────────────

func TestFinding_CWESet_SEC001(t *testing.T) {
	s := &parser.MCPServer{
		Name: "cwe-test", Command: "npx",
		Args: []string{"-y", "pkg@1.0"},
		Env:  map[string]string{"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}
	for _, f := range CheckSecrets(s) {
		if f.CheckID == "SEC-001" && f.CWEID == "" {
			t.Error("SEC-001 finding should have a non-empty CWE ID")
		}
	}
}

func TestFinding_CWESet_SC001(t *testing.T) {
	s := &parser.MCPServer{
		Name: "cwe-sc001", Command: "npx",
		Args: []string{"-y", "mcp-server-free"},
	}
	for _, f := range CheckSupplyChain(s) {
		if f.CheckID == "SC-001" && f.CWEID == "" {
			t.Error("SC-001 finding should have a non-empty CWE ID")
		}
	}
}

func TestFinding_CWESet_PE005(t *testing.T) {
	s := &parser.MCPServer{
		Name: "docker-priv", Command: "docker",
		Args: []string{"run", "--privileged", "ubuntu"},
	}
	for _, f := range CheckPrivilege(s) {
		if f.CheckID == "PE-005" {
			if f.CWEID == "" {
				t.Error("PE-005 should have a CWE ID (expect CWE-250 or similar)")
			}
			return
		}
	}
}

func TestFinding_CWESet_SH004(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "filesysteм", // Cyrillic м
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
	}
	for _, f := range CheckShadow(s) {
		if f.CheckID == "SH-004" {
			if f.CWEID == "" {
				t.Error("SH-004 should carry a CWE ID")
			}
			return
		}
	}
	t.Error("expected SH-004 finding for homoglyph server name")
}

func TestFinding_CWESet_AT004(t *testing.T) {
	s := &parser.MCPServer{
		Name: "wildcard", Command: "node",
		Args: []string{"server.js"},
		URL:  "http://0.0.0.0:8000/mcp",
	}
	for _, f := range CheckAudit(s) {
		if f.CheckID == "AT-004" {
			if f.CWEID == "" {
				t.Error("AT-004 should carry a CWE ID (expect CWE-668)")
			}
			return
		}
	}
	t.Error("expected AT-004 finding for wildcard binding")
}

// ── OWASP category presence ───────────────────────────────────────────────────

func TestFinding_OWASP_SH004_IsMCP03(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "filesysteм", // Cyrillic м
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
	}
	for _, f := range CheckShadow(s) {
		if f.CheckID == "SH-004" {
			if string(f.OWASP) == "" {
				t.Error("SH-004 should have an OWASP category")
			}
			return
		}
	}
}

func TestFinding_OWASP_SC005_IsMCP04(t *testing.T) {
	// SC-005: GitHub-hosted package (corp/repo pattern)
	s := &parser.MCPServer{
		Name: "gh-pkg", Command: "npx",
		Args: []string{"-y", "canfieldjuan/pdf-generator"},
	}
	for _, f := range CheckSupplyChain(s) {
		if f.CheckID == "SC-005" {
			if string(f.OWASP) == "" {
				t.Error("SC-005 should have an OWASP category")
			}
			return
		}
	}
}

func TestFinding_OWASP_AT004_IsMCP08(t *testing.T) {
	s := &parser.MCPServer{
		Name: "wildcard", Command: "node",
		Args: []string{"server.js"},
		URL:  "http://[::]:8000",
	}
	for _, f := range CheckAudit(s) {
		if f.CheckID == "AT-004" {
			if string(f.OWASP) == "" {
				t.Error("AT-004 should have OWASP mapping")
			}
			return
		}
	}
}

func TestFinding_OWASP_PE005_IsMCP05(t *testing.T) {
	s := &parser.MCPServer{
		Name: "docker", Command: "docker",
		Args: []string{"run", "--privileged", "ubuntu"},
	}
	for _, f := range CheckPrivilege(s) {
		if f.CheckID == "PE-005" {
			if string(f.OWASP) == "" {
				t.Error("PE-005 should have OWASP mapping")
			}
			return
		}
	}
}

// ── AttackTactic presence ─────────────────────────────────────────────────────

func TestFinding_AttackTactic_SH004(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "filesysteм", // Cyrillic м
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
	}
	for _, f := range CheckShadow(s) {
		if f.CheckID == "SH-004" {
			if f.AttackTactic == "" {
				t.Error("SH-004 should have an AttackTactic (defense-evasion)")
			}
			return
		}
	}
	t.Error("no SH-004 finding for homoglyph server name")
}

func TestFinding_AttackTactic_SC005(t *testing.T) {
	s := &parser.MCPServer{
		Name: "gh-pkg", Command: "npx",
		Args: []string{"-y", "canfieldjuan/pdf-generator"},
	}
	for _, f := range CheckSupplyChain(s) {
		if f.CheckID == "SC-005" {
			if f.AttackTactic == "" {
				t.Error("SC-005 should have an AttackTactic (initial-access)")
			}
			return
		}
	}
}
