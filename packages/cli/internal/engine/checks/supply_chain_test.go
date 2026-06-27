package checks

import (
	"strings"
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func npxServer(pkg string) *parser.MCPServer {
	return &parser.MCPServer{Name: "test", Command: "npx", Args: []string{"-y", pkg}, Env: map[string]string{}, Headers: map[string]string{}}
}

func TestCheckSupplyChain_KnownMalicious(t *testing.T) {
	s := npxServer("mcp-server-free")
	findings := CheckSupplyChain(s)
	if !hasCheckID(findings, "SC-001") {
		t.Error("want SC-001 for known malicious package")
	}
}

func TestCheckSupplyChain_LiteLLMNpmMalicious(t *testing.T) {
	s := npxServer("litellm")
	findings := CheckSupplyChain(s)
	if !hasCheckID(findings, "SC-001") {
		t.Error("want SC-001 for litellm on npm (runtime-specific block)")
	}
}

func TestCheckSupplyChain_Typosquat_MissingO(t *testing.T) {
	// @modelcontextprotocl (missing 'o') — matches the lookahead-rewritten pattern
	s := npxServer("@modelcontextprotocl/server-filesystem")
	findings := CheckSupplyChain(s)
	if !hasCheckID(findings, "SC-002") {
		t.Error("want SC-002 for typosquatted package (missing o)")
	}
}

func TestCheckSupplyChain_LegitimateProtocol_NoSC002(t *testing.T) {
	// The legitimate @modelcontextprotocol/ should NOT trigger SC-002
	s := npxServer("@modelcontextprotocol/server-filesystem@1.2.3")
	findings := CheckSupplyChain(s)
	if hasCheckID(findings, "SC-002") {
		t.Error("legitimate @modelcontextprotocol package should NOT trigger SC-002")
	}
}

func TestCheckSupplyChain_UnverifiedScope(t *testing.T) {
	s := npxServer("@random-company/some-mcp-server")
	findings := CheckSupplyChain(s)
	if !hasCheckID(findings, "SC-003") {
		t.Error("want SC-003 for unverified npm scope")
	}
}

func TestCheckSupplyChain_TrustedScope_NoSC003(t *testing.T) {
	s := npxServer("@modelcontextprotocol/server-github@1.0.0")
	findings := CheckSupplyChain(s)
	if hasCheckID(findings, "SC-003") {
		t.Error("trusted scope should NOT trigger SC-003")
	}
}

func TestCheckSupplyChain_GitHubRef(t *testing.T) {
	s := npxServer("github:user/some-mcp-server")
	findings := CheckSupplyChain(s)
	if !hasCheckID(findings, "SC-005") {
		t.Error("want SC-005 for direct GitHub ref")
	}
}

func TestCheckSupplyChain_HomoglyphPackageName(t *testing.T) {
	// 'а' is Cyrillic (U+0430), not Latin 'a'
	s := npxServer("@аnthropic/mcp-server")
	findings := CheckSupplyChain(s)
	if !hasCheckID(findings, "SC-006") {
		t.Error("want SC-006 for homoglyph in package name")
	}
}

func TestCheckSupplyChain_CustomNpmRegistry(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", Command: "npx",
		Args:    []string{"--registry", "https://evil.example.com", "-y", "some-pkg"},
		Env:     map[string]string{},
		Headers: map[string]string{},
	}
	findings := CheckSupplyChain(s)
	if !hasCheckID(findings, "SC-007") {
		t.Error("want SC-007 for custom npm registry")
	}
}

func TestCheckSupplyChain_CustomNpmRegistryEnvVar(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", Command: "npx",
		Args:    []string{"-y", "some-pkg"},
		Env:     map[string]string{"NPM_CONFIG_REGISTRY": "https://evil.example.com"},
		Headers: map[string]string{},
	}
	findings := CheckSupplyChain(s)
	if !hasCheckID(findings, "SC-007") {
		t.Error("want SC-007 for npm registry env var override")
	}
}

func TestCheckSupplyChain_CustomPyPIIndex(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", Command: "uv",
		Args:    []string{"run", "--index-url", "https://evil.example.com", "--with", "mcp-server"},
		Env:     map[string]string{},
		Headers: map[string]string{},
	}
	findings := CheckSupplyChain(s)
	if !hasCheckID(findings, "SC-007") {
		t.Error("want SC-007 for custom PyPI index")
	}
}

func TestCheckSupplyChain_UVXPackage(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", Command: "uvx",
		Args:    []string{"mcp-server-free"},
		Env:     map[string]string{},
		Headers: map[string]string{},
	}
	findings := CheckSupplyChain(s)
	// mcp-server-free is known malicious
	if !hasCheckID(findings, "SC-001") {
		t.Error("want SC-001 for uvx running known malicious package")
	}
}

func TestBasePackageName(t *testing.T) {
	cases := []struct{ input, want string }{
		{"@modelcontextprotocol/server-filesystem@1.2.3", "@modelcontextprotocol/server-filesystem"},
		{"some-pkg@2.0.0", "some-pkg"},
		{"mcp-server==1.0.0", "mcp-server"},
		{"@scope/pkg", "@scope/pkg"},
	}
	for _, tc := range cases {
		got := basePackageName(tc.input)
		if got != tc.want {
			t.Errorf("basePackageName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestCheckSupplyChain_NoPackages(t *testing.T) {
	// Server with no recognisable package runner — no supply chain findings
	s := &parser.MCPServer{
		Name: "test", Command: "/usr/local/bin/my-server",
		Args:    []string{"--port", "9000"},
		Env:     map[string]string{},
		Headers: map[string]string{},
	}
	findings := CheckSupplyChain(s)
	if len(findings) != 0 {
		t.Errorf("want 0 findings for non-package server, got %d", len(findings))
	}
}

func TestCheckSupplyChain_OfficialNpmRegistry_NoSC007(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", Command: "npx",
		Args:    []string{"--registry", "https://registry.npmjs.org", "-y", "some-pkg"},
		Env:     map[string]string{},
		Headers: map[string]string{},
	}
	findings := CheckSupplyChain(s)
	if hasCheckID(findings, "SC-007") {
		t.Error("official npm registry should NOT trigger SC-007")
	}
}

func TestExtractPackages_UV_WithFlag(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", Command: "uv",
		Args:    []string{"run", "--with", "mcp-server-a", "--with", "mcp-server-b", "script.py"},
		Env:     map[string]string{},
		Headers: map[string]string{},
	}
	pkgs := extractPackages(s)
	if len(pkgs) != 2 {
		t.Errorf("want 2 packages, got %d", len(pkgs))
	}
	for _, p := range pkgs {
		if p.Runtime != "pypi" {
			t.Errorf("want pypi runtime, got %s", p.Runtime)
		}
	}
	names := []string{pkgs[0].Name, pkgs[1].Name}
	if !strings.Contains(strings.Join(names, " "), "mcp-server-a") {
		t.Error("missing mcp-server-a")
	}
}
