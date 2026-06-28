package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckSupplyChain_Clean(t *testing.T) {
	s := &parser.MCPServer{
		Name: "clean", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
	}
	findings := CheckSupplyChain(s)
	for _, f := range findings {
		if f.CheckID == "SC-001" || f.CheckID == "SC-002" {
			t.Errorf("clean server should not have %s, got: %s", f.CheckID, f.Title)
		}
	}
}

func TestCheckSupplyChain_SC001_KnownMalicious(t *testing.T) {
	s := &parser.MCPServer{
		Name: "bad", Command: "npx",
		Args: []string{"-y", "mcp-server-free"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-001") {
		t.Error("want SC-001 for known-malicious package mcp-server-free")
	}
}

func TestCheckSupplyChain_SC001_LiteLLMOnNPM(t *testing.T) {
	// litellm is legitimate on PyPI but was supply-chain-attacked on npm
	s := &parser.MCPServer{
		Name: "bad", Command: "npx",
		Args: []string{"-y", "litellm"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-001") {
		t.Error("want SC-001 for litellm on npm")
	}
}

func TestCheckSupplyChain_SC002_TypoSqauat_MissingO(t *testing.T) {
	// @modelcontextprotocl (missing 'o' in protocol)
	s := &parser.MCPServer{
		Name: "bad", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocl/server-filesystem"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-002") {
		t.Error("want SC-002 for typosquat @modelcontextprotocl")
	}
}

func TestCheckSupplyChain_SC002_LegitPackageNotFlagged(t *testing.T) {
	// @modelcontextprotocol/server-filesystem should NOT be SC-002
	s := &parser.MCPServer{
		Name: "clean", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
	}
	if hasCheckID(CheckSupplyChain(s), "SC-002") {
		t.Error("legitimate @modelcontextprotocol package should NOT trigger SC-002")
	}
}

func TestCheckSupplyChain_SC003_UnverifiedScope(t *testing.T) {
	s := &parser.MCPServer{
		Name: "third-party", Command: "npx",
		Args: []string{"-y", "@random-company/my-mcp-server@1.0"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-003") {
		t.Error("want SC-003 for unverified scope @random-company")
	}
}

func TestCheckSupplyChain_SC003_TrustedScopeNotFlagged(t *testing.T) {
	s := &parser.MCPServer{
		Name: "aws", Command: "npx",
		Args: []string{"-y", "@aws-sdk/mcp-server-something@1.0"},
	}
	if hasCheckID(CheckSupplyChain(s), "SC-003") {
		t.Error("@aws-sdk scope should NOT trigger SC-003")
	}
}

func TestCheckSupplyChain_SC005_GitHubRef(t *testing.T) {
	s := &parser.MCPServer{
		Name: "gitdep", Command: "npx",
		Args: []string{"-y", "github:some-user/some-mcp-server"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-005") {
		t.Error("want SC-005 for direct github: ref")
	}
}

func TestCheckSupplyChain_SC005_GitLabRef(t *testing.T) {
	s := &parser.MCPServer{
		Name: "gitdep", Command: "npx",
		Args: []string{"-y", "gitlab:some-user/some-mcp-server"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-005") {
		t.Error("want SC-005 for direct gitlab: ref")
	}
}

func TestCheckSupplyChain_SC006_HomoglyphNPM(t *testing.T) {
	// Package name with Cyrillic character
	s := &parser.MCPServer{
		Name: "hg", Command: "npx",
		Args: []string{"-y", "mcp-server-аnthropic"}, // Cyrillic 'а' at start
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-006") {
		t.Error("want SC-006 for non-ASCII package name")
	}
}

func TestCheckSupplyChain_SC008_GitHTTPS(t *testing.T) {
	s := &parser.MCPServer{
		Name: "giturl", Command: "npx",
		Args: []string{"-y", "git+https://github.com/user/mcp-server.git"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-008") {
		t.Error("want SC-008 for git+https:// package URL")
	}
}

func TestCheckSupplyChain_SC008_GitSSH(t *testing.T) {
	s := &parser.MCPServer{
		Name: "giturl", Command: "npx",
		Args: []string{"-y", "git+ssh://git@github.com/user/mcp-server.git"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-008") {
		t.Error("want SC-008 for git+ssh:// package URL")
	}
}

func TestCheckSupplyChain_SC008_TarballURL(t *testing.T) {
	// npx accepts tarball URLs directly; the extractor returns the first non-flag arg
	s := &parser.MCPServer{
		Name: "tarball", Command: "npx",
		Args: []string{"https://example.com/mcp-server-1.0.0.tar.gz"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-008") {
		t.Error("want SC-008 for tarball URL package")
	}
}

func TestCheckSupplyChain_SC008_NoFire_NormalHTTPS(t *testing.T) {
	// A normal https URL that is NOT a tarball should not fire SC-008
	s := &parser.MCPServer{
		Name: "srv", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"},
	}
	if hasCheckID(CheckSupplyChain(s), "SC-008") {
		t.Error("SC-008 should not fire for normal npm package with version pin")
	}
}

func TestCheckSupplyChain_SC007_RegistryOverride(t *testing.T) {
	s := &parser.MCPServer{
		Name: "custom-reg", Command: "npx",
		Args: []string{"-y", "--registry", "https://my-private-registry.example.com", "some-package@1.0"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-007") {
		t.Error("want SC-007 for custom npm registry")
	}
}

func TestCheckSupplyChain_SC007_RegistryOverrideEqual(t *testing.T) {
	s := &parser.MCPServer{
		Name: "custom-reg", Command: "npx",
		Args: []string{"-y", "--registry=https://my-private-registry.example.com", "some-package@1.0"},
	}
	if !hasCheckID(CheckSupplyChain(s), "SC-007") {
		t.Error("want SC-007 for --registry= syntax")
	}
}

func TestCheckSupplyChain_SC007_OfficialRegistryOK(t *testing.T) {
	s := &parser.MCPServer{
		Name: "ok-reg", Command: "npx",
		Args: []string{"-y", "--registry", "https://registry.npmjs.org", "some-package@1.0"},
	}
	if hasCheckID(CheckSupplyChain(s), "SC-007") {
		t.Error("official registry should NOT trigger SC-007")
	}
}

func TestCheckSupplyChain_UVX_PyPI(t *testing.T) {
	s := &parser.MCPServer{
		Name: "uvx-server", Command: "uvx",
		Args: []string{"mcp-server-fetch"},
	}
	// Should produce SC findings for unverified package
	findings := CheckSupplyChain(s)
	_ = findings // just ensure no panic
}

func TestCheckSupplyChain_UV_With(t *testing.T) {
	s := &parser.MCPServer{
		Name: "uv-server", Command: "uv",
		Args: []string{"run", "--with", "mcp-server-a", "--with", "mcp-server-b", "main.py"},
	}
	pkgs := extractPackages(s)
	if len(pkgs) != 2 {
		t.Errorf("want 2 packages from --with flags, got %d", len(pkgs))
	}
	for _, p := range pkgs {
		if p.Runtime != "pypi" {
			t.Errorf("want pypi runtime for uv --with, got %s", p.Runtime)
		}
	}
}

func TestCheckSupplyChain_BasePackageName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"@scope/pkg@1.0.0", "@scope/pkg"},
		{"@scope/pkg", "@scope/pkg"},
		{"simple-pkg@2.0.0", "simple-pkg"},
		{"simple-pkg", "simple-pkg"},
		{"pkg==1.2.3", "pkg"},
		{"pkg>=1.0", "pkg"},
	}
	for _, tc := range cases {
		got := basePackageName(tc.in)
		if got != tc.want {
			t.Errorf("basePackageName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
