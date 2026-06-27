package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// ── SH-005: Auto-discovery / dynamic loading ──────────────────────────────────

func TestCheckShadow_SH005_MCPAutoDiscovery(t *testing.T) {
	// SH-005: env var enabling auto-discovery of MCP servers at runtime
	s := &parser.MCPServer{
		Name: "auto-discover", Command: "npx",
		Args: []string{"-y", "mcp-server@1.0"},
		Env:  map[string]string{"MCP_AUTO_DISCOVERY": "true"},
	}
	if !hasCheckID(CheckShadow(s), "SH-005") {
		t.Error("want SH-005 for MCP_AUTO_DISCOVERY=true")
	}
}

func TestCheckShadow_SH005_PluginDiscoverEnabled(t *testing.T) {
	s := &parser.MCPServer{
		Name: "plugin-discover", Command: "node",
		Args: []string{"server.js"},
		Env:  map[string]string{"PLUGIN_DISCOVER": "enabled"},
	}
	if !hasCheckID(CheckShadow(s), "SH-005") {
		t.Error("want SH-005 for PLUGIN_DISCOVER=enabled")
	}
}

func TestCheckShadow_SH005_AutoDiscoveryFalse_NoFire(t *testing.T) {
	s := &parser.MCPServer{
		Name: "no-discover", Command: "node",
		Args: []string{"server.js"},
		Env:  map[string]string{"MCP_AUTO_DISCOVERY": "false"},
	}
	if hasCheckID(CheckShadow(s), "SH-005") {
		t.Error("MCP_AUTO_DISCOVERY=false should NOT trigger SH-005")
	}
}

func TestCheckShadow_SH005_UnrelatedEnv_NoFire(t *testing.T) {
	s := &parser.MCPServer{
		Name: "clean", Command: "node",
		Args: []string{"server.js"},
		Env:  map[string]string{"NODE_ENV": "production", "PORT": "8080"},
	}
	if hasCheckID(CheckShadow(s), "SH-005") {
		t.Error("unrelated env vars should NOT trigger SH-005")
	}
}

func TestCheckShadow_SH005_DynamicLoad(t *testing.T) {
	s := &parser.MCPServer{
		Name: "dyn-load", Command: "node",
		Args: []string{"server.js"},
		Env:  map[string]string{"DYNAMIC_LOAD": "yes"},
	}
	if !hasCheckID(CheckShadow(s), "SH-005") {
		t.Error("want SH-005 for DYNAMIC_LOAD=yes")
	}
}

// ── SH-005 CWE and OWASP ────────────────────────────────────────────────────

func TestCheckShadow_SH005_OWASPCategory(t *testing.T) {
	s := &parser.MCPServer{
		Name: "auto-discover", Command: "npx",
		Args: []string{"-y", "mcp-server@1.0"},
		Env:  map[string]string{"MCP_AUTO_DISCOVERY": "true"},
	}
	for _, f := range CheckShadow(s) {
		if f.CheckID == "SH-005" {
			if string(f.OWASP) == "" {
				t.Error("SH-005 should carry an OWASP category")
			}
			return
		}
	}
}

func TestCheckShadow_SH005_CWEPresent(t *testing.T) {
	s := &parser.MCPServer{
		Name: "auto-discover", Command: "npx",
		Args: []string{"-y", "mcp-server@1.0"},
		Env:  map[string]string{"MCP_AUTO_DISCOVERY": "true"},
	}
	for _, f := range CheckShadow(s) {
		if f.CheckID == "SH-005" {
			if f.CWEID == "" {
				t.Error("SH-005 should carry a CWE ID")
			}
			return
		}
	}
}
