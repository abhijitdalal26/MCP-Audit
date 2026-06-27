package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckAudit_AT002_BothCommandAndURL(t *testing.T) {
	// AT-002: transport ambiguity — both command AND url present simultaneously
	s := &parser.MCPServer{
		Name:    "ambiguous",
		Command: "npx",
		Args:    []string{"-y", "mcp-server@1.0"},
		URL:     "https://api.example.com/mcp",
	}
	if !hasCheckID(CheckAudit(s), "AT-002") {
		t.Error("want AT-002 when both command and url are set (transport ambiguity)")
	}
}

func TestCheckAudit_AT002_CommandOnly_NoFire(t *testing.T) {
	s := &parser.MCPServer{
		Name: "stdio-only", Command: "npx",
		Args: []string{"-y", "mcp-server@1.0"},
	}
	if hasCheckID(CheckAudit(s), "AT-002") {
		t.Error("command-only server should NOT trigger AT-002")
	}
}

func TestCheckAudit_AT003_URLNoTransport(t *testing.T) {
	// AT-003: remote URL without explicit transport type declared
	s := &parser.MCPServer{
		Name: "remote-no-transport",
		URL:  "https://api.example.com/mcp",
	}
	if !hasCheckID(CheckAudit(s), "AT-003") {
		t.Error("want AT-003 for remote URL without transport declaration")
	}
}

func TestCheckAudit_AT003_URLWithSSETransport_NoFire(t *testing.T) {
	s := &parser.MCPServer{
		Name:      "remote-sse",
		URL:       "https://api.example.com/mcp",
		Transport: "sse",
	}
	if hasCheckID(CheckAudit(s), "AT-003") {
		t.Error("URL server with explicit 'sse' transport should NOT trigger AT-003")
	}
}

func TestCheckAudit_AT003_URLWithHTTPTransport_NoFire(t *testing.T) {
	s := &parser.MCPServer{
		Name:      "remote-http",
		URL:       "https://api.example.com/mcp",
		Transport: "http",
	}
	if hasCheckID(CheckAudit(s), "AT-003") {
		t.Error("URL server with explicit 'http' transport should NOT trigger AT-003")
	}
}

func TestCheckAudit_AT003_URLWithStreamableHTTP_NoFire(t *testing.T) {
	s := &parser.MCPServer{
		Name:      "remote-shttp",
		URL:       "https://api.example.com/mcp",
		Transport: "streamable-http",
	}
	if hasCheckID(CheckAudit(s), "AT-003") {
		t.Error("URL server with 'streamable-http' transport should NOT trigger AT-003")
	}
}

func TestCheckAudit_AT004_WildcardBinding(t *testing.T) {
	s := &parser.MCPServer{
		Name: "wildcard", Command: "node",
		Args: []string{"server.js"},
		URL:  "http://0.0.0.0:8000/mcp",
	}
	if !hasCheckID(CheckAudit(s), "AT-004") {
		t.Error("want AT-004 for 0.0.0.0 wildcard binding in URL")
	}
}

func TestCheckAudit_AT004_IPv6WildcardBinding(t *testing.T) {
	s := &parser.MCPServer{
		Name: "ipv6-wildcard", Command: "node",
		Args: []string{"server.js"},
		URL:  "http://[::]:8000/mcp",
	}
	if !hasCheckID(CheckAudit(s), "AT-004") {
		t.Error("want AT-004 for [::] IPv6 wildcard binding in URL")
	}
}

func TestCheckAudit_AT004_LocalhostOK(t *testing.T) {
	s := &parser.MCPServer{
		Name: "local", Command: "node",
		Args: []string{"server.js"},
		URL:  "http://localhost:8000/mcp",
	}
	if hasCheckID(CheckAudit(s), "AT-004") {
		t.Error("localhost binding should NOT trigger AT-004")
	}
}

func TestCheckAudit_AT004_127Binding(t *testing.T) {
	s := &parser.MCPServer{
		Name: "loopback", Command: "node",
		Args: []string{"server.js"},
		URL:  "http://127.0.0.1:8000/mcp",
	}
	if hasCheckID(CheckAudit(s), "AT-004") {
		t.Error("127.0.0.1 loopback binding should NOT trigger AT-004")
	}
}

func TestCheckAudit_Clean_StdioOnly(t *testing.T) {
	s := &parser.MCPServer{
		Name: "clean", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"},
		Env:  map[string]string{},
	}
	findings := CheckAudit(s)
	for _, f := range findings {
		if f.CheckID == "AT-002" || f.CheckID == "AT-003" || f.CheckID == "AT-004" {
			t.Errorf("clean stdio server should not trigger %s", f.CheckID)
		}
	}
}
