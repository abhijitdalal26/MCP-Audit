package checks

import (
	"fmt"
	"strings"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// CheckAudit checks for audit and telemetry issues (AT-002, AT-003, AT-004).
// AT-001 and AT-005/AT-006 are config-level and live in scanner.go.
func CheckAudit(server *parser.MCPServer) []models.Finding {
	findings := []models.Finding{}

	hasURL := server.URL != ""
	hasCommand := server.Command != ""
	hasStdioTransport := server.Transport == "" || server.Transport == "stdio"

	// AT-002: Transport ambiguity — both command and URL present
	if hasURL && hasCommand && hasStdioTransport {
		findings = append(findings, models.Finding{
			CheckID:  "AT-002",
			Title:    "Transport ambiguity: server has both `command` and `url` fields",
			Detail:   fmt.Sprintf("Server `%s` specifies both a `command` field (`%s`) and a `url` field (`%s`). MCP servers use either stdio transport (command-based) or SSE/HTTP transport (URL-based), not both. This inconsistency may indicate a misconfigured config or an attempt to obscure which transport is actually used.", server.Name, server.Command, server.URL),
			Severity: models.SeverityLow,
			OWASP:    models.MCP08,
			ServerName: server.Name,
			Remediation: "Remove one of `command` or `url` depending on the server's actual transport. stdio servers: keep `command`, remove `url`. Remote servers: keep `url`, remove `command` (or use it only for the local proxy).",
			Engine:   "custom",
			CWEID:    "CWE-16",
		})
	}

	// AT-003: Remote URL without explicit transport declaration
	validTransports := map[string]bool{"sse": true, "http": true, "streamable-http": true, "ws": true, "websocket": true}
	if hasURL && !hasCommand && !validTransports[strings.ToLower(server.Transport)] {
		findings = append(findings, models.Finding{
			CheckID:  "AT-003",
			Title:    "Remote server URL without explicit transport declaration",
			Detail:   fmt.Sprintf("Server `%s` connects to a remote URL (`%s`) but does not declare a `transport` type (e.g., `sse` or `streamable-http`). Without an explicit transport declaration, the MCP client will guess, which can lead to unexpected behavior or security issues if the server uses a non-default protocol.", server.Name, server.URL),
			Severity: models.SeverityInfo,
			OWASP:    models.MCP08,
			ServerName: server.Name,
			Remediation: fmt.Sprintf("Add `\"transport\": \"sse\"` or `\"transport\": \"streamable-http\"` to the `%s` server config to make the transport explicit.", server.Name),
			Engine:   "custom",
			CWEID:    "CWE-16",
		})
	}

	// AT-004: Server bound to all network interfaces (0.0.0.0 or [::])
	for _, pattern := range []string{"0.0.0.0", "[::]"} {
		if server.URL != "" && strings.Contains(server.URL, pattern) {
			findings = append(findings, models.Finding{
				CheckID:  "AT-004",
				Title:    fmt.Sprintf("MCP server bound to all network interfaces: `%s`", server.URL),
				Detail:   fmt.Sprintf("Server `%s` is configured with URL `%s` containing `%s`, which listens on ALL network interfaces — not just localhost. Any device on the same local network (or the internet if no firewall) can send MCP tool calls to this server without any authentication. This is the NeighborJack attack pattern: a malicious device on the same WiFi can invoke your MCP tools, read filesystem contents, or exfiltrate data.", server.Name, server.URL, pattern),
				Severity: models.SeverityHigh,
				OWASP:    models.MCP08,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Replace `%s` with `127.0.0.1` (IPv4 localhost) or `[::1]` (IPv6 loopback) to restrict the server to the local machine only. If this server must be network-accessible, add authentication and TLS (HTTPS).", pattern),
				Engine:       "custom",
				AttackTactic: "initial-access",
				CWEID:        "CWE-668",
			})
			break
		}
	}

	return findings
}
