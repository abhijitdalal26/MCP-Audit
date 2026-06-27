package checks

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

var knownGoodScopes = map[string]bool{
	"@modelcontextprotocol": true,
	"@anthropic":            true,
	"@smithery":             true,
	"@aws":                  true,
	"@aws-sdk":              true,
	"@aws-cdk":              true,
	"@google":               true,
	"@google-cloud":         true,
	"@googleapis":           true,
	"@microsoft":            true,
	"@azure":                true,
	"@openai":               true,
	"@github":               true,
	"@vercel":               true,
	"@supabase":             true,
	"@cloudflare":           true,
	"@stripe":               true,
	"@sentry":               true,
	"@elastic":              true,
	"@raycast":              true,
	"@e2b":                  true,
	"@upstash":              true,
	"@linear":               true,
}

var knownGoodPackages = map[string]bool{
	"@modelcontextprotocol/server-filesystem":        true,
	"@modelcontextprotocol/server-github":            true,
	"@modelcontextprotocol/server-git":               true,
	"@modelcontextprotocol/server-google-drive":      true,
	"@modelcontextprotocol/server-slack":             true,
	"@modelcontextprotocol/server-postgres":          true,
	"@modelcontextprotocol/server-sqlite":            true,
	"@modelcontextprotocol/server-brave-search":      true,
	"@modelcontextprotocol/server-puppeteer":         true,
	"@modelcontextprotocol/server-fetch":             true,
	"@modelcontextprotocol/server-memory":            true,
	"@modelcontextprotocol/server-sequentialthinking": true,
	"@modelcontextprotocol/server-gdrive":            true,
	"@modelcontextprotocol/server-time":              true,
	"@modelcontextprotocol/server-everything":        true,
	"mcp-server-sqlite-npx":                         true,
	"@upstash/mcp-server":                           true,
	"@vercel/mcp-server":                            true,
	"@supabase/mcp-server-supabase":                 true,
	"mcp-server-sentry":                             true,
	"@raycast/mcp":                                  true,
	"mcp-obsidian":                                  true,
	"mcp-server-qdrant":                             true,
	"@e2b/mcp-server":                               true,
	"mcp-remote":                                    true,
	"mcp-server-firecrawl":                          true,
	"@firecrawl/mcp-server":                         true,
	"mcp-server-tavily":                             true,
	"mcp-server-perplexity":                         true,
	"mcp-server-linear":                             true,
	"mcp-server-jira":                               true,
	"mcp-server-notion":                             true,
	"mcp-server-slack":                              true,
	"mcp-server-github":                             true,
	"@wong2/mcp-cli":                               true,
	"mcp-server-macos":                              true,
	"mcp-server-playwright":                         true,
	"mcp-server-cursor":                             true,
	"@browserbase/mcp-server-browserbase":           true,
	"mcp-server-terminal":                           true,
	"mcp-server-docker":                             true,
	"@stripe/agent-toolkit":                         true,
}

var autoDiscoveryKeyRE = regexp.MustCompile(`(?i)(auto_?discover|plugin_?discover|dynamic_?load|server_?discover|tool_?discover)`)
var authLikeRE = regexp.MustCompile(`(?i)(api[_\-]?key|api[_\-]?token|auth[_\-]?token|bearer|secret|password|passwd|credential|oauth|jwt|x[_\-]?api|access[_\-]?token|id[_\-]?token|client[_\-]?secret|authorization|apikey)`)
var authInURLRE = regexp.MustCompile(`(?i)[?&](key|token|secret|auth|api_key)=`)

// stripVersion removes version pin from a package name for allowlist comparison.
func stripVersion(pkg string) string {
	if strings.HasPrefix(pkg, "@") {
		parts := strings.SplitN(pkg[1:], "/", 2)
		if len(parts) == 2 {
			atIdx := strings.Index(parts[1], "@")
			if atIdx != -1 {
				return "@" + parts[0] + "/" + parts[1][:atIdx]
			}
		}
		return pkg
	}
	if idx := strings.Index(pkg, "@"); idx != -1 {
		return pkg[:idx]
	}
	return pkg
}

func isKnownGood(pkg string) bool {
	base := strings.ToLower(stripVersion(pkg))
	if knownGoodPackages[base] {
		return true
	}
	if strings.HasPrefix(base, "@") {
		scope := strings.SplitN(base, "/", 2)[0]
		if knownGoodScopes[scope] {
			return true
		}
	}
	return false
}

func hasNonASCIILetters(text string) bool {
	for _, r := range text {
		if r > 127 && unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// CheckShadow checks for shadow server issues (SH-001..006).
func CheckShadow(server *parser.MCPServer) []models.Finding {
	findings := []models.Finding{}

	// SH-001: Unverified package not in known allowlist
	cmd := cmdBasename(server)
	if cmd == "npx" || cmd == "npm" || cmd == "uvx" {
		for _, arg := range server.Args {
			if !strings.HasPrefix(arg, "-") {
				if !isKnownGood(arg) {
					stripped := stripVersion(arg)
					findings = append(findings, models.Finding{
						CheckID:  "SH-001",
						Title:    fmt.Sprintf("Unverified MCP package: `%s`", stripped),
						Detail:   fmt.Sprintf("Server `%s` installs `%s`, which is not in MCPAudit's verified package allowlist (registry.modelcontextprotocol.io, Glama, Smithery). This does not mean the package is malicious — internal, new, or niche community servers are often unlisted. Verify the publisher and source before trusting it.", server.Name, arg),
						Severity: models.SeverityInfo,
						OWASP:    models.MCP09,
						ServerName: server.Name,
						Remediation: fmt.Sprintf("Verify `%s` against registry.modelcontextprotocol.io and glama.ai/mcp/servers. For internal packages, document ownership and audit the source code. Pin to an exact version after verification.", stripped),
						Engine:       "custom",
						AttackTactic: "initial-access",
						CWEID:        "CWE-829",
					})
				}
				break // one SH-001 per server
			}
		}
	}

	// SH-002: HTTP server without TLS (not localhost)
	if server.URL != "" {
		isLocalhost := strings.Contains(server.URL, "localhost") ||
			strings.Contains(server.URL, "127.0.0.1") ||
			strings.Contains(server.URL, "0.0.0.0")
		if strings.HasPrefix(server.URL, "http://") && !isLocalhost {
			findings = append(findings, models.Finding{
				CheckID:  "SH-002",
				Title:    fmt.Sprintf("MCP server using unencrypted HTTP: `%s`", server.URL),
				Detail:   fmt.Sprintf("Server `%s` connects to `%s` over plain HTTP. Unencrypted connections expose all MCP tool calls, responses, and any credentials passed to network interception (man-in-the-middle attacks).", server.Name, server.URL),
				Severity: models.SeverityHigh,
				OWASP:    models.MCP07,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Replace `%s` with an HTTPS equivalent. If the server operator does not support HTTPS, do not use it in production.", server.URL),
				Engine:       "custom",
				AttackTactic: "initial-access",
				CWEID:        "CWE-319",
			})
		}
	}

	// SH-003: Localhost URL backed by remotely-fetched npm package
	if server.URL != "" && (strings.Contains(server.URL, "localhost") || strings.Contains(server.URL, "127.0.0.1")) {
		if pkg := getNPMPackage(server); pkg != "" && !isLocalPath(server.Command) {
			findings = append(findings, models.Finding{
				CheckID:  "SH-003",
				Title:    fmt.Sprintf("Localhost server backed by remote package `%s`", pkg),
				Detail:   fmt.Sprintf("Server `%s` exposes a localhost URL (`%s`) but fetches `%s` from npm on every run. A malicious npm update could silently change what code runs on your local machine.", server.Name, server.URL, pkg),
				Severity: models.SeverityLow,
				OWASP:    models.MCP09,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Pin `%s` to an exact version and verify its integrity hash, or install it locally and reference the binary directly so it is not re-fetched each run.", pkg),
				Engine:   "custom",
				CWEID:    "CWE-346",
			})
		}
	}

	// SH-004: Unicode homoglyphs in server name
	if hasNonASCIILetters(server.Name) {
		var suspicious []string
		for _, r := range server.Name {
			if r > 127 && unicode.IsLetter(r) {
				suspicious = append(suspicious, fmt.Sprintf("U+%04X", r))
				if len(suspicious) >= 5 {
					break
				}
			}
		}
		findings = append(findings, models.Finding{
			CheckID:  "SH-004",
			Title:    fmt.Sprintf("Server name contains Unicode homoglyphs: `%s`", server.Name),
			Detail:   fmt.Sprintf("Server `%s` contains non-ASCII Unicode letters that may be visually indistinguishable from legitimate ASCII server names. Suspicious characters: %s. This is a Tool Name Spoofing attack (Adversa AI Top 25 MCP #12): a malicious server registers a name that looks identical to a trusted server (e.g., 'filesystem') but routes tool calls to a different, attacker-controlled implementation.", server.Name, strings.Join(suspicious, ", ")),
			Severity: models.SeverityHigh,
			OWASP:    models.MCP03,
			ServerName: server.Name,
			Remediation: "Remove this server from your config and investigate its source. Legitimate MCP server names use only ASCII characters (a-z, 0-9, hyphens, underscores). If you installed this from a third-party source, treat it as potentially malicious.",
			Engine:       "custom",
			AttackTactic: "defense-evasion",
			CWEID:        "CWE-1007",
		})
	}

	// SH-005: Auto-discovery env var enabling silent plugin loading
	for k, v := range server.Env {
		if autoDiscoveryKeyRE.MatchString(k) {
			vLower := strings.ToLower(v)
			if vLower == "true" || vLower == "1" || vLower == "yes" || vLower == "on" || vLower == "enabled" {
				findings = append(findings, models.Finding{
					CheckID:  "SH-005",
					Title:    fmt.Sprintf("Auto-discovery env var enables silent plugin loading: `%s=%s`", k, v),
					Detail:   fmt.Sprintf("Server `%s` has `%s=%s` in its environment, which enables automatic discovery and loading of MCP plugins or extensions at runtime. Auto-discovery means the server can silently load additional tool providers that were never explicitly approved in your MCP config — each discovered extension gains the same access level as the parent server.", server.Name, k, v),
					Severity: models.SeverityHigh,
					OWASP:    models.MCP09,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Set `%s=false` or remove the env var entirely. All MCP servers and tool providers should be explicitly listed in your config so you have full visibility over what has access to your AI assistant. If auto-discovery is required by this server, audit every extension it loads.", k),
					Engine:       "custom",
					AttackTactic: "persistence",
					CWEID:        "CWE-284",
				})
				break
			}
		}
	}

	// SH-006: HTTP/SSE transport with no authentication configuration
	if server.URL != "" && strings.HasPrefix(server.URL, "http") {
		hasAuthEnv := false
		for k := range server.Env {
			if authLikeRE.MatchString(k) {
				hasAuthEnv = true
				break
			}
		}
		hasAuthHeader := false
		for k := range server.Headers {
			if authLikeRE.MatchString(k) {
				hasAuthHeader = true
				break
			}
		}
		hasAuthURL := authInURLRE.MatchString(server.URL)

		if !hasAuthEnv && !hasAuthHeader && !hasAuthURL {
			findings = append(findings, models.Finding{
				CheckID:  "SH-006",
				Title:    fmt.Sprintf("HTTP MCP server appears to have no authentication: `%s`", server.URL),
				Detail:   fmt.Sprintf("Server `%s` connects to `%s` via HTTP/SSE transport but has no auth-related environment variables (API key, token, bearer, etc.), no auth headers configured, and no credential query parameters in the URL. If this endpoint is network-accessible, any process or user on the network can call its tools without proving identity. (Research: Censys 2026 — ~40%% of 12,520 exposed MCP services have no authentication)", server.Name, server.URL),
				Severity: models.SeverityMedium,
				OWASP:    models.MCP07,
				ServerName: server.Name,
				Remediation: "Add an authentication mechanism: set an API key via env var (e.g. `MCP_API_KEY`), use mTLS client certificates, or ensure the HTTP transport enforces token-based auth. Never expose an MCP HTTP endpoint on a shared network without authentication.",
				Engine:       "custom",
				AttackTactic: "initial-access",
				CWEID:        "CWE-306",
			})
		}
	}

	return findings
}

func getNPMPackage(server *parser.MCPServer) string {
	cmd := cmdBasename(server)
	if cmd == "npx" || cmd == "npm" {
		for _, arg := range server.Args {
			if !strings.HasPrefix(arg, "-") {
				return arg
			}
		}
	}
	return ""
}

func isLocalPath(command string) bool {
	return strings.Contains(command, "/") || strings.Contains(command, "\\")
}
