package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

var clShellKeywords = []string{"--exec", "--shell", "--cmd", "/bin/sh", "/bin/bash", "cmd.exe", "powershell.exe"}
var clBroadPaths = []string{"/", "/Users", "/home", "/root", "/etc", "C:\\", "C:\\Users"}
var debugEnvRE = regexp.MustCompile(`(?i)^(debug|verbose|log_level|logging_level|loglevel)$`)
var debugValRE = regexp.MustCompile(`(?i)^(true|1|debug|verbose|all|trace)$`)
var clSecretCheckIDs = map[string]bool{
	"SEC-001": true, "SEC-002": true, "SEC-003": true, "SEC-004": true, "SEC-005": true,
}

type securityDisablePattern struct {
	keyRE   *regexp.Regexp
	valRE   *regexp.Regexp
	desc    string
	sev     models.Severity
	cwe     string
}

var securityDisablePatterns = []securityDisablePattern{
	{
		regexp.MustCompile(`^NODE_TLS_REJECT_UNAUTHORIZED$`),
		regexp.MustCompile(`^0$`),
		"TLS certificate verification disabled (NODE_TLS_REJECT_UNAUTHORIZED=0) — all HTTPS requests accept invalid/self-signed certs",
		models.SeverityHigh, "CWE-295",
	},
	{
		regexp.MustCompile(`(?i)^(disable_?auth|auth_?bypass|skip_?auth|no_?auth)$`),
		regexp.MustCompile(`(?i)^(true|1|yes|on)$`),
		"Authentication disabled via env var",
		models.SeverityHigh, "CWE-306",
	},
	{
		regexp.MustCompile(`(?i)^(skip_tls(_verify)?|skip_ssl(_verify)?|no_?verify|insecure_skip_verify)$`),
		regexp.MustCompile(`(?i)^(true|1|yes|on)$`),
		"TLS/SSL verification skipped via env var",
		models.SeverityHigh, "CWE-295",
	},
	{
		regexp.MustCompile(`(?i)^(ssl_?verify|tls_?verify|verify_?ssl|verify_?tls)$`),
		regexp.MustCompile(`(?i)^(false|0|no|off)$`),
		"TLS/SSL verification disabled via env var",
		models.SeverityHigh, "CWE-295",
	},
	{
		regexp.MustCompile(`(?i)^(disable_?security|security_?disabled|bypass_?security)$`),
		regexp.MustCompile(`(?i)^(true|1|yes|on)$`),
		"Security mechanism disabled via env var",
		models.SeverityHigh, "CWE-284",
	},
	{
		regexp.MustCompile(`(?i)^(allow_?insecure|insecure_?mode|unsafe_?mode)$`),
		regexp.MustCompile(`(?i)^(true|1|yes|on)$`),
		"Insecure mode enabled via env var",
		models.SeverityMedium, "CWE-284",
	},
}

func clHasSecrets(serverName string, perServer map[string][]models.Finding) bool {
	for _, f := range perServer[serverName] {
		if clSecretCheckIDs[f.CheckID] {
			return true
		}
	}
	return false
}

func clHasShell(server *parser.MCPServer) bool {
	for _, arg := range server.Args {
		argL := strings.ToLower(arg)
		for _, kw := range clShellKeywords {
			if strings.Contains(argL, strings.ToLower(kw)) {
				return true
			}
		}
	}
	return false
}

func clHasBroadFS(server *parser.MCPServer) bool {
	for _, arg := range server.Args {
		for _, broad := range clBroadPaths {
			if arg == broad {
				return true
			}
			if strings.HasPrefix(arg, broad+"/") || strings.HasPrefix(arg, broad+"\\") {
				argParts := strings.Split(strings.ReplaceAll(strings.TrimRight(arg, "/\\"), "\\", "/"), "/")
				broadParts := strings.Split(strings.ReplaceAll(strings.TrimRight(broad, "/\\"), "\\", "/"), "/")
				if len(argParts) <= len(broadParts)+1 {
					return true
				}
			}
		}
	}
	return false
}

func isWildcardAutoApprove(aa *parser.AutoApprove) bool {
	if aa == nil {
		return false
	}
	if aa.Bool != nil && *aa.Bool {
		return true
	}
	if aa.Str != nil {
		v := strings.ToLower(strings.TrimSpace(*aa.Str))
		return v == "*" || v == "all" || v == "true"
	}
	for _, item := range aa.List {
		l := strings.ToLower(strings.TrimSpace(item))
		if l == "*" || l == "all" {
			return true
		}
	}
	return false
}

// CheckConfigLevel runs cross-server config checks (CL-001..004, EC-001).
func CheckConfigLevel(config *parser.MCPConfig, perServer map[string][]models.Finding) []models.Finding {
	findings := []models.Finding{}
	checkConfusedDeputy(config, perServer, &findings)
	checkDuplicateServers(config, &findings)
	checkDebugLoggingExposure(config, perServer, &findings)
	checkSecurityFeatureDisabled(config, &findings)
	checkAutoApprove(config, &findings)
	return findings
}

func checkConfusedDeputy(config *parser.MCPConfig, perServer map[string][]models.Finding, out *[]models.Finding) {
	for _, server := range config.Servers {
		hasBroad := clHasBroadFS(&server)
		hasShell := clHasShell(&server)
		hasSecrets := clHasSecrets(server.Name, perServer)

		if hasBroad && hasShell {
			*out = append(*out, models.Finding{
				CheckID:    "CL-001",
				Title:      fmt.Sprintf("Confused deputy risk: `%s` has broad filesystem AND shell execution", server.Name),
				Detail:     fmt.Sprintf("Server `%s` combines over-broad filesystem access with shell execution capability. This is a classic confused deputy setup: if an attacker tricks your AI assistant into calling this server's tools, the server can silently exfiltrate any file on your system by using its legitimate filesystem access and shell. Neither permission seems dangerous in isolation — combined, they are.", server.Name),
				Severity:   models.SeverityHigh,
				OWASP:      models.MCP02,
				ServerName: server.Name,
				Remediation: "Separate filesystem and shell capabilities into two different, minimal-permission servers. The filesystem server should only access a specific project directory (not /Users or /). The shell server should not have access to sensitive directories.",
				Engine:       "custom",
				AttackTactic: "privilege-escalation",
				CWEID:        "CWE-441",
			})
		}
		if hasSecrets && hasShell && !hasBroad {
			*out = append(*out, models.Finding{
				CheckID:    "CL-001",
				Title:      fmt.Sprintf("Confused deputy risk: `%s` has hardcoded secrets AND shell execution", server.Name),
				Detail:     fmt.Sprintf("Server `%s` has hardcoded API credentials AND shell execution capability. An attacker who compromises this server can use the shell to exfiltrate the credentials without any AI involvement — the server already has everything needed.", server.Name),
				Severity:   models.SeverityHigh,
				OWASP:      models.MCP02,
				ServerName: server.Name,
				Remediation: "Remove hardcoded credentials and shell execution from the same server. Use environment variable injection at the system level (shell profile) rather than embedding secrets in the MCP config.",
				Engine:       "custom",
				AttackTactic: "credential-access",
				CWEID:        "CWE-441",
			})
		}
	}
}

func checkDuplicateServers(config *parser.MCPConfig, out *[]models.Finding) {
	seen := map[string]string{} // "command:firstPkg" -> server name

	for _, server := range config.Servers {
		if server.Command == "" {
			continue
		}
		firstPkg := ""
		for _, a := range server.Args {
			if !strings.HasPrefix(a, "-") {
				firstPkg = a
				break
			}
		}
		if firstPkg == "" {
			continue
		}
		key := server.Command + ":" + firstPkg
		if prev, ok := seen[key]; ok {
			*out = append(*out, models.Finding{
				CheckID:    "CL-002",
				Title:      fmt.Sprintf("Duplicate server package: `%s` duplicates `%s`", server.Name, prev),
				Detail:     fmt.Sprintf("Servers `%s` and `%s` both run `%s %s`. Multiple entries for the same package may indicate a tool-shadowing attack where a malicious server is registered under a different name to intercept or override tool calls from the legitimate server.", server.Name, prev, server.Command, firstPkg),
				Severity:   models.SeverityMedium,
				OWASP:      models.MCP03,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Remove the duplicate entry `%s` if it is unintentional. If both servers are needed, verify they have different purposes and that the second entry is not a misconfigured or injected copy.", server.Name),
				Engine:   "custom",
				CWEID:    "CWE-290",
			})
		} else {
			seen[key] = server.Name
		}
	}
}

func checkSecurityFeatureDisabled(config *parser.MCPConfig, out *[]models.Finding) {
	for _, server := range config.Servers {
		for envKey, envVal := range server.Env {
			if envVal == "" {
				continue
			}
			for _, pat := range securityDisablePatterns {
				if pat.keyRE.MatchString(envKey) && pat.valRE.MatchString(strings.TrimSpace(envVal)) {
					*out = append(*out, models.Finding{
						CheckID:    "CL-003",
						Title:      fmt.Sprintf("Security feature disabled: `%s=%s` in `%s`", envKey, envVal, server.Name),
						Detail:     fmt.Sprintf("Server `%s` has `%s=%s`, which %s. Disabling security features in MCP server configurations is a common development shortcut that frequently persists into production. When Claude Desktop loads this config, the server runs with degraded security.", server.Name, envKey, envVal, pat.desc),
						Severity:   pat.sev,
						OWASP:      models.MCP07,
						ServerName: server.Name,
						Remediation: fmt.Sprintf("Remove `%s=%s` from the server configuration. If TLS verification is disabled to handle self-signed certificates, add the certificate to your trust store instead. If authentication is disabled for development, use a separate dev config that is never loaded in production.", envKey, envVal),
						Engine:   "custom",
						CWEID:    pat.cwe,
					})
					break
				}
			}
		}
	}
}

func checkDebugLoggingExposure(config *parser.MCPConfig, perServer map[string][]models.Finding, out *[]models.Finding) {
	for _, server := range config.Servers {
		if !clHasSecrets(server.Name, perServer) {
			continue
		}
		for envKey, envVal := range server.Env {
			if debugEnvRE.MatchString(envKey) && debugValRE.MatchString(envVal) {
				*out = append(*out, models.Finding{
					CheckID:    "EC-001",
					Title:      fmt.Sprintf("Debug logging enabled with hardcoded credentials in `%s`", server.Name),
					Detail:     fmt.Sprintf("Server `%s` has debug/verbose logging enabled (`%s=true`) AND contains hardcoded API credentials. Many MCP server implementations log environment variables and HTTP headers when debug mode is on. This combination can cause API keys to appear in log files, stdout, or observability platforms in plaintext.", server.Name, envKey),
					Severity:   models.SeverityMedium,
					OWASP:      models.MCP01,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Disable debug logging in production (`%s=false`). Move secrets out of the MCP config entirely. If debug mode is needed for development, use a separate config file with placeholder credentials and never commit debug-mode configs.", envKey),
					Engine:   "custom",
					CWEID:    "CWE-532",
				})
				break
			}
		}
	}
}

func checkAutoApprove(config *parser.MCPConfig, out *[]models.Finding) {
	for _, server := range config.Servers {
		if server.Disabled || server.AutoApprove == nil {
			continue
		}

		if isWildcardAutoApprove(server.AutoApprove) {
			*out = append(*out, models.Finding{
				CheckID:    "CL-004",
				Title:      fmt.Sprintf("Wildcard autoApprove bypasses all tool confirmations in `%s`", server.Name),
				Detail:     fmt.Sprintf("Server `%s` has `autoApprove` set to approve every tool call without user confirmation. This removes the last line of defense against tool poisoning, prompt injection, and malicious MCP behavior — the AI can invoke any tool silently, including filesystem writes, shell commands, and network requests.", server.Name),
				Severity:   models.SeverityCritical,
				OWASP:      models.MCP07,
				ServerName: server.Name,
				Remediation: "Remove `autoApprove: \"*\"` (or `alwaysAllow: true`) from this server entry. Approve tools individually after reviewing what each one does. Never use wildcard auto-approve for servers with filesystem, shell, or network access.",
				Engine:       "custom",
				AttackTactic: "defense-evasion",
				CWEID:        "CWE-284",
			})
			continue
		}

		toolCount := len(server.AutoApprove.List)
		if server.AutoApprove.Str != nil {
			toolCount = 1
		}
		if toolCount > 0 {
			preview := ""
			if len(server.AutoApprove.List) > 0 {
				n := 5
				if len(server.AutoApprove.List) < n {
					n = len(server.AutoApprove.List)
				}
				shown := make([]string, n)
				for i := range shown {
					shown[i] = "`" + server.AutoApprove.List[i] + "`"
				}
				extra := ""
				if toolCount > 5 {
					extra = fmt.Sprintf(" (+%d more)", toolCount-5)
				}
				preview = " Tools: " + strings.Join(shown, ", ") + extra + "."
			}
			sev := models.SeverityMedium
			if toolCount >= 5 {
				sev = models.SeverityHigh
			}
			*out = append(*out, models.Finding{
				CheckID:    "CL-004",
				Title:      fmt.Sprintf("Partial autoApprove list (%d tool(s)) in `%s`", toolCount, server.Name),
				Detail:     fmt.Sprintf("Server `%s` auto-approves %d tool(s) without confirmation.%s Pre-approved tools run silently — if the server's tool list changes via a package update, new dangerous tools may inherit approval without your review.", server.Name, toolCount, preview),
				Severity:   sev,
				OWASP:      models.MCP07,
				ServerName: server.Name,
				Remediation: "Remove the `autoApprove` list and confirm each tool call manually until you trust this server. If you need convenience, auto-approve only read-only tools and re-audit after every package version change.",
				Engine:       "custom",
				AttackTactic: "defense-evasion",
				CWEID:        "CWE-284",
			})
		}
	}
}
