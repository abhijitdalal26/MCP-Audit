package checks

import (
	"fmt"
	"strings"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// classifyCapabilities returns the capability buckets for a server.
// Mirrors Python's _classify_capabilities() — uses existing findings to avoid re-running checks.
func classifyCapabilities(server *parser.MCPServer, findings []models.Finding) map[string]bool {
	caps := map[string]bool{}
	checkIDs := map[string]bool{}
	for _, f := range findings {
		checkIDs[f.CheckID] = true
	}
	argsLower := joinArgsLower(server)
	cmdBase := cmdBasename(server)

	// filesystem_writer
	if checkIDs["PE-001"] || strings.Contains(argsLower, "server-filesystem") {
		caps["filesystem_writer"] = true
	}
	if strings.Contains(argsLower, "server-file") && !strings.Contains(argsLower, "server-filesystem") {
		caps["filesystem_writer"] = true
	}

	// shell_executor
	if checkIDs["PE-002"] || checkIDs["EX-001"] || checkIDs["EX-002"] || checkIDs["EX-003"] {
		caps["shell_executor"] = true
	}
	switch cmdBase {
	case "bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh", "docker":
		caps["shell_executor"] = true
	}
	for _, pkg := range []string{"server-shell", "server-terminal", "mcp-server-terminal", "server-exec", "mcp-exec"} {
		if strings.Contains(argsLower, pkg) {
			caps["shell_executor"] = true
			break
		}
	}

	// secret_holder — any live-credential SEC finding
	for _, id := range []string{"SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "SEC-007"} {
		if checkIDs[id] {
			caps["secret_holder"] = true
			break
		}
	}

	// http_outbound — external URL or known fetch packages
	localHosts := []string{"localhost", "127.0.0.1", "0.0.0.0", "::1"}
	if server.URL != "" {
		isLocal := false
		for _, h := range localHosts {
			if strings.Contains(server.URL, h) {
				isLocal = true
				break
			}
		}
		if !isLocal {
			caps["http_outbound"] = true
		}
	}
	for _, pkg := range []string{"server-fetch", "mcp-fetch", "server-http", "http-client"} {
		if strings.Contains(argsLower, pkg) {
			caps["http_outbound"] = true
			break
		}
	}

	return caps
}

// CheckCrossServerChains detects dangerous capability chains across multiple servers (CHAIN-001..003).
func CheckCrossServerChains(config *parser.MCPConfig, perServer map[string][]models.Finding) []models.Finding {
	if len(config.Servers) < 2 {
		return nil
	}

	findings := []models.Finding{}

	capMap := map[string]map[string]bool{}
	for _, server := range config.Servers {
		if server.Disabled {
			continue
		}
		capMap[server.Name] = classifyCapabilities(&server, perServer[server.Name])
	}

	var writers, executors, secretServers, httpServers []string
	for name, caps := range capMap {
		if caps["filesystem_writer"] {
			writers = append(writers, name)
		}
		if caps["shell_executor"] {
			executors = append(executors, name)
		}
		if caps["secret_holder"] {
			secretServers = append(secretServers, name)
		}
		if caps["http_outbound"] {
			httpServers = append(httpServers, name)
		}
	}

	// CHAIN-001: Write + Execute gadget pair (different servers)
	var chain1Pairs [][2]string
	for _, w := range writers {
		for _, e := range executors {
			if w != e {
				chain1Pairs = append(chain1Pairs, [2]string{w, e})
			}
		}
	}
	if len(chain1Pairs) > 0 {
		writerName, execName := chain1Pairs[0][0], chain1Pairs[0][1]
		extra := ""
		if len(chain1Pairs) > 1 {
			extra = fmt.Sprintf(" (%d additional pair(s) also present)", len(chain1Pairs)-1)
		}
		findings = append(findings, models.Finding{
			CheckID:    "CHAIN-001",
			Title:      fmt.Sprintf("Write+Execute gadget pair: `%s` (filesystem) + `%s` (executor)", writerName, execName),
			Detail:     fmt.Sprintf("Two servers in this config compose into a remote code execution chain: `%s` has filesystem write capability and `%s` has shell/code execution capability.%s Via prompt injection, an attacker can instruct the LLM to: (1) write a malicious script to a shared writable path via `%s`, then (2) execute it via `%s`. Neither server is critical-severity in isolation — their composition creates arbitrary code execution. This is a documented multi-server attack pattern.", writerName, execName, extra, writerName, execName),
			Severity:   models.SeverityHigh,
			OWASP:      models.MCP02,
			ServerName: fmt.Sprintf("%s + %s", writerName, execName),
			Remediation: fmt.Sprintf("Remove either the filesystem writer or the shell executor if both are not strictly necessary in the same session. If both are needed: restrict the filesystem server's writable paths to directories `%s` cannot access, and review whether shell execution can be replaced with a more constrained tool.", execName),
			Engine:       "custom",
			AttackTactic: "execution",
			CWEID:        "CWE-250",
		})
	}

	// CHAIN-002: Secrets + HTTP exfiltration chain (different servers)
	var chain2Pairs [][2]string
	for _, s := range secretServers {
		for _, h := range httpServers {
			if s != h {
				chain2Pairs = append(chain2Pairs, [2]string{s, h})
			}
		}
	}
	if len(chain2Pairs) > 0 {
		secretName, httpName := chain2Pairs[0][0], chain2Pairs[0][1]
		extra2 := ""
		if len(chain2Pairs) > 1 {
			extra2 = fmt.Sprintf(" (%d additional pair(s) also present)", len(chain2Pairs)-1)
		}
		findings = append(findings, models.Finding{
			CheckID:    "CHAIN-002",
			Title:      fmt.Sprintf("Credential exfiltration chain: `%s` (secrets) + `%s` (HTTP outbound)", secretName, httpName),
			Detail:     fmt.Sprintf("Two servers in this config compose into a credential exfiltration chain: `%s` holds embedded credentials and `%s` can make external HTTP requests.%s Via prompt injection in any tool response, an attacker can instruct the LLM to: (1) read or use credentials accessible to `%s`, then (2) transmit them to an attacker-controlled URL via `%s`. This path requires no code execution — just two sequential tool calls. The Postmark MCP incident (Sep 2025) demonstrated this exact pattern: a credentials server + an email server composed into mass exfiltration.", secretName, httpName, extra2, secretName, httpName),
			Severity:   models.SeverityHigh,
			OWASP:      models.MCP01,
			ServerName: fmt.Sprintf("%s + %s", secretName, httpName),
			Remediation: fmt.Sprintf("Rotate any credentials embedded in `%s` immediately if this config was exposed to untrusted content (web browsing, email, user-controlled files). Going forward: move secrets to a proper secrets manager instead of MCP env blocks. If `%s` is needed, restrict it to an allowlist of approved domains so it cannot POST to arbitrary external URLs.", secretName, httpName),
			Engine:       "custom",
			AttackTactic: "exfiltration",
			CWEID:        "CWE-200",
		})
	}

	// CHAIN-003: Amplified filesystem blast radius (3+ filesystem writers)
	const chain3Threshold = 3
	if len(writers) >= chain3Threshold {
		writerList := make([]string, 0, 5)
		for i, w := range writers {
			if i >= 5 {
				break
			}
			writerList = append(writerList, "`"+w+"`")
		}
		wListStr := strings.Join(writerList, ", ")
		if len(writers) > 5 {
			wListStr += fmt.Sprintf(" (+%d more)", len(writers)-5)
		}
		findings = append(findings, models.Finding{
			CheckID:    "CHAIN-003",
			Title:      fmt.Sprintf("Amplified filesystem blast radius: %d filesystem servers in config", len(writers)),
			Detail:     fmt.Sprintf("This config has %d servers with filesystem write access: %s. When accessed by the same LLM session, their writable paths compose into a single effective attack surface equal to the union of all accessible directories. A ransomware-style or data-wipe prompt injection can chain file operations across all servers in a single conversation turn. Per-server analysis (PE-001) evaluates each server's paths independently — it does not account for the compounded blast radius from multiple servers.", len(writers), wListStr),
			Severity:   models.SeverityMedium,
			OWASP:      models.MCP02,
			ServerName: "(" + strings.Join(writers, ", ") + ")",
			Remediation: fmt.Sprintf("Audit whether all %d filesystem servers are required simultaneously. Reduce to the minimum. For each remaining server, narrow its accessible path to the smallest directory needed (a specific project folder, not /home or /). Consider running separate Claude Desktop profiles for tasks that need different filesystem scopes to prevent cross-task capability composition.", len(writers)),
			Engine:       "custom",
			AttackTactic: "impact",
			CWEID:        "CWE-732",
		})
	}

	return findings
}
