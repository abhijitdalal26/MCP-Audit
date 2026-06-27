package checks

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf16"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

var inlineExecPatterns = []struct {
	re   *regexp.Regexp
	desc string
}{
	{regexp.MustCompile(`python[23]?\s+-[cC]\s+["']`), "Python -c inline execution"},
	{regexp.MustCompile(`node\s+-e\s+["']`), "Node.js -e inline execution"},
	{regexp.MustCompile(`(?:bash|sh|zsh|fish)\s+-[cC]\s+["']`), "Shell -c inline execution"},
	{regexp.MustCompile(`\beval\s*\(`), "eval() function call"},
	{regexp.MustCompile(`\bexec\s*\(`), "exec() function call"},
	{regexp.MustCompile(`__import__\s*\(`), "Python __import__() bypass"},
	{regexp.MustCompile(`os\.system\s*\(`), "os.system() shell call"},
	{regexp.MustCompile(`subprocess\s*\.\s*(?:call|run|Popen|check_output)\s*\(`), "subprocess execution call"},
	{regexp.MustCompile(`require\s*\(\s*["']child_process`), "Node.js child_process require"},
	{regexp.MustCompile(`Runtime\.getRuntime\(\)\.exec\s*\(`), "Java Runtime.exec() call"},
	{regexp.MustCompile(`Process\s*\(\s*["']`), "Python Process() execution"},
}

var cmdSubstitutionPatterns = []struct {
	re   *regexp.Regexp
	desc string
}{
	{regexp.MustCompile(`\$\([^)]+\)`), "Shell command substitution $()"},
	{regexp.MustCompile("`[^`]{2,}`"), "Backtick command substitution"},
	{regexp.MustCompile(`\{\{[^}]{3,}\}\}`), "Template injection pattern {{}}"},
	{regexp.MustCompile(`<\([^)]+\)`), "Process substitution <()"},
	{regexp.MustCompile(`;\s*(?:rm|curl|wget|nc|bash|sh|python|node)\s`), "Chained shell command injection"},
	{regexp.MustCompile(`\|\s*(?:bash|sh|python|node|perl|ruby)\b`), "Pipe to shell interpreter"},
}

// psFlagRE matches PowerShell encoded command flags (case-insensitive).
// Note: Go RE2 doesn't have case-insensitive boundary \b but we use (?i) prefix.
var psFlagRE = regexp.MustCompile(`(?i)^-(?:EncodedCommand|ec|e|en|enc|enco|encod)$`)
var base64PayloadRE = regexp.MustCompile(`^[A-Za-z0-9+/]{20,}={0,2}$`)
var curlPipeShellRE = regexp.MustCompile(`(?i)(?:curl|wget)\s+.*?\|\s*(?:bash|sh|python|python3|node|perl|ruby)\b`)
var pyB64ExecRE = regexp.MustCompile(`(?i)(?:exec|eval)\s*\(\s*(?:base64\.b64decode|codecs\.decode)\s*\(\s*["']([A-Za-z0-9+/]{20,}={0,2})["']`)

// CheckCodeExecution detects inline code execution patterns in MCP server args (EX-001..003).
func CheckCodeExecution(server *parser.MCPServer) []models.Finding {
	findings := []models.Finding{}
	seen := map[string]bool{}

	for i, arg := range server.Args {
		dedupPrefix := fmt.Sprintf("%s:%d", server.Name, i)

		// EX-001: Inline code execution
		for _, pat := range inlineExecPatterns {
			if pat.re.MatchString(arg) {
				key := "EX-001:" + dedupPrefix
				if !seen[key] {
					seen[key] = true
					snip := arg
					if len(snip) > 120 {
						snip = snip[:120] + "..."
					}
					findings = append(findings, models.Finding{
						CheckID:  "EX-001",
						Title:    fmt.Sprintf("Inline code execution in server arg #%d: %s", i+1, pat.desc),
						Detail:   fmt.Sprintf("Server `%s` passes argument #%d containing what appears to be inline code execution (%s): `%s`. Injecting executable code as MCP configuration arguments is a hallmark of supply chain and prompt injection attacks. Legitimate MCP servers do not require inline code in their arguments.", server.Name, i+1, pat.desc, snip),
						Severity: models.SeverityCritical,
						OWASP:    models.MCP05,
						ServerName: server.Name,
						Remediation: "Remove any inline code from server arguments immediately. MCP server arguments should only contain configuration values (paths, flags, package names), never executable code. If this server was installed from an untrusted source, remove it entirely.",
						Engine:   "custom",
					})
				}
				break
			}
		}

		// EX-002: Command substitution injection
		for _, pat := range cmdSubstitutionPatterns {
			if pat.re.MatchString(arg) {
				key := "EX-002:" + dedupPrefix
				if !seen[key] {
					seen[key] = true
					snip := arg
					if len(snip) > 120 {
						snip = snip[:120] + "..."
					}
					findings = append(findings, models.Finding{
						CheckID:  "EX-002",
						Title:    fmt.Sprintf("Command substitution injection in server arg #%d: %s", i+1, pat.desc),
						Detail:   fmt.Sprintf("Server `%s` argument #%d contains a command substitution pattern (%s): `%s`. Shell command substitution in MCP config arguments can execute arbitrary commands when the config is processed by the MCP runtime.", server.Name, i+1, pat.desc, snip),
						Severity: models.SeverityHigh,
						OWASP:    models.MCP05,
						ServerName: server.Name,
						Remediation: "Remove all command substitution syntax from server arguments. MCP configs should not contain shell-expansion syntax (`$()`, backticks, etc.). Use environment variables for dynamic values instead.",
						Engine:   "custom",
					})
				}
				break
			}
		}
	}

	// EX-003a: PowerShell encoded command
	var psFlagIdx = -1
	for i, arg := range server.Args {
		if psFlagRE.MatchString(strings.TrimSpace(arg)) {
			psFlagIdx = i
		} else if psFlagIdx != -1 && base64PayloadRE.MatchString(strings.TrimSpace(arg)) {
			decoded := decodePSBase64(arg)
			key := fmt.Sprintf("EX-003:ps:%s", server.Name)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, models.Finding{
					CheckID:  "EX-003",
					Title:    "PowerShell encoded command detected (obfuscated payload)",
					Detail:   fmt.Sprintf("Server `%s` uses a PowerShell `-EncodedCommand` (or equivalent) flag in argument #%d, followed by a Base64 payload in argument #%d. Decoded preview: `%s`. Base64-encoded PowerShell is the most common technique for hiding malicious commands from static detection. No legitimate MCP server requires this pattern.", server.Name, psFlagIdx+1, i+1, decoded),
					Severity: models.SeverityCritical,
					OWASP:    models.MCP05,
					ServerName: server.Name,
					Remediation: "Immediately remove this server from your config. Decode the Base64 payload to understand what it executes, then investigate how the server was installed. Report to the package maintainer if it was installed from a registry.",
					Engine:       "custom",
					AttackTactic: "defense-evasion",
					CWEID:        "CWE-116",
				})
			}
			break
		} else {
			psFlagIdx = -1
		}
	}

	// EX-003b: curl/wget pipe to shell
	fullArgs := strings.Join(server.Args, " ")
	if m := curlPipeShellRE.FindString(fullArgs); m != "" {
		key := fmt.Sprintf("EX-003:curl:%s", server.Name)
		if !seen[key] {
			seen[key] = true
			findings = append(findings, models.Finding{
				CheckID:  "EX-003",
				Title:    "Remote script download-and-execute (curl/wget pipe to shell)",
				Detail:   fmt.Sprintf("Server `%s` appears to download and immediately execute a remote script: `%s`. curl/wget piped to bash/sh/python fetches arbitrary code from a remote URL and executes it in one step, with no verification or review. This is one of the most common supply chain attack techniques.", server.Name, m),
				Severity: models.SeverityCritical,
				OWASP:    models.MCP05,
				ServerName: server.Name,
				Remediation: "Download the script first, inspect its contents, then execute it manually. Never pipe a remote URL directly into a shell interpreter. Verify the script's integrity with a checksum before running.",
				Engine:       "custom",
				AttackTactic: "execution",
				CWEID:        "CWE-494",
			})
		}
	}

	// EX-003c: Python base64 decode-and-execute
	for _, arg := range server.Args {
		if m := pyB64ExecRE.FindStringSubmatch(arg); len(m) > 1 {
			decoded := decodeB64UTF8(m[1])
			key := fmt.Sprintf("EX-003:pyb64:%s", server.Name)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, models.Finding{
					CheckID:  "EX-003",
					Title:    "Python base64 decode-and-execute detected (obfuscated payload)",
					Detail:   fmt.Sprintf("Server `%s` contains a `exec(base64.b64decode(...))` pattern — the Python equivalent of PowerShell -EncodedCommand. Decoded payload preview: `%s`. This is a classic payload obfuscation technique used to hide malicious Python code from static scanners. No legitimate MCP server config requires runtime base64 decoding of executable code.", server.Name, decoded),
					Severity: models.SeverityCritical,
					OWASP:    models.MCP05,
					ServerName: server.Name,
					Remediation: "Remove this server immediately. Decode the base64 payload manually (python3 -c \"import base64; print(base64.b64decode('<payload>').decode())\") to understand what it executes, then report to the package maintainer.",
					Engine:       "custom",
					AttackTactic: "defense-evasion",
					CWEID:        "CWE-116",
				})
			}
			break
		}
	}

	return findings
}

// decodePSBase64 decodes a PowerShell Base64 payload (UTF-16LE) and returns a preview.
func decodePSBase64(payload string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		if len(payload) > 80 {
			return payload[:80]
		}
		return payload
	}
	// PowerShell -EncodedCommand uses UTF-16LE
	if len(raw)%2 != 0 {
		raw = append(raw, 0)
	}
	u16 := make([]uint16, len(raw)/2)
	for i := range u16 {
		u16[i] = uint16(raw[i*2]) | uint16(raw[i*2+1])<<8
	}
	runes := utf16.Decode(u16)
	result := string(runes)
	if len(result) > 80 {
		return result[:80]
	}
	return result
}

// decodeB64UTF8 decodes a standard Base64 payload as UTF-8 and returns a preview.
func decodeB64UTF8(payload string) string {
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		if len(payload) > 80 {
			return payload[:80]
		}
		return payload
	}
	result := string(raw)
	if len(result) > 80 {
		return result[:80]
	}
	return result
}
