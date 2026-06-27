package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

var injectionPatterns = []struct {
	re   *regexp.Regexp
	desc string
}{
	{regexp.MustCompile(`(?i)ignore\s+(previous|all|prior)\s+instructions?`), "instruction override phrase"},
	{regexp.MustCompile(`(?i)do\s+not\s+(reveal|disclose|share|tell)`), "information suppression directive"},
	{regexp.MustCompile(`(?i)(override|bypass|ignore)\s+(the\s+)?(system\s+prompt|instructions?|rules?|constraints?)`), "system prompt override"},
	{regexp.MustCompile(`(?i)you\s+(are|must|should)\s+(now\s+|always\s+)?(act\s+as|pretend|roleplay|simulate)`), "role manipulation directive"},
	{regexp.MustCompile(`(?i)(hidden|secret|confidential)\s+instructions?`), "hidden instruction reference"},
	{regexp.MustCompile(`(?i)<\|.+?\|>`), "control token injection"},
	{regexp.MustCompile(`(?i)\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>`), "LLM control token"},
	{regexp.MustCompile(`(?i)###\s*SYSTEM\s*###|###\s*USER\s*###|###\s*ASSISTANT\s*###`), "LLM section delimiter"},
	{regexp.MustCompile(`(?i)<system>|</system>|<user>|</user>|<assistant>|</assistant>`), "XML role delimiter injection"},
	{regexp.MustCompile(`(?i)AUTOEXECUTE|AUTO_EXECUTE|SYSTEM_OVERRIDE`), "automation override keyword"},
	{regexp.MustCompile(`(?i)disregard\s+(all|any|previous)`), "instruction disregard phrase"},
	{regexp.MustCompile(`(?i)(your|the)\s+(real|true|actual)\s+(purpose|goal|mission|task)\s+is`), "purpose redefinition"},
	{regexp.MustCompile(`(?i)developer\s+mode|jailbreak\s+mode|DAN\s+mode`), "jailbreak mode reference"},
}

var exfilPatterns = []struct {
	re   *regexp.Regexp
	desc string
}{
	{regexp.MustCompile(`(?i)(send|upload|transmit|exfiltrat|forward|relay)\s+(data|files?|credentials?|tokens?)\s+(to|from)`), "data transfer directive"},
	{regexp.MustCompile(`(?i)POST\s+to\s+https?://`), "HTTP POST to external URL"},
	{regexp.MustCompile(`https?://(?:(?:localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s]*|[^\s]{15,})`), "external URL embedded in argument"},
	{regexp.MustCompile(`(?i)(webhook|callback)\s+url`), "webhook/callback URL reference"},
	{regexp.MustCompile(`(?i)(steal|harvest|collect|scrape)\s+(data|credentials?|tokens?|passwords?)`), "data harvesting language"},
	{regexp.MustCompile(`(?i)(bcc|blind.?carbon.?copy)`), "BCC/blind copy email exfiltration"},
	{regexp.MustCompile(`(?i)(forward.?to|cc.?to|reply.?to)\s*[=:]\s*[^\s@]+@[^\s]{3,}`), "email forwarding rule"},
}

// exfilEnvPatterns: subset of exfilPatterns safe for env var values (excludes generic URL pattern).
var exfilEnvPatterns = []struct {
	re   *regexp.Regexp
	desc string
}{
	{regexp.MustCompile(`(?i)(send|upload|transmit|exfiltrat|forward|relay)\s+(data|files?|credentials?|tokens?)\s+(to|from)`), "data transfer directive"},
	{regexp.MustCompile(`(?i)POST\s+to\s+https?://`), "HTTP POST to external URL"},
	{regexp.MustCompile(`(?i)(webhook|callback)\s+url`), "webhook/callback URL reference"},
	{regexp.MustCompile(`(?i)(steal|harvest|collect|scrape)\s+(data|credentials?|tokens?|passwords?)`), "data harvesting language"},
	{regexp.MustCompile(`(?i)(bcc|blind.?carbon.?copy)`), "BCC/blind copy email exfiltration"},
	{regexp.MustCompile(`(?i)(forward.?to|cc.?to|reply.?to)\s*[=:]\s*[^\s@]+@[^\s]{3,}`), "email forwarding rule"},
}

var unicodeEscRE = regexp.MustCompile(`(?:\\u[0-9a-fA-F]{4}){4,}`)
var hexEscRE = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){4,}`)

// invisibleUnicode: zero-width and invisible Unicode codepoints, keyed by rune value.
// Mirrors Python's _INVISIBLE_UNICODE + _BIDI_OVERRIDE_UNICODE.
// Codepoints are expressed as integer literals to avoid embedding invisible chars in source.
var invisibleUnicode = map[rune]string{
	0x200B: "Zero Width Space",
	0x200C: "Zero Width Non-Joiner",
	0x200D: "Zero Width Joiner",
	0xFEFF: "BOM/Zero Width No-Break Space",
	0x2060: "Word Joiner",
	0x2061: "Function Application (invisible)",
	0x2062: "Invisible Times",
	0x2063: "Invisible Separator",
	0x2064: "Invisible Plus",
	0x00AD: "Soft Hyphen",
	0x180E: "Mongolian Vowel Separator",
	0x034F: "Combining Grapheme Joiner",
}

var bidiOverrideUnicode = map[rune]string{
	0x202A: "LTR Embedding",
	0x202B: "RTL Embedding",
	0x202C: "Pop Directional Formatting",
	0x202D: "LTR Override",
	0x202E: "RTL Override (Trojan Source)",
	0x2066: "LTR Isolate",
	0x2067: "RTL Isolate",
	0x2068: "First Strong Isolate",
	0x2069: "Pop Directional Isolate",
}

const maxArgsLength = 2000
const horizontalScrollThreshold = 300

func findStealthChars(text string) (names []string, anyBidi bool) {
	seen := map[rune]bool{}
	for _, r := range text {
		if seen[r] {
			continue
		}
		if name, ok := invisibleUnicode[r]; ok {
			seen[r] = true
			names = append(names, name)
		} else if name, ok := bidiOverrideUnicode[r]; ok {
			seen[r] = true
			names = append(names, name)
			anyBidi = true
		}
	}
	return
}

// CheckToolPoisoning checks for prompt injection, exfiltration, and Unicode steganography (PI-001..005, DX-001).
func CheckToolPoisoning(server *parser.MCPServer) []models.Finding {
	findings := []models.Finding{}

	fullArgs := strings.Join(server.Args, " ")
	var envParts []string
	for k, v := range server.Env {
		envParts = append(envParts, k+"="+v)
	}
	fullEnvVals := strings.Join(envParts, " ")

	// PI-001: Prompt injection keywords in args or env var values
	pi001Done := false
	for _, src := range []struct{ text, label string }{{fullArgs, "args"}, {fullEnvVals, "env vars"}} {
		if pi001Done {
			break
		}
		for _, pat := range injectionPatterns {
			if m := pat.re.FindString(src.text); m != "" {
				findings = append(findings, models.Finding{
					CheckID:  "PI-001",
					Title:    fmt.Sprintf("Potential prompt injection in server %s (%s)", src.label, pat.desc),
					Detail:   fmt.Sprintf("Server `%s` contains %s text matching a known prompt injection pattern (%s): `%s`. This phrasing is used in tool poisoning attacks to silently hijack AI assistant behavior.", server.Name, src.label, pat.desc, m),
					Severity: models.SeverityHigh,
					OWASP:    models.MCP03,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Review this server's %s and source code carefully. If it was installed from an untrusted source, remove it. Legitimate MCP servers do not embed instruction-override language in their configuration.", src.label),
					Engine:   "custom",
					CWEID:    "CWE-77",
				})
				pi001Done = true
				break
			}
		}
	}

	// PI-002: Excessively long combined args
	if len(fullArgs) > maxArgsLength {
		findings = append(findings, models.Finding{
			CheckID:  "PI-002",
			Title:    fmt.Sprintf("Excessively long server arguments (%d chars)", len(fullArgs)),
			Detail:   fmt.Sprintf("Server `%s` has unusually long combined arguments (%d characters). Arguments exceeding %d characters may be hiding injected instructions or obfuscated payloads within what appears to be normal configuration.", server.Name, len(fullArgs), maxArgsLength),
			Severity: models.SeverityMedium,
			OWASP:    models.MCP06,
			ServerName: server.Name,
			Remediation: "Review all arguments to this server carefully. Legitimate MCP servers rarely require more than a few hundred characters of configuration arguments. Look for any base64-encoded strings or unusually dense text blocks.",
			Engine:   "custom",
			CWEID:    "CWE-400",
		})
	}

	// PI-003: Horizontal scroll hidden injection
	for i, arg := range server.Args {
		if len(arg) > horizontalScrollThreshold && !strings.ContainsAny(arg, "\n\r") {
			hasInj := false
			for _, pat := range injectionPatterns {
				if pat.re.MatchString(arg) {
					hasInj = true
					break
				}
			}
			sev := models.SeverityMedium
			if hasInj {
				sev = models.SeverityHigh
			}
			findings = append(findings, models.Finding{
				CheckID:  "PI-003",
				Title:    fmt.Sprintf("Horizontal-scroll injection risk: arg #%d is %d chars (single line)", i+1, len(arg)),
				Detail:   fmt.Sprintf("Server `%s` has argument #%d with %d characters on a single line. In Claude Desktop and Cursor approval dialogs, content beyond the visible viewport is hidden via horizontal scroll. An attacker can hide an injected instruction off-screen while the visible portion looks harmless. (Research source: MDPI May 2026 — MCP Threat Modeling)", server.Name, i+1, len(arg)),
				Severity: sev,
				OWASP:    models.MCP03,
				ServerName: server.Name,
				Remediation: "Investigate why this argument is so long. Legitimate MCP server arguments are typically short paths, flags, or package names (< 200 chars). If you need to pass long configuration, use a config file instead of an inline argument.",
				Engine:   "custom",
				CWEID:    "CWE-693",
			})
			break
		}
	}

	// PI-004: Obfuscation via escape sequences in args
	for i, arg := range server.Args {
		uniMatch := unicodeEscRE.FindString(arg)
		hexMatch := hexEscRE.FindString(arg)
		if uniMatch != "" || hexMatch != "" {
			encType := "unicode escape sequences (\\uXXXX)"
			match := uniMatch
			if uniMatch == "" {
				encType = "hex escape sequences (\\xXX)"
				match = hexMatch
			}
			findings = append(findings, models.Finding{
				CheckID:  "PI-004",
				Title:    fmt.Sprintf("Obfuscated payload in server args via %s", strings.SplitN(encType, "(", 2)[0]),
				Detail:   fmt.Sprintf("Server `%s` has argument #%d containing %s: `%s`. Escape sequences are used in tool poisoning attacks to embed injection payloads that look like gibberish in UI displays but decode to instruction-override text when interpreted by the language model. This is a strong indicator of adversarial content.", server.Name, i+1, encType, match),
				Severity: models.SeverityHigh,
				OWASP:    models.MCP03,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Remove argument #%d from server `%s` and investigate its source. Legitimate MCP server arguments never require escape-sequence-encoded payloads. If the server was installed from a third-party source, remove it immediately.", i+1, server.Name),
				Engine:       "custom",
				AttackTactic: "defense-evasion",
				CWEID:        "CWE-116",
			})
			break
		}
	}

	// DX-001: Data exfiltration patterns in args or env var values
	dx001Done := false
	for _, src := range []struct {
		text     string
		label    string
		patterns []struct {
			re   *regexp.Regexp
			desc string
		}
	}{
		{fullArgs, "args", exfilPatterns},
		{fullEnvVals, "env vars", exfilEnvPatterns},
	} {
		if dx001Done {
			break
		}
		for _, pat := range src.patterns {
			if m := pat.re.FindString(src.text); m != "" {
				findings = append(findings, models.Finding{
					CheckID:  "DX-001",
					Title:    fmt.Sprintf("Potential data exfiltration pattern in server %s: %s", src.label, pat.desc),
					Detail:   fmt.Sprintf("Server `%s` %s contain language suggesting data exfiltration: `%s` (%s). In the Postmark MCP incident (Sep 2025), a malicious env var (DEFAULT_BCC) silently BCC'd all emails to an attacker for 2 weeks. Legitimate MCP servers do not need data-transfer directives in configuration.", server.Name, src.label, m, pat.desc),
					Severity: models.SeverityHigh,
					OWASP:    models.MCP03,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Review this server's %s and source code carefully. If the server makes undisclosed outbound connections or email forwarding, remove it. Legitimate MCP servers document all network calls and data flows explicitly.", src.label),
					Engine:   "custom",
					CWEID:    "CWE-200",
				})
				dx001Done = true
				break
			}
		}
	}

	// PI-005: Invisible / zero-width / bidi-override Unicode steganography
	pi005Sources := []struct{ text, label string }{
		{fullArgs, "args"},
		{fullEnvVals, "env vars"},
		{server.Name, "server name"},
	}
	for _, src := range pi005Sources {
		names, anyBidi := findStealthChars(src.text)
		if len(names) == 0 {
			continue
		}
		sev := models.SeverityMedium
		if anyBidi {
			sev = models.SeverityHigh
		}
		summary := strings.Join(names, ", ")
		if len(names) > 3 {
			summary = strings.Join(names[:3], ", ") + fmt.Sprintf(" (+%d more)", len(names)-3)
		}
		bidiNote := ""
		if anyBidi {
			bidiNote = " Bidi override characters (Trojan Source technique, CVE-2021-42574) can make injected text display as harmless-looking content while the LLM processes the actual malicious instruction."
		}
		findings = append(findings, models.Finding{
			CheckID:  "PI-005",
			Title:    fmt.Sprintf("Invisible Unicode in server %s: %s", src.label, summary),
			Detail:   fmt.Sprintf("Server `%s` %s contain invisible Unicode character(s): %s. These characters render as nothing in Claude Desktop / Cursor approval dialogs but are passed to the language model in full, enabling completely invisible injection attacks. An attacker can split keywords like 'ignore' into separated characters — bypassing PI-001 regex checks while the LLM reads the word normally.%s", server.Name, src.label, summary, bidiNote),
			Severity: sev,
			OWASP:    models.MCP03,
			ServerName: server.Name,
			Remediation: fmt.Sprintf("Open this server's %s in a hex editor or Unicode-aware text editor to locate and remove the invisible characters. These have no legitimate use in MCP server configuration. If this config was received from an external source or copy-pasted from a chat/web page, treat it as potentially tampered.", src.label),
			Engine:       "custom",
			AttackTactic: "defense-evasion",
			CWEID:        "CWE-116",
		})
		break // one PI-005 per server
	}

	return findings
}
