import re
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'ignore\s+(previous|all|prior)\s+instructions?', re.I), "instruction override phrase"),
    (re.compile(r'do\s+not\s+(reveal|disclose|share|tell)', re.I), "information suppression directive"),
    (re.compile(r'(override|bypass|ignore)\s+(the\s+)?(system\s+prompt|instructions?|rules?|constraints?)', re.I),
     "system prompt override"),
    (re.compile(r'you\s+(are|must|should)\s+(now\s+|always\s+)?(act\s+as|pretend|roleplay|simulate)', re.I),
     "role manipulation directive"),
    (re.compile(r'(hidden|secret|confidential)\s+instructions?', re.I), "hidden instruction reference"),
    (re.compile(r'<\|.+?\|>', re.I), "control token injection"),
    (re.compile(r'\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>', re.I), "LLM control token"),
    (re.compile(r'AUTOEXECUTE|AUTO_EXECUTE|SYSTEM_OVERRIDE', re.I), "automation override keyword"),
    (re.compile(r'disregard\s+(all|any|previous)', re.I), "instruction disregard phrase"),
    (re.compile(r'(your|the)\s+(real|true|actual)\s+(purpose|goal|mission|task)\s+is', re.I), "purpose redefinition"),
    (re.compile(r'developer\s+mode|jailbreak\s+mode|DAN\s+mode', re.I), "jailbreak mode reference"),
]

# Data exfiltration indicators in args/descriptions (AS-017 equivalent)
_EXFILTRATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)(send|upload|transmit|exfiltrat|forward|relay)\s+(data|files?|credentials?|tokens?)\s+(to|from)'), "data transfer directive"),
    (re.compile(r'(?i)POST\s+to\s+https?://'), "HTTP POST to external URL"),
    (re.compile(r'https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s]{15,}'), "external URL embedded in argument"),
    (re.compile(r'(?i)(webhook|callback)\s+url'), "webhook/callback URL reference"),
    (re.compile(r'(?i)(steal|harvest|collect|scrape)\s+(data|credentials?|tokens?|passwords?)'), "data harvesting language"),
]

_MAX_ARGS_LENGTH = 2000
_HORIZONTAL_SCROLL_THRESHOLD = 300  # chars on a single line before flagging PI-003

# PI-004: Obfuscation via escape sequences
# 4+ consecutive unicode escapes = "bash" or "ignore" hiding in plain sight
_UNICODE_ESC_RE = re.compile(r'(?:\\u[0-9a-fA-F]{4}){4,}')
# 4+ consecutive hex escapes = same technique in hex form
_HEX_ESC_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}')


def check_tool_poisoning(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []
    full_args = " ".join(server.args)

    # PI-001: Prompt injection keywords in server args
    for pattern, description in _INJECTION_PATTERNS:
        match = pattern.search(full_args)
        if match:
            findings.append(Finding(
                check_id="PI-001",
                title=f"Potential prompt injection in server args ({description})",
                detail=(
                    f"Server `{server.name}` contains argument text matching a known prompt injection pattern "
                    f"({description}): `{match.group(0)!r}`. "
                    "This phrasing is used in tool poisoning attacks to silently hijack AI assistant behavior."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP03,
                server_name=server.name,
                remediation=(
                    "Review this server's arguments and source code carefully. "
                    "If it was installed from an untrusted source, remove it. "
                    "Legitimate MCP servers do not embed instruction-override language in their configuration."
                ),
                engine="custom",
            ))
            break  # One PI-001 per server

    # PI-002: Excessively long combined args
    if len(full_args) > _MAX_ARGS_LENGTH:
        findings.append(Finding(
            check_id="PI-002",
            title=f"Excessively long server arguments ({len(full_args):,} chars)",
            detail=(
                f"Server `{server.name}` has unusually long combined arguments ({len(full_args):,} characters). "
                f"Arguments exceeding {_MAX_ARGS_LENGTH:,} characters may be hiding injected "
                "instructions or obfuscated payloads within what appears to be normal configuration."
            ),
            severity=Severity.MEDIUM,
            owasp=OWASPCategory.MCP06,
            server_name=server.name,
            remediation=(
                "Review all arguments to this server carefully. "
                "Legitimate MCP servers rarely require more than a few hundred characters of configuration arguments. "
                "Look for any base64-encoded strings or unusually dense text blocks."
            ),
            engine="custom",
        ))

    # PI-003: Horizontal scroll hidden injection (MDPI May 2026)
    # Detects the delivery mechanism (single long line), not the payload content
    for i, arg in enumerate(server.args):
        if len(arg) > _HORIZONTAL_SCROLL_THRESHOLD and '\n' not in arg and '\r' not in arg:
            has_injection = any(p.search(arg) for p, _ in _INJECTION_PATTERNS)
            severity = Severity.HIGH if has_injection else Severity.MEDIUM
            findings.append(Finding(
                check_id="PI-003",
                title=f"Horizontal-scroll injection risk: arg #{i+1} is {len(arg):,} chars (single line)",
                detail=(
                    f"Server `{server.name}` has argument #{i+1} with {len(arg):,} characters on a single line. "
                    "In Claude Desktop and Cursor approval dialogs, content beyond the visible viewport "
                    "is hidden via horizontal scroll. An attacker can hide an injected instruction "
                    "off-screen while the visible portion looks harmless. "
                    "(Research source: MDPI May 2026 — MCP Threat Modeling)"
                ),
                severity=severity,
                owasp=OWASPCategory.MCP03,
                server_name=server.name,
                remediation=(
                    "Investigate why this argument is so long. Legitimate MCP server arguments "
                    "are typically short paths, flags, or package names (< 200 chars). "
                    "If you need to pass long configuration, use a config file instead of an inline argument."
                ),
                engine="custom",
            ))
            break  # One PI-003 per server

    # PI-004: Obfuscation via escape sequences in args
    # Detects unicode/hex escape sequences used to hide injection payloads beyond what tools display.
    # Real-world attack: "\\u0049\\u0067\\u006e\\u006f\\u0072\\u0065" decodes to "Ignore"
    for i, arg in enumerate(server.args):
        uni_match = _UNICODE_ESC_RE.search(arg)
        hex_match = _HEX_ESC_RE.search(arg)
        obf_match = uni_match or hex_match
        if obf_match:
            enc_type = "unicode escape sequences (\\uXXXX)" if uni_match else "hex escape sequences (\\xXX)"
            findings.append(Finding(
                check_id="PI-004",
                title=f"Obfuscated payload in server args via {enc_type.split('(')[0].strip()}",
                detail=(
                    f"Server `{server.name}` has argument #{i+1} containing {enc_type}: "
                    f"`{obf_match.group(0)!r}`. "
                    "Escape sequences are used in tool poisoning attacks to embed injection payloads "
                    "that look like gibberish in UI displays but decode to instruction-override text "
                    "when interpreted by the language model. This is a strong indicator of adversarial content."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP03,
                server_name=server.name,
                remediation=(
                    f"Remove argument #{i+1} from server `{server.name}` and investigate its source. "
                    "Legitimate MCP server arguments never require escape-sequence-encoded payloads. "
                    "If the server was installed from a third-party source, remove it immediately."
                ),
                engine="custom",
                attack_tactic="defense-evasion",
                cwe_id="CWE-116",
            ))
            break  # One PI-004 per server

    # DX-001: Data exfiltration patterns (AS-017 equivalent)
    for pattern, description in _EXFILTRATION_PATTERNS:
        match = pattern.search(full_args)
        if match:
            findings.append(Finding(
                check_id="DX-001",
                title=f"Potential data exfiltration pattern in server args: {description}",
                detail=(
                    f"Server `{server.name}` arguments contain language suggesting data exfiltration: "
                    f"`{match.group(0)!r}` ({description}). "
                    "Legitimate MCP servers do not need to instruct users to transmit data to external endpoints "
                    "via their configuration arguments."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP03,
                server_name=server.name,
                remediation=(
                    "Review this server's source code and documentation carefully. "
                    "If the server makes undisclosed outbound connections, remove it. "
                    "Legitimate MCP servers document all network calls explicitly."
                ),
                engine="custom",
            ))
            break  # One DX-001 per server

    return findings
