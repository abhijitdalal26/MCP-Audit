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
    # LLM control tokens: Llama [INST], Claude <<SYS>>, GPT-4 ###
    (re.compile(r'\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>', re.I), "LLM control token"),
    (re.compile(r'###\s*SYSTEM\s*###|###\s*USER\s*###|###\s*ASSISTANT\s*###', re.I), "LLM section delimiter"),
    # XML-style system prompt tags used in Claude 3.5+ multi-turn injection
    (re.compile(r'<system>|</system>|<user>|</user>|<assistant>|</assistant>', re.I), "XML role delimiter injection"),
    (re.compile(r'AUTOEXECUTE|AUTO_EXECUTE|SYSTEM_OVERRIDE', re.I), "automation override keyword"),
    (re.compile(r'disregard\s+(all|any|previous)', re.I), "instruction disregard phrase"),
    (re.compile(r'(your|the)\s+(real|true|actual)\s+(purpose|goal|mission|task)\s+is', re.I), "purpose redefinition"),
    (re.compile(r'developer\s+mode|jailbreak\s+mode|DAN\s+mode', re.I), "jailbreak mode reference"),
]

# Data exfiltration indicators in args (all patterns — AS-017 equivalent)
_EXFILTRATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)(send|upload|transmit|exfiltrat|forward|relay)\s+(data|files?|credentials?|tokens?)\s+(to|from)'), "data transfer directive"),
    (re.compile(r'(?i)POST\s+to\s+https?://'), "HTTP POST to external URL"),
    (re.compile(r'https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s]{15,}'), "external URL embedded in argument"),
    (re.compile(r'(?i)(webhook|callback)\s+url'), "webhook/callback URL reference"),
    (re.compile(r'(?i)(steal|harvest|collect|scrape)\s+(data|credentials?|tokens?|passwords?)'), "data harvesting language"),
    (re.compile(r'(?i)(bcc|blind.?carbon.?copy)'), "BCC/blind copy email exfiltration"),
    (re.compile(r'(?i)(forward.?to|cc.?to|reply.?to)\s*[=:]\s*[^\s@]+@[^\s]{3,}'), "email forwarding rule"),
]

# Subset safe to apply to env var VALUES — excludes generic URL pattern (too many false positives
# from legitimate API endpoint env vars like BACKEND_URL=https://api.example.com).
_EXFILTRATION_ENV_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'(?i)(send|upload|transmit|exfiltrat|forward|relay)\s+(data|files?|credentials?|tokens?)\s+(to|from)'), "data transfer directive"),
    (re.compile(r'(?i)POST\s+to\s+https?://'), "HTTP POST to external URL"),
    (re.compile(r'(?i)(webhook|callback)\s+url'), "webhook/callback URL reference"),
    (re.compile(r'(?i)(steal|harvest|collect|scrape)\s+(data|credentials?|tokens?|passwords?)'), "data harvesting language"),
    # Postmark Sep 2025: DEFAULT_BCC env var silently exfiltrated all emails to attacker for 2 weeks
    (re.compile(r'(?i)(bcc|blind.?carbon.?copy)'), "BCC/blind copy email exfiltration"),
    (re.compile(r'(?i)(forward.?to|cc.?to|reply.?to)\s*[=:]\s*[^\s@]+@[^\s]{3,}'), "email forwarding rule"),
]

_MAX_ARGS_LENGTH = 2000
_HORIZONTAL_SCROLL_THRESHOLD = 300  # chars on a single line before flagging PI-003

# PI-004: Obfuscation via escape sequences
# 4+ consecutive unicode escapes = "bash" or "ignore" hiding in plain sight
_UNICODE_ESC_RE = re.compile(r'(?:\\u[0-9a-fA-F]{4}){4,}')
# 4+ consecutive hex escapes = same technique in hex form
_HEX_ESC_RE = re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}')

# PI-005: Invisible / zero-width / bidi-override Unicode characters (Research 1).
# Distinct from PI-004: PI-004 catches \uXXXX as a literal 6-char text sequence.
# PI-005 catches the actual decoded codepoints already present in the config string.
# SH-004 catches non-ASCII *letters* (Unicode category "L") in server names.
# PI-005 targets category "Cf" (Format) chars in args/env — a vector SH-004 misses.
# Reference: Trojan Source CVE-2021-42574; MDPI May 2026 MCP Threat Modeling paper.
_INVISIBLE_UNICODE: dict[str, str] = {
    '​': 'Zero Width Space',
    '‌': 'Zero Width Non-Joiner',
    '‍': 'Zero Width Joiner',
    '﻿': 'BOM/Zero Width No-Break Space',
    '⁠': 'Word Joiner',
    '⁡': 'Function Application (invisible)',
    '⁢': 'Invisible Times',
    '⁣': 'Invisible Separator',
    '⁤': 'Invisible Plus',
    '­': 'Soft Hyphen',
    '᠎': 'Mongolian Vowel Separator',
    '͏': 'Combining Grapheme Joiner',
}
# Bidi overrides can flip text display direction — U+202E makes text read backwards in the UI.
_BIDI_OVERRIDE_UNICODE: dict[str, str] = {
    '‪': 'LTR Embedding',
    '‫': 'RTL Embedding',
    '‬': 'Pop Directional Formatting',
    '‭': 'LTR Override',
    '‮': 'RTL Override (Trojan Source)',
    '⁦': 'LTR Isolate',
    '⁧': 'RTL Isolate',
    '⁨': 'First Strong Isolate',
    '⁩': 'Pop Directional Isolate',
}
_ALL_STEALTH_UNICODE: dict[str, str] = {**_INVISIBLE_UNICODE, **_BIDI_OVERRIDE_UNICODE}


def _find_stealth_chars(text: str) -> tuple[list[str], bool]:
    """Return (unique_char_names_found, any_bidi_override_present)."""
    found: list[str] = []
    seen: set[str] = set()
    any_bidi = False
    for char in text:
        if char in _ALL_STEALTH_UNICODE and char not in seen:
            seen.add(char)
            found.append(_ALL_STEALTH_UNICODE[char])
            if char in _BIDI_OVERRIDE_UNICODE:
                any_bidi = True
    return found, any_bidi


def _render_safe(text: str, max_len: int = 80) -> str:
    """Safe ASCII representation of text for embedding in Finding.detail."""
    parts: list[str] = []
    for char in text[:max_len]:
        if char in _ALL_STEALTH_UNICODE or ord(char) > 127 or ord(char) < 32:
            parts.append(f'\\u{ord(char):04X}')
        else:
            parts.append(char)
    if len(text) > max_len:
        parts.append('...')
    return ''.join(parts)


def check_tool_poisoning(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []
    full_args = " ".join(server.args)
    # Also build a searchable string from env var VALUES for injection/exfiltration patterns
    full_env_vals = " ".join(f"{k}={v}" for k, v in server.env.items())

    # PI-001: Prompt injection keywords in server args OR env var values
    # Env values: real-world attack — malicious env var instructs server to override system behavior
    for target_text, source_label in [(full_args, "args"), (full_env_vals, "env vars")]:
        for pattern, description in _INJECTION_PATTERNS:
            match = pattern.search(target_text)
            if match:
                findings.append(Finding(
                    check_id="PI-001",
                    title=f"Potential prompt injection in server {source_label} ({description})",
                    detail=(
                        f"Server `{server.name}` contains {source_label} text matching a known prompt injection pattern "
                        f"({description}): `{match.group(0)!r}`. "
                        "This phrasing is used in tool poisoning attacks to silently hijack AI assistant behavior."
                    ),
                    severity=Severity.HIGH,
                    owasp=OWASPCategory.MCP03,
                    server_name=server.name,
                    remediation=(
                        f"Review this server's {source_label} and source code carefully. "
                        "If it was installed from an untrusted source, remove it. "
                        "Legitimate MCP servers do not embed instruction-override language in their configuration."
                    ),
                    engine="custom",
                    cwe_id="CWE-77",
                ))
                break  # One PI-001 per source (args or env)
        else:
            continue
        break  # Found one PI-001 total — don't double-fire

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
            cwe_id="CWE-400",
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
                cwe_id="CWE-693",
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

    # DX-001: Data exfiltration patterns in args OR env var values
    # Real-world incident (Postmark, Sep 2025): DEFAULT_BCC env var silently exfiltrated all emails
    _dx_sources = [
        (full_args, "args", _EXFILTRATION_PATTERNS),
        (full_env_vals, "env vars", _EXFILTRATION_ENV_PATTERNS),
    ]
    for target_text, source_label, patterns in _dx_sources:
        for pattern, description in patterns:
            match = pattern.search(target_text)
            if match:
                findings.append(Finding(
                    check_id="DX-001",
                    title=f"Potential data exfiltration pattern in server {source_label}: {description}",
                    detail=(
                        f"Server `{server.name}` {source_label} contain language suggesting data exfiltration: "
                        f"`{match.group(0)!r}` ({description}). "
                        "In the Postmark MCP incident (Sep 2025), a malicious env var (DEFAULT_BCC) silently "
                        "BCC'd all emails to an attacker for 2 weeks. "
                        "Legitimate MCP servers do not need data-transfer directives in configuration."
                    ),
                    severity=Severity.HIGH,
                    owasp=OWASPCategory.MCP03,
                    server_name=server.name,
                    remediation=(
                        f"Review this server's {source_label} and source code carefully. "
                        "If the server makes undisclosed outbound connections or email forwarding, remove it. "
                        "Legitimate MCP servers document all network calls and data flows explicitly."
                    ),
                    engine="custom",
                    cwe_id="CWE-200",
                ))
                break
        else:
            continue
        break  # One DX-001 total — don't double-fire

    # PI-005: Invisible / zero-width / bidi-override Unicode steganography
    # Attack: embed U+200B (Zero Width Space) between letters of "ignore all instructions" —
    # the text is invisible in Claude Desktop / Cursor approval dialogs but the LLM reads it
    # intact, bypassing PI-001's keyword regex (which requires consecutive visible characters).
    # Bidi overrides (U+202E) additionally flip display direction (Trojan Source technique).
    _pi005_targets = [
        (" ".join(server.args), "args"),
        (" ".join(f"{k}={v}" for k, v in server.env.items()), "env vars"),
        (server.name, "server name"),
    ]
    for target_text, source_label in _pi005_targets:
        found_names, any_bidi = _find_stealth_chars(target_text)
        if found_names:
            severity = Severity.HIGH if any_bidi else Severity.MEDIUM
            bidi_note = (
                " Bidi override characters (Trojan Source technique, CVE-2021-42574) can "
                "make injected text display as harmless-looking content while the LLM "
                "processes the actual malicious instruction."
            ) if any_bidi else ""
            char_summary = ", ".join(found_names[:3])
            if len(found_names) > 3:
                char_summary += f" (+{len(found_names) - 3} more)"
            findings.append(Finding(
                check_id="PI-005",
                title=f"Invisible Unicode in server {source_label}: {char_summary}",
                detail=(
                    f"Server `{server.name}` {source_label} contain invisible Unicode character(s): "
                    f"{char_summary}. "
                    "These characters render as nothing in Claude Desktop / Cursor approval dialogs "
                    "but are passed to the language model in full, enabling completely invisible "
                    "injection attacks. An attacker can split keywords like 'ignore' into "
                    "'i​g​n​o​r​e' — bypassing PI-001 regex checks while "
                    f"the LLM reads the word normally.{bidi_note}"
                ),
                severity=severity,
                owasp=OWASPCategory.MCP03,
                server_name=server.name,
                remediation=(
                    f"Open this server's {source_label} in a hex editor or Unicode-aware "
                    "text editor to locate and remove the invisible characters. "
                    "These have no legitimate use in MCP server configuration. "
                    "If this config was received from an external source or copy-pasted "
                    "from a chat/web page, treat it as potentially tampered."
                ),
                engine="custom",
                attack_tactic="defense-evasion",
                cwe_id="CWE-116",
            ))
            break  # One PI-005 per server — first field wins to avoid noise

    return findings
