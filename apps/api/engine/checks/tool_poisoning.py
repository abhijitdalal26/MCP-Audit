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
]

_MAX_ARGS_LENGTH = 2000


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
            break  # One finding per server for PI-001

    # PI-002: Excessively long args (potential hidden payload)
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

    return findings
