import re
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

    return findings
