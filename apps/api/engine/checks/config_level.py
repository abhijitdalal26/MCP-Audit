"""
Config-level cross-server security checks.
These run against the full MCPConfig, not individual servers.
CL-001: Confused deputy risk — one server has secrets, another has shell/exec
CL-002: Duplicate server configurations (masked identity/shadowing)
EC-001: Debug logging + secret credentials in same server (log exfiltration risk)
"""
import re
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPConfig, MCPServer

_SHELL_KEYWORDS = {"--exec", "--shell", "--cmd", "/bin/sh", "/bin/bash", "cmd.exe", "powershell.exe"}
_BROAD_PATHS_SET = {"/", "/Users", "/home", "/root", "/etc", "C:\\", "C:\\Users"}
_DEBUG_ENV_PATTERNS = re.compile(r'(?i)^(debug|verbose|log_level|logging_level|loglevel)$')
_DEBUG_VAL_PATTERNS = re.compile(r'(?i)^(true|1|debug|verbose|all|trace)$')
_SECRET_CHECK_IDS = {"SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005"}


def check_config_level(config: MCPConfig, per_server_findings: dict[str, list[Finding]]) -> list[Finding]:
    findings: list[Finding] = []

    _check_confused_deputy(config, per_server_findings, findings)
    _check_duplicate_servers(config, findings)
    _check_debug_logging_exposure(config, per_server_findings, findings)

    return findings


def _has_secrets(server: MCPServer, server_findings: list[Finding]) -> bool:
    return any(f.check_id in _SECRET_CHECK_IDS for f in server_findings)


def _has_shell_execution(server: MCPServer) -> bool:
    for arg in server.args:
        if any(kw in arg.lower() for kw in _SHELL_KEYWORDS):
            return True
    return False


def _has_broad_filesystem(server: MCPServer) -> bool:
    for arg in server.args:
        if arg in _BROAD_PATHS_SET:
            return True
        for broad in _BROAD_PATHS_SET:
            if arg.startswith(broad + "/") or arg.startswith(broad + "\\"):
                parts = arg.replace("\\", "/").rstrip("/").split("/")
                broad_parts = broad.replace("\\", "/").rstrip("/").split("/")
                if len(parts) <= len(broad_parts) + 1:
                    return True
    return False


def _check_confused_deputy(config: MCPConfig, per_server_findings: dict[str, list[Finding]], out: list[Finding]) -> None:
    """CL-001: A single server that has both broad filesystem access AND shell execution capability.
    This is the classic confused deputy — if the LLM is tricked into calling a malicious tool,
    the server already has the access needed to exfiltrate files via shell.
    """
    for server in config.servers:
        server_findings = per_server_findings.get(server.name, [])
        has_broad = _has_broad_filesystem(server)
        has_shell = _has_shell_execution(server)
        has_secrets = _has_secrets(server, server_findings)

        # Shell + broad filesystem = can silently exfiltrate anything
        if has_broad and has_shell:
            out.append(Finding(
                check_id="CL-001",
                title=f"Confused deputy risk: `{server.name}` has broad filesystem AND shell execution",
                detail=(
                    f"Server `{server.name}` combines over-broad filesystem access with shell execution "
                    "capability. This is a classic confused deputy setup: if an attacker tricks your "
                    "AI assistant into calling this server's tools, the server can silently exfiltrate "
                    "any file on your system by using its legitimate filesystem access and shell. "
                    "Neither permission seems dangerous in isolation — combined, they are."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP02,
                server_name=server.name,
                remediation=(
                    "Separate filesystem and shell capabilities into two different, minimal-permission servers. "
                    "The filesystem server should only access a specific project directory (not /Users or /). "
                    "The shell server should not have access to sensitive directories."
                ),
                engine="custom",
                attack_tactic="privilege-escalation",
            ))

        # Secrets + shell = can exfiltrate credentials out of band
        if has_secrets and has_shell and not has_broad:
            out.append(Finding(
                check_id="CL-001",
                title=f"Confused deputy risk: `{server.name}` has hardcoded secrets AND shell execution",
                detail=(
                    f"Server `{server.name}` has hardcoded API credentials AND shell execution capability. "
                    "An attacker who compromises this server can use the shell to exfiltrate the credentials "
                    "without any AI involvement — the server already has everything needed."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP02,
                server_name=server.name,
                remediation=(
                    "Remove hardcoded credentials and shell execution from the same server. "
                    "Use environment variable injection at the system level (shell profile) rather than "
                    "embedding secrets in the MCP config."
                ),
                engine="custom",
                attack_tactic="credential-access",
            ))


def _check_duplicate_servers(config: MCPConfig, out: list[Finding]) -> None:
    """CL-002: Two or more servers use the exact same command+package — possible shadowing attack."""
    seen: dict[str, str] = {}  # (command, first_non_flag_arg) -> server_name

    for server in config.servers:
        if not server.command:
            continue
        first_pkg = next((a for a in server.args if not a.startswith("-")), "")
        key = f"{server.command}:{first_pkg}"

        if key in seen and first_pkg:
            out.append(Finding(
                check_id="CL-002",
                title=f"Duplicate server package: `{server.name}` duplicates `{seen[key]}`",
                detail=(
                    f"Servers `{server.name}` and `{seen[key]}` both run `{server.command} {first_pkg}`. "
                    "Multiple entries for the same package may indicate a tool-shadowing attack where "
                    "a malicious server is registered under a different name to intercept or override "
                    "tool calls from the legitimate server."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.MCP03,
                server_name=server.name,
                remediation=(
                    f"Remove the duplicate entry `{server.name}` if it is unintentional. "
                    "If both servers are needed, verify they have different purposes and that the "
                    "second entry is not a misconfigured or injected copy."
                ),
                engine="custom",
            ))
        else:
            seen[key] = server.name


def _check_debug_logging_exposure(config: MCPConfig, per_server_findings: dict[str, list[Finding]], out: list[Finding]) -> None:
    """EC-001: Debug logging enabled + secrets present in the same server.
    Debug logs often capture environment variables and network payloads, which would expose secrets.
    """
    for server in config.servers:
        has_debug = False
        debug_var = ""
        has_secrets = _has_secrets(server, per_server_findings.get(server.name, []))

        if not has_secrets:
            continue

        for env_key, env_val in server.env.items():
            if _DEBUG_ENV_PATTERNS.match(env_key) and _DEBUG_VAL_PATTERNS.match(env_val):
                has_debug = True
                debug_var = env_key
                break

        if has_debug:
            out.append(Finding(
                check_id="EC-001",
                title=f"Debug logging enabled with hardcoded credentials in `{server.name}`",
                detail=(
                    f"Server `{server.name}` has debug/verbose logging enabled (`{debug_var}=true`) "
                    "AND contains hardcoded API credentials. Many MCP server implementations log "
                    "environment variables and HTTP headers when debug mode is on. "
                    "This combination can cause API keys to appear in log files, stdout, or "
                    "observability platforms in plaintext."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.MCP01,
                server_name=server.name,
                remediation=(
                    f"Disable debug logging in production (`{debug_var}=false`). "
                    "Move secrets out of the MCP config entirely. "
                    "If debug mode is needed for development, use a separate config file with "
                    "placeholder credentials and never commit debug-mode configs."
                ),
                engine="custom",
            ))
