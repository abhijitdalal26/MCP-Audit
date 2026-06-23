import os
import re
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

_BROAD_PATHS: list[str] = [
    "/", "/Users", "/home", "/root", "/etc", "/var",
    "C:\\", "C:\\Users", "C:\\Windows", "/usr", "/opt",
]

# Any single Windows drive letter root: F:/, F:\, F:
_WIN_DRIVE_ROOT_RE = re.compile(r'^[A-Za-z]:[/\\]?$')

# Commands that can invoke filesystem/JS/Python servers (by basename without extension)
_EXEC_BASENAMES = {"npx", "node", "uvx", "uv", "python", "python3", "deno", "bun"}


def _is_node_like_command(cmd: str | None) -> bool:
    """True if command is a known script-runner, accepting full paths like /usr/bin/node."""
    if cmd is None:
        return False
    base = os.path.basename(cmd).lower()
    # Strip extensions (.exe, .cmd) for Windows paths
    if "." in base:
        base = base.rsplit(".", 1)[0]
    return base in _EXEC_BASENAMES

_SHELL_KEYWORDS: list[str] = [
    "--exec", "--shell", "--cmd", "--command",
    "--eval", "--run", "--execute",
    "/bin/sh", "/bin/bash", "cmd.exe", "powershell.exe",
]

_ADMIN_ENV_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("PE-003", re.compile(r'(?i)(sudo_password|root_token|root_password|admin_key|admin_password|admin_token)')),
    ("PE-003", re.compile(r'(?i)(master_key|super_admin|superuser_password|master_password)')),
]

_DB_READ_ONLY_MARKERS: list[str] = [
    "?mode=ro", "readonly=true", "read_only=true", "?readOnly=true",
]

_DB_ENV_RE = re.compile(r'(?i)(database_url|db_url|postgres_url|mysql_url|connection_string)')
_WRITE_SERVER_RE = re.compile(r'(?i)(write|insert|update|delete|admin|migrate)')


def _is_broad_path(arg: str, broad: str) -> bool:
    """True only if the path IS the broad path or at most 1 level deeper (e.g. /Users/me but not /Users/me/projects)."""
    if arg == broad:
        return True
    sep = "/" if "/" in broad else "\\"
    if arg.startswith(broad + sep) or arg.startswith(broad + ("/" if sep == "\\" else "\\")):
        broad_depth = len(broad.replace("\\", "/").rstrip("/").split("/"))
        arg_depth = len(arg.replace("\\", "/").rstrip("/").split("/"))
        return arg_depth <= broad_depth + 1
    return False


def check_privilege(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []

    # PE-001: Filesystem server with overly broad paths
    if _is_node_like_command(server.command):
        seen_pe1: set[str] = set()
        for arg in server.args:
            if arg in seen_pe1:
                continue
            flagged = False
            # Check static broad path list
            for broad in _BROAD_PATHS:
                if _is_broad_path(arg, broad):
                    flagged = True
                    break
            # Dynamic check: Windows drive roots (F:/, D:\, etc.)
            if not flagged and _WIN_DRIVE_ROOT_RE.match(arg):
                flagged = True
            if flagged:
                seen_pe1.add(arg)
                findings.append(Finding(
                    check_id="PE-001",
                    title=f"Over-broad filesystem path: `{arg}`",
                    detail=(
                        f"Server `{server.name}` has access to `{arg}`, an overly broad filesystem path. "
                        "This grants the MCP server read/write access to far more files than it needs, "
                        "including potentially sensitive system files, SSH keys, and credentials."
                    ),
                    severity=Severity.HIGH,
                    owasp=OWASPCategory.MCP02,
                    server_name=server.name,
                    remediation=(
                        f"Restrict the path to the minimum required directory. "
                        f"Replace `{arg}` with only the specific project folder this server needs "
                        "(e.g., `/Users/you/projects/myapp` instead of `/Users`)."
                    ),
                    engine="custom",
                ))

    # PE-002: Shell execution capabilities in args
    for arg in server.args:
        for keyword in _SHELL_KEYWORDS:
            if keyword.lower() in arg.lower():
                findings.append(Finding(
                    check_id="PE-002",
                    title=f"Shell execution argument detected: `{arg}`",
                    detail=(
                        f"Server `{server.name}` passes `{arg}` as an argument, suggesting it has "
                        "shell execution capabilities. MCP servers with shell access can run arbitrary "
                        "commands on your machine under your user account."
                    ),
                    severity=Severity.HIGH,
                    owasp=OWASPCategory.MCP05,
                    server_name=server.name,
                    remediation=(
                        "Only allow shell-execution MCP servers from verified, well-reviewed sources. "
                        "Audit the server's source code before installing. "
                        "Consider using a more restricted alternative if shell access is not required."
                    ),
                    engine="custom",
                ))
                break

    # PE-003: Admin/root credential patterns in env vars
    seen_pe3: set[str] = set()
    for env_key in server.env:
        for check_id, pattern in _ADMIN_ENV_PATTERNS:
            dedup = f"{env_key}"
            if dedup in seen_pe3:
                continue
            if pattern.search(env_key):
                seen_pe3.add(dedup)
                findings.append(Finding(
                    check_id=check_id,
                    title=f"Admin/root credential in env var: `{env_key}`",
                    detail=(
                        f"Server `{server.name}` sets `{env_key}`, suggesting it uses "
                        "administrative or root-level credentials. "
                        "Granting MCP servers admin access significantly expands the blast radius of any compromise."
                    ),
                    severity=Severity.HIGH,
                    owasp=OWASPCategory.MCP02,
                    server_name=server.name,
                    remediation=(
                        "Avoid giving MCP servers admin or root credentials. "
                        "Create a least-privilege service account with only the permissions "
                        "this specific server actually requires."
                    ),
                    engine="custom",
                ))
                break

    # PE-004: Database access without explicit read-only constraint
    for env_key, env_val in server.env.items():
        if _DB_ENV_RE.search(env_key) and env_val:
            if not any(marker in env_val.lower() for marker in _DB_READ_ONLY_MARKERS):
                if not _WRITE_SERVER_RE.search(server.name):
                    findings.append(Finding(
                        check_id="PE-004",
                        title=f"Database connection without read-only constraint in `{env_key}`",
                        detail=(
                            f"Server `{server.name}` has a database connection string in `{env_key}` "
                            "without an explicit read-only flag. If this server only needs read access, "
                            "granting implicit write access violates the principle of least privilege."
                        ),
                        severity=Severity.MEDIUM,
                        owasp=OWASPCategory.MCP10,
                        server_name=server.name,
                        remediation=(
                            "If this server only needs read access, use a read-only database user "
                            "or append `?mode=ro` (SQLite) to the connection string. "
                            "For PostgreSQL, create a role with only SELECT privileges."
                        ),
                        engine="custom",
                    ))

    return findings
