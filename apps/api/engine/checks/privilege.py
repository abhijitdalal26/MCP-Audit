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

# Docker dangerous flags: flag_or_prefix → description of risk
# Covers both --flag=value and --flag value forms
_DOCKER_DANGER_FLAGS: dict[str, str] = {
    "--privileged": "grants full host root access — all host devices + capabilities (equivalent to running as root on the host)",
    "--cap-add=all": "grants ALL Linux capabilities — equivalent to root on the container's namespace",
    "--network=host": "bypasses network isolation — container shares host network stack, can bind any host port",
    "--pid=host": "shares host PID namespace — container can observe/signal all host processes",
    "--ipc=host": "shares host IPC namespace — access to all host inter-process communication resources",
    "--security-opt=no-new-privileges=false": "allows privilege escalation via SUID binaries inside the container",
    "--userns=host": "disables user namespace isolation — container root is host root",
}

# Sensitive host paths that should not be volume-mounted into containers
_DOCKER_SENSITIVE_MOUNT_PATHS: list[str] = [
    "/", "/etc", "/root", "/proc", "/sys", "/dev", "/run", "/boot",
    "/lib", "/lib64", "/usr", "/var/run", "/var/run/docker.sock",
]


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

# PE-006: Commands that run with elevated OS privileges
# No legitimate MCP server should start as root/sudo — it grants host-level access
_ELEVATED_CMD_BASENAMES = {"sudo", "su", "doas", "pkexec", "runas"}

# Sudo/runas in args is also dangerous: e.g. bash args ["-c", "sudo rm -rf /"]
_SUDO_IN_ARGS_RE = re.compile(r'(?:^|[\s;|&])(sudo|doas|pkexec)\s', re.I)

# PE-007: Permission bypass flags — auto-approve all tool calls without user consent
# These flags cause the MCP client to skip ALL user confirmation prompts, meaning
# any tool poisoning or prompt injection attack executes immediately without approval.
# Source: Claude Desktop documentation ("--dangerously-skip-permissions" is explicitly
# warned against for production use); Adversa AI Top 25 #4 (automatic tool execution).
_PERMISSION_BYPASS_FLAGS: set[str] = {
    "--dangerously-skip-permissions",
    "--dangerously-allow-all-permissions",
    "--skip-permissions",
    "--allow-all-permissions",
    "--bypass-permissions",
    "--no-permissions",
}

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
                    cwe_id="CWE-732",
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
                    cwe_id="CWE-77",
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
                    cwe_id="CWE-250",
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
                        cwe_id="CWE-732",
                    ))

    # PE-005: Docker privilege escalation
    # MCP servers running via Docker can break container isolation if dangerous flags are passed.
    # Corpus: terminal_server uses docker run — these flags could appear in real configs.
    _docker_cmd = os.path.basename(server.command or "").lower().rstrip(".exe")
    if _docker_cmd == "docker":
        args_lower = [a.lower() for a in server.args]
        args_joined = " ".join(args_lower)

        # Check for dangerous runtime flags
        for flag, risk_description in _DOCKER_DANGER_FLAGS.items():
            # Match --flag or --flag=... or (for two-word forms) --flag value
            if flag in args_joined or any(a.startswith(flag.split("=")[0] + "=") for a in args_lower):
                findings.append(Finding(
                    check_id="PE-005",
                    title=f"Docker container with dangerous privilege flag: `{flag}`",
                    detail=(
                        f"Server `{server.name}` runs a Docker container with the `{flag}` flag: "
                        f"{risk_description}. "
                        "Dangerous Docker flags break the isolation between the container and the host, "
                        "allowing an MCP server to access host files, processes, or gain root-equivalent "
                        "capabilities — defeating the purpose of containerization."
                    ),
                    severity=Severity.CRITICAL,
                    owasp=OWASPCategory.MCP05,
                    server_name=server.name,
                    remediation=(
                        f"Remove `{flag}` from the Docker run command. "
                        "Run the container without privileged access and with a minimal set of capabilities. "
                        "Use `--cap-drop=ALL --cap-add=<only-what-you-need>` for fine-grained control."
                    ),
                    engine="custom",
                    attack_tactic="privilege-escalation",
                    cwe_id="CWE-250",
                ))
                break  # One PE-005 per server is sufficient for the flag check

        # Check for sensitive host volume mounts (-v /etc:/... or --mount source=/etc,...)
        seen_pe5_mount = False
        for i, arg in enumerate(server.args):
            if seen_pe5_mount:
                break
            # -v flag: next arg is the mount spec, or --volume=spec
            if arg in ("-v", "--volume") and i + 1 < len(server.args):
                mount_spec = server.args[i + 1]
            elif arg.startswith(("--volume=", "-v=")):
                mount_spec = arg.split("=", 1)[1]
            elif arg.startswith("--mount"):
                mount_spec = arg
            else:
                continue
            # Extract host path (before the colon in "hostpath:containerpath[:options]")
            raw = mount_spec.split(":")[0]
            host_path = raw.rstrip("/") or "/"  # preserve "/" if stripping leaves empty
            if any(host_path == p or host_path.startswith(p + "/") for p in _DOCKER_SENSITIVE_MOUNT_PATHS):
                seen_pe5_mount = True
                findings.append(Finding(
                    check_id="PE-005",
                    title=f"Docker container mounts sensitive host path: `{host_path}`",
                    detail=(
                        f"Server `{server.name}` mounts `{host_path}` from the host into the container. "
                        "This gives the containerized MCP server read/write access to sensitive host files. "
                        "Mounting `/etc` exposes credentials; `/` exposes everything; "
                        "`/var/run/docker.sock` gives the container control over the Docker daemon itself."
                    ),
                    severity=Severity.CRITICAL,
                    owasp=OWASPCategory.MCP05,
                    server_name=server.name,
                    remediation=(
                        f"Replace the host mount `{host_path}:...` with a specific subdirectory "
                        "containing only the files this server actually needs. "
                        "Never mount system directories, /etc, /root, or the Docker socket into MCP containers."
                    ),
                    engine="custom",
                    attack_tactic="privilege-escalation",
                    cwe_id="CWE-732",
                ))

    # PE-006: Server command or args request elevated OS privileges (sudo/su/runas)
    # No legitimate MCP server needs to start as sudo — grants full host control.
    _cmd_base = os.path.basename(server.command or "").lower().split(".")[0]
    if _cmd_base in _ELEVATED_CMD_BASENAMES:
        findings.append(Finding(
            check_id="PE-006",
            title=f"MCP server runs with elevated privileges: `{server.command}`",
            detail=(
                f"Server `{server.name}` uses `{server.command}` as its command, requesting "
                "elevated operating system privileges (root/admin). "
                "Running an MCP server as sudo gives it unrestricted host access — "
                "any tool poisoning, prompt injection, or supply chain attack against "
                "this server would gain root-level execution capability."
            ),
            severity=Severity.CRITICAL,
            owasp=OWASPCategory.MCP02,
            server_name=server.name,
            remediation=(
                f"Remove `{server.command}` and run the MCP server under a regular user account. "
                "If the server genuinely requires root access for a specific operation, "
                "isolate that operation in a separate privileged process and grant only "
                "the minimum required capability (e.g., `CAP_NET_BIND_SERVICE` for port 80, "
                "not full root)."
            ),
            engine="custom",
            attack_tactic="privilege-escalation",
            cwe_id="CWE-250",
        ))
    else:
        # Also check args for sudo usage inside shell commands
        full_args_str = " ".join(server.args)
        m = _SUDO_IN_ARGS_RE.search(full_args_str)
        if m:
            findings.append(Finding(
                check_id="PE-006",
                title=f"Privilege escalation via `{m.group(1)}` in server arguments",
                detail=(
                    f"Server `{server.name}` argument string contains `{m.group(1)}`, "
                    "which would execute subsequent commands with elevated privileges. "
                    "This is often used in post-install scripts or shell wrappers to "
                    "silently escalate from user to root during MCP server execution."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP02,
                server_name=server.name,
                remediation=(
                    f"Remove the `{m.group(1)}` call from server arguments. "
                    "MCP servers should operate entirely within user-level permissions. "
                    "If a privileged operation is required, extract it into a separate, "
                    "auditable process with minimal capabilities."
                ),
                engine="custom",
                attack_tactic="privilege-escalation",
                cwe_id="CWE-250",
            ))

    # PE-008: Path traversal sequences in server args (CWE-22)
    # Legitimate MCP server configs use absolute paths — never relative traversals.
    # If a server arg contains "/.." or "\..", it may be an attempt to escape the intended dir.
    # Source: Anthropic Git MCP path traversal CVE (Nov 2025); OWASP Path Traversal CWE-22.
    _PATH_TRAVERSAL_RE = re.compile(r'(?:^|[/\\])\.\.[/\\]|(?:^|[/\\])\.\.(?:$)')
    for arg in server.args:
        if _PATH_TRAVERSAL_RE.search(arg):
            findings.append(Finding(
                check_id="PE-008",
                title=f"Path traversal sequence in server arg: `{arg[:80]}`",
                detail=(
                    f"Server `{server.name}` has an argument containing `..` path traversal: "
                    f"`{arg[:200]}`. "
                    "Legitimate MCP configs always use absolute, canonical paths. "
                    "The presence of `..` sequences suggests either a misconfiguration or "
                    "an injection attempt to escape the intended directory sandbox — "
                    "for example, `/home/user/projects/../../etc/passwd` resolves to `/etc/passwd`. "
                    "(CVE reference: Anthropic Git MCP server path traversal + argument injection, Nov 2025)"
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP02,
                server_name=server.name,
                remediation=(
                    f"Replace the argument `{arg[:80]}` with the resolved absolute path "
                    "(run `realpath` on the intended directory). "
                    "Never use `..` sequences in MCP filesystem server arguments. "
                    "If this argument came from external input, ensure it is canonicalized before use."
                ),
                engine="custom",
                attack_tactic="privilege-escalation",
                cwe_id="CWE-22",
            ))
            break  # One PE-008 per server

    # PE-007: Permission bypass flag in server args
    # These flags cause the MCP client to auto-approve every tool call without user consent.
    # Combining PE-007 with any prompt injection or supply chain attack = immediate exploit.
    for arg in server.args:
        if arg.lower() in _PERMISSION_BYPASS_FLAGS:
            findings.append(Finding(
                check_id="PE-007",
                title=f"Permission bypass flag in server args: `{arg}`",
                detail=(
                    f"Server `{server.name}` passes `{arg}` in its arguments. "
                    "This flag instructs the MCP client to automatically approve ALL tool calls "
                    "from this server without showing the user a confirmation prompt. "
                    "The MCP permission model exists specifically to prevent unauthorized tool calls — "
                    "bypassing it means any prompt injection, tool poisoning, or supply chain attack "
                    "against this server executes silently with zero user interaction. "
                    "This flag is intended for trusted local development only; it must never appear "
                    "in shared, team, or production configurations."
                ),
                severity=Severity.CRITICAL,
                owasp=OWASPCategory.MCP02,
                server_name=server.name,
                remediation=(
                    f"Remove `{arg}` from the server args immediately. "
                    "The user permission prompt is a primary defense layer for MCP security — "
                    "it gives users the opportunity to review and block unexpected tool calls. "
                    "If you need to reduce approval friction for trusted servers, use "
                    "per-tool approval policies rather than blanket bypass flags."
                ),
                engine="custom",
                attack_tactic="defense-evasion",
                cwe_id="CWE-284",
            ))
            break  # One PE-007 per server

    return findings
