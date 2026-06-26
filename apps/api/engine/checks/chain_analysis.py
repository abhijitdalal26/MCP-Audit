"""
Cross-Server Capability Chain Analysis — CHAIN-001, CHAIN-002, CHAIN-003.
Research 2: see research/cross_server_chains/RESEARCH.md for background.

All 43 existing checks analyze servers in isolation. This module detects dangerous
capability combinations that only emerge when multiple servers' permissions compose
within the same LLM session.

Called from scanner.py after per-server checks, receiving per_server findings dict
so this module reuses already-computed findings rather than re-running checks.
"""

from __future__ import annotations
import os
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPConfig, MCPServer


# --- Capability Classification ---

def _classify_capabilities(server: MCPServer, findings: list[Finding]) -> set[str]:
    """
    Classify a server into capability buckets.

    Uses existing per-server findings (avoids re-running checks) combined with
    lightweight direct inspection of command and args for cases not covered by
    existing check IDs.

    Buckets:
      filesystem_writer — can write to local filesystem paths
      shell_executor    — can run shell commands or arbitrary code
      secret_holder     — has embedded credentials / secrets in env vars
      http_outbound     — can make requests to non-localhost HTTP endpoints
    """
    caps: set[str] = set()
    check_ids: set[str] = {f.check_id for f in findings}
    args_lower: str = " ".join(server.args).lower()

    cmd_base = os.path.basename(server.command or "").lower()
    if "." in cmd_base:
        cmd_base = cmd_base.rsplit(".", 1)[0]

    # filesystem_writer
    # PE-001 fires for broad paths (/home, /etc, etc.) — definite filesystem write capability
    if "PE-001" in check_ids:
        caps.add("filesystem_writer")
    if "server-filesystem" in args_lower:
        caps.add("filesystem_writer")
    # Generic file-server packages (mcp-server-files, etc.)
    if "server-file" in args_lower and "server-filesystem" not in args_lower:
        caps.add("filesystem_writer")

    # shell_executor
    # PE-002 fires for --exec/--shell/subprocess-style args
    if "PE-002" in check_ids:
        caps.add("shell_executor")
    # EX-001/002/003 fire for inline execution, command substitution, PowerShell encoded cmd
    if check_ids & {"EX-001", "EX-002", "EX-003"}:
        caps.add("shell_executor")
    # Direct shell invocation as the command itself
    if cmd_base in ("bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh"):
        caps.add("shell_executor")
    # Docker always gets shell_executor — it can spawn arbitrary containers
    if cmd_base == "docker":
        caps.add("shell_executor")
    # Known shell/terminal MCP server packages
    _SHELL_PKGS = ("server-shell", "server-terminal", "mcp-server-terminal",
                   "server-exec", "mcp-exec")
    if any(pkg in args_lower for pkg in _SHELL_PKGS):
        caps.add("shell_executor")

    # secret_holder
    # Any SEC finding (SEC-001..007) means live credentials are embedded in this server's env
    _SECRET_CHECKS = {
        "SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006", "SEC-007",
    }
    if check_ids & _SECRET_CHECKS:
        caps.add("secret_holder")

    # http_outbound
    # Server has an external URL (non-localhost)
    _local_hosts = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
    if server.url and not any(h in server.url for h in _local_hosts):
        caps.add("http_outbound")
    # Known HTTP/fetch MCP packages
    _FETCH_PKGS = ("server-fetch", "mcp-fetch", "server-http", "http-client")
    if any(pkg in args_lower for pkg in _FETCH_PKGS):
        caps.add("http_outbound")

    return caps


# --- Chain Detection ---

def check_cross_server_chains(
    config: MCPConfig,
    per_server: dict[str, list[Finding]],
) -> list[Finding]:
    """
    Detect dangerous multi-server capability chains.

    Requires ≥ 2 servers in config — single-server risks are handled by PE/EX/SEC checks.

    CHAIN-001: filesystem_writer + shell_executor on DIFFERENT servers
               (write gadget + execute gadget = arbitrary code execution chain)

    CHAIN-002: secret_holder + http_outbound on DIFFERENT servers
               (credential access + external HTTP = exfiltration chain, no code needed)

    CHAIN-003: 3+ filesystem_writer servers
               (amplified blast radius — union of all writable paths)
    """
    if len(config.servers) < 2:
        return []

    findings: list[Finding] = []

    # Build capability map: server_name → frozenset of capabilities
    cap_map: dict[str, set[str]] = {
        server.name: _classify_capabilities(server, per_server.get(server.name, []))
        for server in config.servers
        if not server.disabled
    }

    writers = [name for name, caps in cap_map.items() if "filesystem_writer" in caps]
    executors = [name for name, caps in cap_map.items() if "shell_executor" in caps]
    secret_servers = [name for name, caps in cap_map.items() if "secret_holder" in caps]
    http_servers = [name for name, caps in cap_map.items() if "http_outbound" in caps]

    # CHAIN-001: Write + Execute gadget pair (different servers only)
    # Composition: writer drops payload to shared path → executor runs it → RCE
    chain1_pairs = [(w, e) for w in writers for e in executors if w != e]
    if chain1_pairs:
        writer_name, exec_name = chain1_pairs[0]
        extra = ""
        if len(chain1_pairs) > 1:
            extra = f" ({len(chain1_pairs) - 1} additional pair(s) also present)"
        findings.append(Finding(
            check_id="CHAIN-001",
            title=(
                f"Write+Execute gadget pair: `{writer_name}` (filesystem) "
                f"+ `{exec_name}` (executor)"
            ),
            detail=(
                f"Two servers in this config compose into a remote code execution chain: "
                f"`{writer_name}` has filesystem write capability and `{exec_name}` has "
                f"shell/code execution capability.{extra} "
                "Via prompt injection, an attacker can instruct the LLM to: "
                f"(1) write a malicious script to a shared writable path via `{writer_name}`, "
                f"then (2) execute it via `{exec_name}`. "
                "Neither server is critical-severity in isolation — their composition creates "
                "arbitrary code execution. This is a documented multi-server attack pattern "
                "(research/cross_server_chains/RESEARCH.md)."
            ),
            severity=Severity.HIGH,
            owasp=OWASPCategory.MCP02,
            server_name=f"{writer_name} + {exec_name}",
            remediation=(
                "Remove either the filesystem writer or the shell executor if both are not "
                "strictly necessary in the same session. If both are needed: restrict the "
                f"filesystem server's writable paths to directories `{exec_name}` cannot access, "
                "and review whether shell execution can be replaced with a more constrained tool. "
                "The principle of least privilege applies at the config level, not just per-server."
            ),
            engine="custom",
            attack_tactic="execution",
            cwe_id="CWE-250",
        ))

    # CHAIN-002: Secrets + HTTP exfiltration chain (different servers only)
    # Composition: LLM reads secrets from holder → POST them via HTTP server → credentials stolen
    chain2_pairs = [(s, h) for s in secret_servers for h in http_servers if s != h]
    if chain2_pairs:
        secret_name, http_name = chain2_pairs[0]
        extra2 = ""
        if len(chain2_pairs) > 1:
            extra2 = f" ({len(chain2_pairs) - 1} additional pair(s) also present)"
        findings.append(Finding(
            check_id="CHAIN-002",
            title=(
                f"Credential exfiltration chain: `{secret_name}` (secrets) "
                f"+ `{http_name}` (HTTP outbound)"
            ),
            detail=(
                f"Two servers in this config compose into a credential exfiltration chain: "
                f"`{secret_name}` holds embedded credentials and `{http_name}` can make "
                f"external HTTP requests.{extra2} "
                "Via prompt injection in any tool response, an attacker can instruct the LLM to: "
                f"(1) read or use credentials accessible to `{secret_name}`, then "
                f"(2) transmit them to an attacker-controlled URL via `{http_name}`. "
                "This path requires no code execution — just two sequential tool calls. "
                "The Postmark MCP incident (Sep 2025) demonstrated this exact pattern: "
                "a credentials server + an email server composed into mass exfiltration."
            ),
            severity=Severity.HIGH,
            owasp=OWASPCategory.MCP01,
            server_name=f"{secret_name} + {http_name}",
            remediation=(
                f"Rotate any credentials embedded in `{secret_name}` immediately if this config "
                "was exposed to untrusted content (web browsing, email, user-controlled files). "
                "Going forward: move secrets to a proper secrets manager instead of MCP env blocks. "
                f"If `{http_name}` is needed, restrict it to an allowlist of approved domains "
                "so it cannot POST to arbitrary external URLs."
            ),
            engine="custom",
            attack_tactic="exfiltration",
            cwe_id="CWE-200",
        ))

    # CHAIN-003: Amplified filesystem blast radius (3+ filesystem writers)
    # Even without a shell executor, multiple writers compose into a larger attack surface.
    # A ransomware-style injection can chain file operations across all servers.
    _CHAIN003_THRESHOLD = 3
    if len(writers) >= _CHAIN003_THRESHOLD:
        writer_list = ", ".join(f"`{w}`" for w in writers[:5])
        if len(writers) > 5:
            writer_list += f" (+{len(writers) - 5} more)"
        findings.append(Finding(
            check_id="CHAIN-003",
            title=f"Amplified filesystem blast radius: {len(writers)} filesystem servers in config",
            detail=(
                f"This config has {len(writers)} servers with filesystem write access: "
                f"{writer_list}. "
                "When accessed by the same LLM session, their writable paths compose into a "
                "single effective attack surface equal to the union of all accessible directories. "
                "A ransomware-style or data-wipe prompt injection can chain file operations "
                "across all servers in a single conversation turn. "
                "Per-server analysis (PE-001) evaluates each server's paths independently — "
                "it does not account for the compounded blast radius from multiple servers."
            ),
            severity=Severity.MEDIUM,
            owasp=OWASPCategory.MCP02,
            server_name="(" + ", ".join(writers) + ")",
            remediation=(
                f"Audit whether all {len(writers)} filesystem servers are required simultaneously. "
                "Reduce to the minimum. For each remaining server, narrow its accessible path "
                "to the smallest directory needed (a specific project folder, not /home or /). "
                "Consider running separate Claude Desktop profiles for tasks that need different "
                "filesystem scopes to prevent cross-task capability composition."
            ),
            engine="custom",
            attack_tactic="impact",
            cwe_id="CWE-732",
        ))

    return findings
