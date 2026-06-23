"""
Audit & Telemetry checks (OWASP MCP08).
AT-001 is in scanner.py (config-level, fires after all servers processed).
AT-002/003 are per-server.
"""
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer


def check_audit(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []

    # AT-002: Transport inconsistency — server declares a URL AND a stdio command
    # A server should use one transport mode; mixing suggests misconfiguration or deception
    has_url = bool(server.url)
    has_command = bool(server.command)
    has_stdio_transport = server.transport in (None, "stdio", "")

    if has_url and has_command and has_stdio_transport:
        findings.append(Finding(
            check_id="AT-002",
            title=f"Transport ambiguity: server has both `command` and `url` fields",
            detail=(
                f"Server `{server.name}` specifies both a `command` field (`{server.command}`) "
                f"and a `url` field (`{server.url}`). "
                "MCP servers use either stdio transport (command-based) or SSE/HTTP transport (URL-based), "
                "not both. This inconsistency may indicate a misconfigured config or an attempt to "
                "obscure which transport is actually used."
            ),
            severity=Severity.LOW,
            owasp=OWASPCategory.MCP08,
            server_name=server.name,
            remediation=(
                "Remove one of `command` or `url` depending on the server's actual transport. "
                "stdio servers: keep `command`, remove `url`. "
                "Remote servers: keep `url`, remove `command` (or use it only for the local proxy)."
            ),
            engine="custom",
        ))

    # AT-003: No transport declared with a URL (implicit HTTP, no SSE/Streamable config)
    if has_url and not has_command:
        if server.transport not in ("sse", "http", "streamable-http", "ws", "websocket"):
            findings.append(Finding(
                check_id="AT-003",
                title=f"Remote server URL without explicit transport declaration",
                detail=(
                    f"Server `{server.name}` connects to a remote URL (`{server.url}`) "
                    "but does not declare a `transport` type (e.g., `sse` or `streamable-http`). "
                    "Without an explicit transport declaration, the MCP client will guess, which can "
                    "lead to unexpected behavior or security issues if the server uses a non-default protocol."
                ),
                severity=Severity.INFO,
                owasp=OWASPCategory.MCP08,
                server_name=server.name,
                remediation=(
                    f"Add `\"transport\": \"sse\"` or `\"transport\": \"streamable-http\"` to the `{server.name}` "
                    "server config to make the transport explicit."
                ),
                engine="custom",
            ))

    # AT-004: Network binding to all interfaces (NeighborJack / localhost bypass)
    # Adversa AI Top 25 MCP #13: servers bound to 0.0.0.0 or [::] expose services
    # to the entire local network. Any device on the same WiFi can send tool calls.
    for pattern in ("0.0.0.0", "[::]"):
        if server.url and pattern in server.url:
            findings.append(Finding(
                check_id="AT-004",
                title=f"MCP server bound to all network interfaces: `{server.url}`",
                detail=(
                    f"Server `{server.name}` is configured with URL `{server.url}` containing `{pattern}`, "
                    "which listens on ALL network interfaces — not just localhost. "
                    "Any device on the same local network (or the internet if no firewall) can "
                    "send MCP tool calls to this server without any authentication. "
                    "This is the NeighborJack attack pattern: a malicious device on the same WiFi "
                    "can invoke your MCP tools, read filesystem contents, or exfiltrate data."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP08,
                server_name=server.name,
                remediation=(
                    f"Replace `{pattern}` with `127.0.0.1` (IPv4 localhost) or `[::1]` (IPv6 loopback) "
                    "to restrict the server to the local machine only. "
                    "If this server must be network-accessible, add authentication and TLS (HTTPS)."
                ),
                engine="custom",
                attack_tactic="initial-access",
                cwe_id="CWE-668",
            ))
            break  # One AT-004 per server

    return findings
