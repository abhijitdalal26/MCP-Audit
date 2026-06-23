import re
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

# Offline allowlist of known-good MCP package scopes and names.
# Sources: registry.modelcontextprotocol.io, Glama verified list, Smithery top-100
# A package NOT in this list gets SH-001 (unregistered shadow server).
_KNOWN_GOOD_SCOPES: set[str] = {
    "@modelcontextprotocol",
    "@anthropic",
    "@smithery",
    "@aws",
    "@google",
    "@microsoft",
}

_KNOWN_GOOD_PACKAGES: set[str] = {
    # Official @modelcontextprotocol packages
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-git",
    "@modelcontextprotocol/server-google-drive",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-sequentialthinking",
    "@modelcontextprotocol/server-gdrive",
    "@modelcontextprotocol/server-time",
    "@modelcontextprotocol/server-everything",
    # Community well-known packages (verified on Glama/Smithery)
    "mcp-server-sqlite-npx",
    "@upstash/mcp-server",
    "@vercel/mcp-server",
    "@supabase/mcp-server-supabase",
    "mcp-server-sentry",
    "@raycast/mcp",
    "mcp-obsidian",
    "mcp-server-qdrant",
    "@e2b/mcp-server",
}

# Strip version pin for comparison
_AT_VERSION_RE = re.compile(r'@[\d.]+$')


def _strip_version(package: str) -> str:
    if package.startswith("@"):
        # @scope/pkg@1.0.0 → @scope/pkg
        parts = package.split("@")
        if len(parts) >= 3:
            return "@" + parts[1] + "/" + "/".join(p.split("@")[0] for p in parts[2:] if p)
        return package
    # pkg@1.0.0 → pkg
    return package.split("@")[0] if "@" in package else package


def _is_known(package: str) -> bool:
    base = _strip_version(package).lower()
    if base in _KNOWN_GOOD_PACKAGES:
        return True
    if base.startswith("@"):
        scope = base.split("/")[0]
        if scope in _KNOWN_GOOD_SCOPES:
            return True
    return False


def check_shadow(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []

    # SH-001: Server not in any known MCP registry / allowlist
    if server.command in ("npx", "npm", "uvx"):
        for arg in server.args:
            if not arg.startswith("-"):
                if not _is_known(arg):
                    findings.append(Finding(
                        check_id="SH-001",
                        title=f"Unregistered MCP server package: `{_strip_version(arg)}`",
                        detail=(
                            f"Server `{server.name}` installs `{arg}`, which is not found in the "
                            "known MCP server registry (registry.modelcontextprotocol.io, Glama, or Smithery). "
                            "Unregistered servers are shadow servers — they may have been installed without "
                            "proper review and could exfiltrate data or run malicious code without disclosure."
                        ),
                        severity=Severity.MEDIUM,
                        owasp=OWASPCategory.MCP09,
                        server_name=server.name,
                        remediation=(
                            f"Verify `{_strip_version(arg)}` against registry.modelcontextprotocol.io and "
                            "glama.ai/mcp/servers before trusting it. "
                            "If this server is internal/custom, document its purpose and audit its source code."
                        ),
                        engine="custom",
                        attack_tactic="initial-access",
                    ))
                break  # Only one SH-001 per server

    # SH-002: HTTP server without TLS
    if server.url:
        is_localhost = "localhost" in server.url or "127.0.0.1" in server.url or "0.0.0.0" in server.url
        if server.url.startswith("http://") and not is_localhost:
            findings.append(Finding(
                check_id="SH-002",
                title=f"MCP server using unencrypted HTTP: `{server.url}`",
                detail=(
                    f"Server `{server.name}` connects to `{server.url}` over plain HTTP. "
                    "Unencrypted connections expose all MCP tool calls, responses, and any "
                    "credentials passed to network interception (man-in-the-middle attacks)."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP07,
                server_name=server.name,
                remediation=(
                    f"Replace `{server.url}` with an HTTPS equivalent. "
                    "If the server operator does not support HTTPS, do not use it in production."
                ),
                engine="custom",
                attack_tactic="initial-access",
            ))

    # SH-003: Localhost URL paired with remotely-fetched npm package
    if server.url and ("localhost" in server.url or "127.0.0.1" in server.url):
        package = _get_npm_package(server)
        if package and not _is_local_path(server.command or ""):
            findings.append(Finding(
                check_id="SH-003",
                title=f"Localhost server backed by remote package `{package}`",
                detail=(
                    f"Server `{server.name}` exposes a localhost URL (`{server.url}`) "
                    f"but fetches `{package}` from npm on every run. "
                    "A malicious npm update could silently change what code runs on your local machine."
                ),
                severity=Severity.LOW,
                owasp=OWASPCategory.MCP09,
                server_name=server.name,
                remediation=(
                    f"Pin `{package}` to an exact version and verify its integrity hash, "
                    "or install it locally and reference the binary directly so it is not re-fetched each run."
                ),
                engine="custom",
            ))

    return findings


def _get_npm_package(server: MCPServer) -> str | None:
    if server.command in ("npx", "npm"):
        for arg in server.args:
            if not arg.startswith("-"):
                return arg
    return None


def _is_local_path(command: str) -> bool:
    return "/" in command or "\\" in command
