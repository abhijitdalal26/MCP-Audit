import re
import unicodedata
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

# Offline allowlist of known-good MCP package scopes and names.
# Sources: registry.modelcontextprotocol.io, Glama verified list, Smithery top-100
# A package NOT in this list gets SH-001 (unregistered shadow server).
_KNOWN_GOOD_SCOPES: set[str] = {
    "@modelcontextprotocol",
    "@anthropic",
    "@smithery",
    # Major verified platforms
    "@aws", "@aws-sdk", "@aws-cdk",
    "@google", "@google-cloud", "@googleapis",
    "@microsoft", "@azure",
    "@openai",
    "@github",
    "@vercel",
    "@supabase",
    "@cloudflare",
    "@stripe",
    "@sentry",
    "@elastic",
    "@raycast",
    "@e2b",
    "@upstash",
    "@linear",
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
    # Community well-known packages (verified on Glama/Smithery top-100)
    "mcp-server-sqlite-npx",
    "@upstash/mcp-server",
    "@vercel/mcp-server",
    "@supabase/mcp-server-supabase",
    "mcp-server-sentry",
    "@raycast/mcp",
    "mcp-obsidian",
    "mcp-server-qdrant",
    "@e2b/mcp-server",
    # Additional verified community packages
    "mcp-remote",
    "mcp-server-firecrawl",
    "@firecrawl/mcp-server",
    "mcp-server-tavily",
    "mcp-server-perplexity",
    "mcp-server-linear",
    "mcp-server-jira",
    "mcp-server-notion",
    "mcp-server-slack",
    "mcp-server-github",
    "@wong2/mcp-cli",
    "mcp-server-macos",
    "mcp-server-playwright",
    "mcp-server-cursor",
    "@browserbase/mcp-server-browserbase",
    "mcp-server-terminal",
    "mcp-server-docker",
    "@stripe/agent-toolkit",
}

# Strip version pin for comparison
_AT_VERSION_RE = re.compile(r'@[\d.]+$')

# Env var key patterns indicating auto-discovery / dynamic plugin loading (SH-005).
# Corpus finding: Dezocode's MCP_AUTO_DISCOVERY=true enables silent plugin loading at runtime.
_AUTO_DISCOVERY_KEY_RE = re.compile(
    r'(auto_?discover|plugin_?discover|dynamic_?load|server_?discover|tool_?discover)',
    re.IGNORECASE,
)


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


def _has_non_ascii_letters(text: str) -> bool:
    """Return True if text contains any non-ASCII Unicode letter (potential homoglyph)."""
    for char in text:
        if ord(char) > 127 and unicodedata.category(char).startswith("L"):
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
                        title=f"Unverified MCP package: `{_strip_version(arg)}`",
                        detail=(
                            f"Server `{server.name}` installs `{arg}`, which is not in MCPAudit's "
                            "verified package allowlist (registry.modelcontextprotocol.io, Glama, Smithery). "
                            "This does not mean the package is malicious — internal, new, or niche community "
                            "servers are often unlisted. Verify the publisher and source before trusting it."
                        ),
                        severity=Severity.INFO,
                        owasp=OWASPCategory.MCP09,
                        server_name=server.name,
                        remediation=(
                            f"Verify `{_strip_version(arg)}` against registry.modelcontextprotocol.io and "
                            "glama.ai/mcp/servers. For internal packages, document ownership and audit "
                            "the source code. Pin to an exact version after verification."
                        ),
                        engine="custom",
                        attack_tactic="initial-access",
                        cwe_id="CWE-829",
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
                cwe_id="CWE-319",
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
                cwe_id="CWE-346",
            ))

    # SH-004: Unicode homoglyphs in server name (Adversa AI Top 25 #12 — Tool Name Spoofing)
    # Attackers register servers with names using non-ASCII Unicode letters that are visually
    # identical to ASCII characters (e.g., Cyrillic 'а' vs Latin 'a'). The server appears
    # as "filesystem" in the UI but is actually a different identifier routing to a malicious server.
    if _has_non_ascii_letters(server.name):
        suspicious_chars = [
            f"U+{ord(c):04X} ({unicodedata.name(c, 'UNKNOWN')})"
            for c in server.name if ord(c) > 127 and unicodedata.category(c).startswith("L")
        ]
        findings.append(Finding(
            check_id="SH-004",
            title=f"Server name contains Unicode homoglyphs: `{server.name}`",
            detail=(
                f"Server `{server.name}` contains non-ASCII Unicode letters that may be visually "
                "indistinguishable from legitimate ASCII server names. "
                f"Suspicious characters: {', '.join(suspicious_chars[:5])}. "
                "This is a Tool Name Spoofing attack (Adversa AI Top 25 MCP #12): a malicious server "
                "registers a name that looks identical to a trusted server (e.g., 'filesystem') but "
                "routes tool calls to a different, attacker-controlled implementation."
            ),
            severity=Severity.HIGH,
            owasp=OWASPCategory.MCP03,
            server_name=server.name,
            remediation=(
                "Remove this server from your config and investigate its source. "
                "Legitimate MCP server names use only ASCII characters (a-z, 0-9, hyphens, underscores). "
                "If you installed this from a third-party source, treat it as potentially malicious."
            ),
            engine="custom",
            attack_tactic="defense-evasion",
            cwe_id="CWE-1007",
        ))

    # SH-005: Auto-discovery env var enabling silent plugin loading at runtime
    # Corpus finding (Dezocode): MCP_AUTO_DISCOVERY=true — binary discovers and loads
    # arbitrary MCP extensions at startup without explicit user approval for each one.
    # This is a shadow server attack vector: one trusted server silently loads untrusted ones.
    for key, value in server.env.items():
        if _AUTO_DISCOVERY_KEY_RE.search(key) and value.lower() in ("true", "1", "yes", "on", "enabled"):
            findings.append(Finding(
                check_id="SH-005",
                title=f"Auto-discovery env var enables silent plugin loading: `{key}={value}`",
                detail=(
                    f"Server `{server.name}` has `{key}={value}` in its environment, "
                    "which enables automatic discovery and loading of MCP plugins or extensions at runtime. "
                    "Auto-discovery means the server can silently load additional tool providers that "
                    "were never explicitly approved in your MCP config — each discovered extension "
                    "gains the same access level as the parent server."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP09,
                server_name=server.name,
                remediation=(
                    f"Set `{key}=false` or remove the env var entirely. "
                    "All MCP servers and tool providers should be explicitly listed in your config "
                    "so you have full visibility over what has access to your AI assistant. "
                    "If auto-discovery is required by this server, audit every extension it loads."
                ),
                engine="custom",
                attack_tactic="persistence",
                cwe_id="CWE-284",
            ))
            break  # One SH-005 per server is sufficient

    # SH-006: HTTP/SSE transport with no authentication configuration
    # Research: Censys 2026 — 12,520 MCP services publicly exposed; ~40% with no auth.
    # tooltrust AS-019 equivalent: unauthenticated MCP route exposure.
    # We check: server has a url: field (SSE/HTTP transport) and no auth-related env var.
    if server.url and server.url.startswith("http"):
        _AUTH_LIKE_PATTERNS = re.compile(
            r'(?i)(api[_\-]?key|api[_\-]?token|auth[_\-]?token|bearer|secret|password|passwd|'
            r'credential|oauth|jwt|x[_\-]?api|access[_\-]?token|id[_\-]?token|client[_\-]?secret|'
            r'authorization|apikey)',
        )
        has_auth_env = any(_AUTH_LIKE_PATTERNS.search(k) for k in server.env)
        has_auth_header = any(_AUTH_LIKE_PATTERNS.search(k) for k in server.headers)
        has_auth_in_url = bool(re.search(r'[?&](key|token|secret|auth|api_key)=', server.url, re.I))
        if not has_auth_env and not has_auth_header and not has_auth_in_url:
            findings.append(Finding(
                check_id="SH-006",
                title=f"HTTP MCP server appears to have no authentication: `{server.url}`",
                detail=(
                    f"Server `{server.name}` connects to `{server.url}` via HTTP/SSE transport "
                    "but has no auth-related environment variables (API key, token, bearer, etc.), "
                    "no auth headers configured, and no credential query parameters in the URL. "
                    "If this endpoint is network-accessible, any process or user on the network "
                    "can call its tools without proving identity. "
                    "(Research: Censys 2026 — ~40% of 12,520 exposed MCP services have no authentication)"
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.MCP07,
                server_name=server.name,
                remediation=(
                    "Add an authentication mechanism: set an API key via env var (e.g. `MCP_API_KEY`), "
                    "use mTLS client certificates, or ensure the HTTP transport enforces token-based auth. "
                    "Never expose an MCP HTTP endpoint on a shared network without authentication."
                ),
                engine="custom",
                attack_tactic="initial-access",
                cwe_id="CWE-306",
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
