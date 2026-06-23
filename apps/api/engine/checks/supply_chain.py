import re
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

# Confirmed malicious, spoofed, or compromised packages
# Sources: tooltrust AS-008, ox.security advisory (Apr 2026), Trend Micro MCP CVEs, community reports
KNOWN_MALICIOUS: set[str] = {
    # Confirmed spoofed/fake
    "mcp-server-free",
    "modelcontextprotocl",           # missing 'o' in protocol
    "modelcontextprotocol-free",
    "mcp-filesystem-server",         # spoofs @modelcontextprotocol/server-filesystem

    # April 2026 supply chain attack wave (tooltrust AS-008)
    "litellm",                       # compromised via npm account takeover — verify using pip/PyPI
    "trivy",                         # npm typosquat of Aqua Security Go binary (legitimate = github release)

    # Known malicious MCP-specific packages (sourced from Trend Micro / Ox Security)
    "mcp-server-free-filesystem",    # typosquat of official filesystem server
    "claude-mcp-server",             # impersonation package not from Anthropic
    "anthropic-mcp",                 # impersonation — Anthropic publishes @anthropic scope, not this
    "mcp-tool-helper",               # generic impersonation pattern
    "mcp-server-helper",             # generic impersonation pattern
    "free-mcp-server",               # generic impersonation pattern
}

# Packages that were compromised but are now patched — flag if an old version is pinned
# Format: (package_name, set_of_bad_versions, remediation_hint)
COMPROMISED_VERSIONS: list[tuple[str, set[str], str]] = [
    # Add as specific compromised versions are documented
    # ("langflow", {"1.0.0", "1.0.1"}, "Upgrade to >=1.1.0"),
]

# Typosquatting detection patterns
_TYPOSQUAT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'@modelcontextprotoc(?!ol/)', re.I), "missing/altered 'ol' in 'protocol'"),
    (re.compile(r'@modelcontextprot0col/', re.I), "zero replacing 'o' in 'protocol'"),
    (re.compile(r'@m0delcontextprotocol/', re.I), "zero replacing 'o' in 'model'"),
    (re.compile(r'mcp-serv[e3]r-', re.I), "leet-speak substitution in 'server'"),
    (re.compile(r'@modelc0ntextprotocol/', re.I), "zero replacing 'o' in 'context'"),
    (re.compile(r'@modelcontexptrotocol/', re.I), "transposed letters in 'context'"),
    (re.compile(r'@modelcontextprotocol\.', re.I), "dot instead of slash after scope"),
]

# Trusted scopes — everything else flagged as unverified (SC-003)
# These are verified npm org accounts belonging to well-known companies.
# Packages from these scopes still need individual review, but the PUBLISHER is established.
_TRUSTED_SCOPES: set[str] = {
    # Official MCP ecosystem
    "@modelcontextprotocol",
    "@anthropic",
    # Major cloud/platform providers with verified npm orgs
    "@aws-sdk",         # Amazon AWS SDK
    "@aws-cdk",         # Amazon CDK
    "@google-cloud",    # Google Cloud
    "@googleapis",      # Google APIs
    "@azure",           # Microsoft Azure
    "@microsoft",       # Microsoft
    "@openai",          # OpenAI
    "@github",          # GitHub (octokit etc.)
    # Developer platforms that publish official MCP servers
    "@vercel",          # Vercel
    "@supabase",        # Supabase
    "@cloudflare",      # Cloudflare
    "@stripe",          # Stripe
    "@sentry",          # Sentry
    "@elastic",         # Elastic/Elasticsearch
    "@smithery",        # Smithery registry (official MCP marketplace)
    "@raycast",         # Raycast
    "@e2b",             # E2B sandbox
    "@upstash",         # Upstash (Redis)
    "@linear",          # Linear
}


def _extract_package(server: MCPServer) -> str | None:
    if server.command in ("npx", "npm", "uvx"):
        for arg in server.args:
            if not arg.startswith("-"):
                return arg
    return None


def _base_package_name(package: str) -> str:
    """Strip version pin to get base name."""
    if package.startswith("@"):
        parts = package.split("@")
        # @scope/pkg@version → @scope/pkg
        return "@" + parts[1].split("/")[0] + "/" + "@".join(parts[1].split("/")[1:]).split("@")[0] if "/" in parts[1] else "@" + parts[1]
    return package.split("@")[0]


def check_supply_chain(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []
    package = _extract_package(server)

    if not package:
        return findings

    base = _base_package_name(package).lower()

    # SC-001: Known malicious / compromised package
    if base in KNOWN_MALICIOUS or package.lower().split("@")[0] in KNOWN_MALICIOUS:
        findings.append(Finding(
            check_id="SC-001",
            title=f"Known malicious or compromised package: `{package}`",
            detail=(
                f"Server `{server.name}` installs `{package}`, which is flagged as known malicious, "
                "confirmed typosquatted, or part of a supply chain attack. "
                "(Sources: tooltrust AS-008 embedded blocklist, Ox.Security advisory April 2026)"
            ),
            severity=Severity.CRITICAL,
            owasp=OWASPCategory.MCP04,
            server_name=server.name,
            remediation=(
                "Remove this server from your config immediately. "
                "Find the official equivalent at registry.modelcontextprotocol.io. "
                "If this is `litellm` or `trivy`, verify you are using the official distribution "
                "channel (pip install litellm from PyPI, not npm)."
            ),
            engine="custom",
        ))
        return findings  # No further supply-chain checks on confirmed bad packages

    # SC-002: Typosquatting detection
    for pattern, reason in _TYPOSQUAT_PATTERNS:
        if pattern.search(package):
            findings.append(Finding(
                check_id="SC-002",
                title=f"Possible typosquatted package: `{package}`",
                detail=(
                    f"Server `{server.name}` installs `{package}`, which resembles a legitimate "
                    f"MCP package but contains a subtle spelling error ({reason}). "
                    "This is a common typosquatting attack pattern."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP04,
                server_name=server.name,
                remediation=(
                    f"Verify the exact package name at registry.modelcontextprotocol.io or npmjs.com. "
                    "Do not install until you have confirmed the correct spelling."
                ),
                engine="custom",
            ))
            break

    # SC-003: Unverified package scope
    if package.startswith("@"):
        scope = package.split("/")[0]
        if scope not in _TRUSTED_SCOPES:
            findings.append(Finding(
                check_id="SC-003",
                title=f"Package from unverified scope: `{scope}`",
                detail=(
                    f"Server `{server.name}` installs `{package}` from scope `{scope}`, "
                    "which is not an officially verified MCP publisher. "
                    "Third-party packages may not have undergone any security review."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.MCP04,
                server_name=server.name,
                remediation=(
                    f"Verify `{package}` on npmjs.com and cross-reference with "
                    "registry.modelcontextprotocol.io or glama.ai/mcp/servers before trusting it. "
                    "Check the package's GitHub repo for source code and maintainer history."
                ),
                engine="custom",
                cwe_id="CWE-829",
            ))

    # SC-005: GitHub ref dependency — bypasses npm registry and audit trail
    # Pattern: npx github:user/repo or npm install github:user/repo
    # These pull directly from a GitHub branch/commit, not a versioned npm release.
    # No npm audit, no integrity hash, no changelog enforcement — any push to that
    # branch silently changes what code runs (rug pull via git force-push).
    if package.startswith("github:") or package.startswith("bitbucket:") or package.startswith("gitlab:"):
        host = package.split(":")[0]
        findings.append(Finding(
            check_id="SC-005",
            title=f"Direct {host.capitalize()} ref dependency: `{package}`",
            detail=(
                f"Server `{server.name}` installs `{package}` directly from {host.capitalize()}, "
                "bypassing the npm registry entirely. "
                "This means: no npm audit trail, no integrity hash verification, no locked version. "
                "A maintainer can force-push to that branch and silently change what code runs "
                "on your machine the next time the MCP server starts (rug pull attack)."
            ),
            severity=Severity.HIGH,
            owasp=OWASPCategory.MCP04,
            server_name=server.name,
            remediation=(
                f"Replace `{package}` with a published npm package version if the author has one. "
                "If you must use a git ref, pin to a specific commit SHA "
                f"(e.g., `github:user/repo#abc1234`) and verify the commit before pinning. "
                "Consider forking the repo to your own account to control when updates are pulled."
            ),
            engine="custom",
            attack_tactic="initial-access",
            cwe_id="CWE-829",
        ))

    return findings
