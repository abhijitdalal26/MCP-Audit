import re
import os
import unicodedata
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

# Confirmed malicious, spoofed, or compromised packages (any runtime)
# Sources: tooltrust AS-008, ox.security advisory (Apr 2026), Trend Micro MCP CVEs, community reports
KNOWN_MALICIOUS: set[str] = {
    # Confirmed spoofed/fake
    "mcp-server-free",
    "modelcontextprotocl",           # missing 'o' in protocol
    "modelcontextprotocol-free",
    "mcp-filesystem-server",         # spoofs @modelcontextprotocol/server-filesystem

    # Known malicious MCP-specific packages (sourced from Trend Micro / Ox Security)
    "mcp-server-free-filesystem",    # typosquat of official filesystem server
    "claude-mcp-server",             # impersonation package not from Anthropic
    "anthropic-mcp",                 # impersonation — Anthropic publishes @anthropic scope, not this
    "mcp-tool-helper",               # generic impersonation pattern
    "mcp-server-helper",             # generic impersonation pattern
    "free-mcp-server",               # generic impersonation pattern
}

# Packages that are malicious ONLY on specific runtimes (disambiguated by command).
# e.g., "litellm" on npm is a supply chain attack; on PyPI via uvx it is legitimate.
KNOWN_MALICIOUS_BY_RUNTIME: dict[str, set[str]] = {
    # npm-only malicious: these package names exist legitimately on other registries but were
    # compromised via npm account takeover (tooltrust AS-008, April 2026 supply chain wave)
    "npx": {"litellm", "trivy"},
    "npm": {"litellm", "trivy"},
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


def _cmd_basename(server: MCPServer) -> str:
    return os.path.basename(server.command or "").lower().split(".")[0]


def _extract_packages(server: MCPServer) -> list[tuple[str, str]]:
    """Return list of (package_name, runtime) tuples for supply-chain checking.

    Supports: npx/npm (npm registry), uvx (PyPI), uv run --with (PyPI).
    """
    cmd = _cmd_basename(server)
    if cmd in ("npx", "npm"):
        for arg in server.args:
            if not arg.startswith("-"):
                return [(arg, "npm")]
        return []
    if cmd == "uvx":
        for arg in server.args:
            if not arg.startswith("-"):
                return [(arg, "pypi")]
        return []
    # uv run --with pkg1 --with pkg2 script.py
    # Commonly used by Python-based MCP servers (e.g. uv run --with mcp server.py)
    if cmd == "uv":
        pkgs: list[tuple[str, str]] = []
        args = server.args
        i = 0
        while i < len(args):
            if args[i] in ("--with", "-w") and i + 1 < len(args):
                pkgs.append((args[i + 1], "pypi"))
                i += 2
                continue
            if args[i].startswith("--with="):
                pkgs.append((args[i].split("=", 1)[1], "pypi"))
            i += 1
        return pkgs
    return []


def _base_package_name(package: str) -> str:
    """Strip version pin to get base name (npm @scope/pkg@ver or PyPI pkg==ver)."""
    if package.startswith("@"):
        parts = package.split("@")
        return "@" + parts[1].split("/")[0] + "/" + "@".join(parts[1].split("/")[1:]).split("@")[0] if "/" in parts[1] else "@" + parts[1]
    # Python: mcp-server==1.2.3 → mcp-server; npm: pkg@1.2.3 → pkg
    return re.split(r'[@=<>!]', package)[0]


def check_supply_chain(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []
    packages = _extract_packages(server)

    if not packages:
        return findings

    cmd = _cmd_basename(server)

    for package, runtime in packages:
        base = _base_package_name(package).lower()

        # SC-001: Known malicious / compromised package
        runtime_blocklist = KNOWN_MALICIOUS_BY_RUNTIME.get(cmd, set())
        if base in KNOWN_MALICIOUS or base in runtime_blocklist or re.split(r'[@=<>!]', package.lower())[0] in KNOWN_MALICIOUS:
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
                cwe_id="CWE-829",
            ))
            continue  # No further supply-chain checks on confirmed bad packages

        # SC-002: Typosquatting detection (npm-focused patterns — @scope/ based)
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
                    cwe_id="CWE-829",
                ))
                break

        # SC-003: Unverified package scope (npm only — PyPI has no scopes)
        if runtime == "npm" and package.startswith("@"):
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

        # SC-005: GitHub/Bitbucket/GitLab ref dependency — bypasses registry and audit trail
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

        # SC-006: Non-ASCII / homoglyph characters in package name (Research 1).
        # SH-004 checks for non-ASCII Unicode *letters* in server *names*.
        # SC-006 covers the args vector: the package name inside npx/uvx args.
        # npm package names are restricted to ASCII [a-z0-9_.\-@/] (npm spec).
        # PyPI names are restricted to [A-Za-z0-9._-] (PEP 508).
        # Any codepoint > 127 is a homoglyph spoofing attempt or encoding corruption.
        # Example: "аnthropic-mcp" with Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061).
        _sc006_hits: list[str] = []
        for i, char in enumerate(package):
            if ord(char) > 127:
                char_name = unicodedata.name(char, 'UNKNOWN CHARACTER')
                char_cat = unicodedata.category(char)
                _sc006_hits.append(
                    f"'{char}' at pos {i} (U+{ord(char):04X} {char_name} [{char_cat}])"
                )
        if _sc006_hits:
            findings.append(Finding(
                check_id="SC-006",
                title=f"Non-ASCII/homoglyph characters in package name: `{package}`",
                detail=(
                    f"Server `{server.name}` installs `{package}` which contains non-ASCII "
                    f"Unicode character(s): {'; '.join(_sc006_hits[:3])}. "
                    f"{'(+%d more) ' % (len(_sc006_hits) - 3) if len(_sc006_hits) > 3 else ''}"
                    "npm and PyPI package names are restricted to ASCII characters. "
                    "Non-ASCII characters are the hallmark of homoglyph spoofing attacks — "
                    "a visually identical character (e.g., Cyrillic 'а' U+0430 vs Latin 'a' U+0061) "
                    "that resolves to a completely different package controlled by an attacker."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP04,
                server_name=server.name,
                remediation=(
                    f"Do not install `{package}`. "
                    "Manually type the correct package name at npmjs.com or pypi.org — "
                    "never copy-paste package names from untrusted sources (chat, web pages, emails). "
                    "Homoglyph attacks rely entirely on visual similarity to deceive the installer."
                ),
                engine="custom",
                attack_tactic="initial-access",
                cwe_id="CWE-1007",
            ))

    return findings
