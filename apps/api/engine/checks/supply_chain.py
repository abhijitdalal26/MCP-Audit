import re
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

# Confirmed malicious or spoofed package names
KNOWN_MALICIOUS: set[str] = {
    "mcp-server-free",
    "modelcontextprotocl",
    "modelcontextprotocol-free",
    "mcp-filesystem-server",  # spoofed (real: @modelcontextprotocol/server-filesystem)
}

# Typosquatting detection patterns
_TYPOSQUAT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'@modelcontextprotoc[^o]l/', re.I), "missing 'o' in 'protocol'"),
    (re.compile(r'@modelcontextprot0col/', re.I), "zero replacing 'o' in 'protocol'"),
    (re.compile(r'@m0delcontextprotocol/', re.I), "zero replacing 'o' in 'model'"),
    (re.compile(r'mcp-serv[e3]r-', re.I), "leet-speak substitution in 'server'"),
    (re.compile(r'@modelc0ntextprotocol/', re.I), "zero replacing 'o' in 'context'"),
]

# Trusted scopes — everything else gets flagged as unverified (SC-003)
_TRUSTED_SCOPES: set[str] = {
    "@modelcontextprotocol",
    "@anthropic",
}


def _extract_package(server: MCPServer) -> str | None:
    if server.command in ("npx", "npm", "uvx"):
        for arg in server.args:
            if not arg.startswith("-"):
                return arg
    return None


def check_supply_chain(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []
    package = _extract_package(server)

    if not package:
        return findings

    pkg_lower = package.lower().split("@")[0] if not package.startswith("@") else package.lower()

    # SC-001: Known malicious package
    base_name = package.split("@")[0] if not package.startswith("@") else "/".join(package.split("/")[:2])
    if base_name.lower() in KNOWN_MALICIOUS or pkg_lower in KNOWN_MALICIOUS:
        findings.append(Finding(
            check_id="SC-001",
            title=f"Known malicious package: `{package}`",
            detail=(
                f"Server `{server.name}` installs `{package}`, which is flagged as a known malicious "
                "or confirmed typosquatted package. This package should not be run."
            ),
            severity=Severity.CRITICAL,
            owasp=OWASPCategory.MCP04,
            server_name=server.name,
            remediation=(
                "Remove this server from your config immediately. "
                "Find the official package at registry.modelcontextprotocol.io."
            ),
            engine="custom",
        ))
        return findings  # No point running further checks on a known-bad package

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
            break  # One typosquat finding per server is enough

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
            ))

    return findings
