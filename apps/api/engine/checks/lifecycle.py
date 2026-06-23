"""
LF-001: npm lifecycle script execution risk (tooltrust AS-015 equivalent).
When npx installs a package without --ignore-scripts, any postinstall/preinstall
scripts in that package run automatically. This is a supply chain attack vector.
"""
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

# Flags that suppress lifecycle script execution
_IGNORE_SCRIPTS_FLAGS = {"--ignore-scripts", "--ignore-scripts=true"}


def check_lifecycle(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []

    if server.command not in ("npx", "npm"):
        return findings

    # Extract package name (first non-flag arg)
    package = None
    has_ignore = False
    has_y = False

    for arg in server.args:
        if arg in _IGNORE_SCRIPTS_FLAGS:
            has_ignore = True
        elif arg in ("-y", "--yes"):
            has_y = True
        elif not arg.startswith("-") and package is None:
            package = arg

    if not package:
        return findings

    # npx -y without --ignore-scripts runs lifecycle scripts automatically on install
    if has_y and not has_ignore:
        findings.append(Finding(
            check_id="LF-001",
            title=f"npm lifecycle scripts will run on install: `{package}`",
            detail=(
                f"Server `{server.name}` runs `{server.command} -y {package}` without `--ignore-scripts`. "
                "npm packages can define `preinstall`, `install`, and `postinstall` scripts that execute "
                "automatically when the package is installed or updated. "
                "A malicious package or a compromised update can use these scripts to run arbitrary code "
                "on your machine before you've had a chance to review the package contents."
            ),
            severity=Severity.MEDIUM,
            owasp=OWASPCategory.MCP04,
            server_name=server.name,
            remediation=(
                f"Add `--ignore-scripts` to the args for `{server.name}` to prevent automatic lifecycle "
                "script execution: "
                f"`\"args\": [\"-y\", \"--ignore-scripts\", \"{package}\"]`. "
                "Note: some packages require lifecycle scripts to function (native modules, binary downloads). "
                "Review the package's scripts block before deciding — run `npm show {package} scripts` to inspect."
            ),
            engine="custom",
            attack_tactic="execution",
            cwe_id="CWE-912",
        ))

    return findings
