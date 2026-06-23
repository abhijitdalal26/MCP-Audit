"""
SC-004: CVE lookup via OSV.dev (https://osv.dev)
Open Source Vulnerabilities — Google's cross-ecosystem vulnerability database.
No API key required. Rate limit: 1000 req/min.
Only fires for packages with a pinned version (unpinned = no version to query).
"""
import re
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

_OSV_URL = "https://api.osv.dev/v1/query"
_TIMEOUT = 3.0  # seconds — scan must not block too long on network
_MAX_FINDINGS_PER_PACKAGE = 3  # cap per package to avoid report flooding


def _ecosystem(server: MCPServer) -> str | None:
    if server.command in ("npx", "npm"):
        return "npm"
    if server.command in ("uvx", "pip", "pip3", "python", "python3"):
        return "PyPI"
    return None


def _parse_package_version(arg: str) -> tuple[str, str] | None:
    """Extract (package_name, version) from a pinned arg like @scope/pkg@1.0.0 or pkg@2.1.0."""
    if arg.startswith("@"):
        # @scope/pkg@version — has 2+ @ signs
        if arg.count("@") >= 2:
            idx = arg.rindex("@")
            return arg[:idx], arg[idx + 1:]
    elif "@" in arg and not arg.startswith("-"):
        idx = arg.index("@")
        return arg[:idx], arg[idx + 1:]
    return None


def _severity_from_vuln(vuln: dict) -> Severity:
    # Try CVSS v3 score first
    for sev in vuln.get("severity", []):
        raw_score = sev.get("score", "")
        try:
            score = float(raw_score)
            if score >= 9.0:
                return Severity.CRITICAL
            if score >= 7.0:
                return Severity.HIGH
            if score >= 4.0:
                return Severity.MEDIUM
            return Severity.LOW
        except (ValueError, TypeError):
            pass

    # Fall back to database_specific severity string
    db_sev = vuln.get("database_specific", {}).get("severity", "")
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(str(db_sev).upper(), Severity.MEDIUM)


def _fix_version(vuln: dict) -> str:
    """Extract the first fix version from an OSV vuln object, if available."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return ""


def check_osv(server: MCPServer) -> list[Finding]:
    if not _HTTPX_AVAILABLE:
        return []

    ecosystem = _ecosystem(server)
    if not ecosystem:
        return []

    findings: list[Finding] = []

    for arg in server.args:
        if arg.startswith("-"):
            continue
        pkg_ver = _parse_package_version(arg)
        if not pkg_ver:
            continue  # skip unpinned packages

        package_name, version = pkg_ver
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.post(_OSV_URL, json={
                    "version": version,
                    "package": {"name": package_name, "ecosystem": ecosystem},
                })
            if resp.status_code != 200:
                continue
            vulns = resp.json().get("vulns", [])
        except Exception:
            continue  # Network unavailable or timeout — skip gracefully

        for vuln in vulns[:_MAX_FINDINGS_PER_PACKAGE]:
            vuln_id = vuln.get("id", "UNKNOWN")
            summary = vuln.get("summary", "No summary available.")
            severity = _severity_from_vuln(vuln)
            fix = _fix_version(vuln)
            fix_hint = f" Fix available in version `{fix}`." if fix else ""

            refs = vuln.get("references", [])
            ref_url = refs[0].get("url", f"https://osv.dev/vulnerability/{vuln_id}") if refs else f"https://osv.dev/vulnerability/{vuln_id}"

            findings.append(Finding(
                check_id="SC-004",
                title=f"CVE in `{package_name}@{version}`: {vuln_id}",
                detail=(
                    f"Server `{server.name}` uses `{package_name}@{version}` which has a known vulnerability: "
                    f"{vuln_id} — {summary}{fix_hint} "
                    "(Source: OSV.dev — open vulnerability database maintained by Google)"
                ),
                severity=severity,
                owasp=OWASPCategory.MCP04,
                server_name=server.name,
                remediation=(
                    f"Upgrade `{package_name}` to a non-vulnerable version.{fix_hint} "
                    f"See full details at: {ref_url}"
                ),
                engine="osv",
            ))

    return findings
