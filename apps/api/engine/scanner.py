import uuid
from datetime import datetime, timezone
from .models import Finding, Severity, ScanResult, ScanSummary, OWASPCategory, SEVERITY_SCORE_WEIGHTS
from .parser import MCPConfig
from .checks.secrets import _is_pinned, _is_package_arg
from .checks import (
    check_secrets,
    check_supply_chain,
    check_tool_poisoning,
    check_privilege,
    check_shadow,
    check_code_execution,
    check_osv,
    check_audit,
    check_lifecycle,
    check_config_level,
)

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_AT005_HIGH_SERVER_THRESHOLD = 10


def scan(config: MCPConfig) -> ScanResult:
    all_findings: list[Finding] = []
    # Collect per-server findings so config-level checks can cross-reference them
    per_server: dict[str, list[Finding]] = {}

    for server in config.servers:
        server_findings: list[Finding] = []
        server_findings.extend(check_secrets(server))
        server_findings.extend(check_supply_chain(server))
        server_findings.extend(check_tool_poisoning(server))
        server_findings.extend(check_privilege(server))
        server_findings.extend(check_shadow(server))
        server_findings.extend(check_code_execution(server))
        server_findings.extend(check_audit(server))
        server_findings.extend(check_lifecycle(server))
        # Network check (OSV.dev) — may add latency, fails gracefully if unavailable
        server_findings.extend(check_osv(server))

        per_server[server.name] = server_findings
        all_findings.extend(server_findings)

    # Config-level cross-server checks
    all_findings.extend(check_config_level(config, per_server))

    n = len(config.servers)

    # AT-001: Systemic absence of version pinning across the entire config
    if n >= 2:
        pinned_count = sum(1 for s in config.servers if _any_pinned(s))
        if pinned_count == 0:
            all_findings.append(Finding(
                check_id="AT-001",
                title="No version pinning across any configured server",
                detail=(
                    f"None of the {n} configured MCP server(s) pin their package versions. "
                    "Without version pins, every Claude Desktop or Cursor restart may silently pull a "
                    "different (potentially compromised) version of each server package."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.MCP08,
                server_name="(all servers)",
                remediation=(
                    "Pin all package versions in server args "
                    "(e.g., `@modelcontextprotocol/server-filesystem@1.2.3`). "
                    "This ensures reproducibility and protects against silent rug pulls."
                ),
                engine="custom",
            ))

    # AT-005: Excessive server count — each server is an independent entry point
    if n >= _AT005_HIGH_SERVER_THRESHOLD:
        all_findings.append(Finding(
            check_id="AT-005",
            title=f"Excessive MCP server count: {n} servers configured",
            detail=(
                f"This config registers {n} MCP servers. Each server is an independent process "
                "with its own tool set, permissions, and attack surface. "
                f"Configurations with {_AT005_HIGH_SERVER_THRESHOLD}+ servers are statistically "
                "more likely to contain at least one compromised or misconfigured server, "
                "and the total attack surface grows with each addition. "
                "Real-world research found that 70% of MCP servers have at least one security finding."
            ),
            severity=Severity.INFO,
            owasp=OWASPCategory.MCP08,
            server_name="(all servers)",
            remediation=(
                f"Audit each of the {n} servers and remove any that are no longer actively used. "
                "For each server, confirm you understand what permissions it has and why it needs them. "
                "A smaller, well-audited set of servers is safer than a large unreviewed collection."
            ),
            engine="custom",
        ))

    all_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        config_hash=config.config_hash,
        findings=all_findings,
        summary=_summarize(all_findings, n),
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )


def _any_pinned(server) -> bool:
    """True if the server has at least one package arg pinned to an exact semver."""
    for arg in server.args:
        if _is_package_arg(arg) and _is_pinned(arg):
            return True
    return False


def _risk_score(findings: list[Finding]) -> tuple[int, str]:
    """Return (0-100 risk score, A-F grade)."""
    raw = sum(SEVERITY_SCORE_WEIGHTS.get(f.severity.value, 0) for f in findings)
    score = min(100, raw)
    if score < 20:
        grade = "A"
    elif score < 40:
        grade = "B"
    elif score < 60:
        grade = "C"
    elif score < 80:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def _summarize(findings: list[Finding], server_count: int) -> ScanSummary:
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    owasp_hit: set[str] = set()
    for f in findings:
        counts[f.severity] += 1
        owasp_hit.add(f.owasp.value)
    score, grade = _risk_score(findings)
    return ScanSummary(
        total=len(findings),
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        info=counts[Severity.INFO],
        servers_scanned=server_count,
        owasp_coverage=sorted(owasp_hit),
        risk_score=score,
        risk_grade=grade,
    )
