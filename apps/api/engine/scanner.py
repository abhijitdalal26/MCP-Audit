import uuid
from datetime import datetime, timezone
from .models import Finding, Severity, ScanResult, ScanSummary, OWASPCategory
from .parser import MCPConfig
from .checks import (
    check_secrets,
    check_supply_chain,
    check_tool_poisoning,
    check_privilege,
    check_shadow,
    check_code_execution,
    check_osv,
)

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def scan(config: MCPConfig) -> ScanResult:
    all_findings: list[Finding] = []

    for server in config.servers:
        # Core static checks (fast, no network)
        all_findings.extend(check_secrets(server))
        all_findings.extend(check_supply_chain(server))
        all_findings.extend(check_tool_poisoning(server))
        all_findings.extend(check_privilege(server))
        all_findings.extend(check_shadow(server))
        all_findings.extend(check_code_execution(server))
        # Network check (OSV.dev) — may add latency, fails gracefully if unavailable
        all_findings.extend(check_osv(server))

    # AT-001: Systemic absence of version pinning across the entire config
    if len(config.servers) >= 2:
        pinned_count = sum(1 for s in config.servers if _any_pinned(s))
        if pinned_count == 0:
            all_findings.append(Finding(
                check_id="AT-001",
                title="No version pinning across any configured server",
                detail=(
                    f"None of the {len(config.servers)} configured MCP server(s) pin their package versions. "
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

    all_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        config_hash=config.config_hash,
        findings=all_findings,
        summary=_summarize(all_findings, len(config.servers)),
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )


def _any_pinned(server) -> bool:
    for arg in server.args:
        if arg.startswith("@") and arg.count("@") >= 2:
            return True
        if not arg.startswith("@") and not arg.startswith("-") and "@" in arg:
            return True
    return False


def _summarize(findings: list[Finding], server_count: int) -> ScanSummary:
    counts: dict[Severity, int] = {s: 0 for s in Severity}
    owasp_hit: set[str] = set()
    for f in findings:
        counts[f.severity] += 1
        owasp_hit.add(f.owasp.value)
    return ScanSummary(
        total=len(findings),
        critical=counts[Severity.CRITICAL],
        high=counts[Severity.HIGH],
        medium=counts[Severity.MEDIUM],
        low=counts[Severity.LOW],
        info=counts[Severity.INFO],
        servers_scanned=server_count,
        owasp_coverage=sorted(owasp_hit),
    )
