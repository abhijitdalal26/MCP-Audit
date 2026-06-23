"""
SARIF 2.1.0 output formatter.
Converts a ScanResult into a SARIF document for GitHub Security tab integration.
"""
from .models import ScanResult, Finding, Severity

_SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "none",
}

_SEVERITY_TO_SECURITY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.8",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "0.0",
}


def to_sarif(result: ScanResult, config_path: str = "mcp.json") -> dict:
    rules: list[dict] = []
    rule_ids_seen: set[str] = set()

    for finding in result.findings:
        if finding.check_id not in rule_ids_seen:
            rule_ids_seen.add(finding.check_id)
            rules.append({
                "id": finding.check_id,
                "name": _check_id_to_name(finding.check_id),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.detail},
                "helpUri": f"https://mcpaudit.app/checks/{finding.check_id}",
                "properties": {
                    "tags": [finding.owasp.value, "security", "mcp"]
                        + ([finding.cwe_id] if finding.cwe_id else []),
                    "security-severity": _SEVERITY_TO_SECURITY_SEVERITY[finding.severity],
                    "precision": "high",
                    "problem.severity": finding.severity.value,
                },
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
                },
            })

    results: list[dict] = []
    for i, finding in enumerate(result.findings):
        results.append({
            "ruleId": finding.check_id,
            "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
            "message": {
                "text": f"{finding.title}\n\n{finding.detail}\n\nRemediation: {finding.remediation}"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": config_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": 1,
                            "startColumn": 1,
                        },
                    },
                    "logicalLocations": [
                        {
                            "name": finding.server_name,
                            "kind": "member",
                            "fullyQualifiedName": f"mcpServers.{finding.server_name}",
                        }
                    ],
                }
            ],
            "properties": {
                "owasp": finding.owasp.value,
                "server": finding.server_name,
                "engine": finding.engine,
                **({"cwe": finding.cwe_id} if finding.cwe_id else {}),
                **({"attackTactic": finding.attack_tactic} if finding.attack_tactic else {}),
            },
            "fingerprints": {
                "mcpAudit/v1": f"{result.config_hash}/{finding.check_id}/{finding.server_name}/{i}",
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPAudit",
                        "version": "0.1.0",
                        "informationUri": "https://mcpaudit.app",
                        "rules": rules,
                    }
                },
                "results": results,
                "automationDetails": {
                    "id": result.scan_id,
                    "description": {
                        "text": f"MCPAudit scan {result.scan_id} — {len(result.findings)} findings across {result.summary.servers_scanned} server(s)"
                    },
                },
                "versionControlProvenance": [],
            }
        ],
    }


def _check_id_to_name(check_id: str) -> str:
    prefixes = {
        "SEC": "SecretExposure",
        "SC": "SupplyChain",
        "PI": "PromptInjection",
        "DX": "DataExfiltration",
        "PE": "PrivilegeEscalation",
        "SH": "ShadowServer",
        "AT": "AuditTelemetry",
        "EX": "CodeExecution",
        "LF": "LifecycleScript",
        "CL": "ConfigLevel",
        "EC": "EnvironmentConfig",
    }
    prefix = check_id.split("-")[0]
    suffix = check_id.split("-")[1] if "-" in check_id else ""
    return prefixes.get(prefix, "SecurityCheck") + suffix
