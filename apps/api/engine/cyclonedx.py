"""
CycloneDX 1.6 AI-BOM (Artificial Intelligence Bill of Materials) output formatter.
Produces an SBOM-compatible document documenting MCP server components.
"""
from datetime import datetime, timezone
from .models import ScanResult, Severity
from .parser import MCPConfig


def to_cyclonedx(result: ScanResult, config: MCPConfig) -> dict:
    now = datetime.now(timezone.utc).isoformat()

    components: list[dict] = []
    for server in config.servers:
        package = _extract_package(server)
        comp: dict = {
            "type": "library",
            "bom-ref": f"mcp-server:{server.name}",
            "name": server.name,
            "description": f"MCP server — command: {server.command or 'n/a'}",
            "properties": [
                {"name": "mcp:transport", "value": server.transport or "stdio"},
                {"name": "mcp:command", "value": server.command or ""},
            ],
        }

        if package:
            pkg_name, pkg_version = _split_package(package)
            comp["purl"] = _build_purl(server, pkg_name, pkg_version)
            if pkg_name:
                comp["name"] = pkg_name
            if pkg_version:
                comp["version"] = pkg_version
            else:
                comp["version"] = "unpinned"
                comp["properties"].append(
                    {"name": "mcp:version-pinned", "value": "false"}
                )

        if server.url:
            comp["properties"].append({"name": "mcp:url", "value": server.url})

        # Map findings to vulnerabilities section
        server_findings = [f for f in result.findings if f.server_name == server.name]
        if server_findings:
            comp["properties"].append(
                {"name": "mcp:finding-count", "value": str(len(server_findings))}
            )

        components.append(comp)

    # Collect vulnerabilities from scan result
    vulnerabilities: list[dict] = []
    for finding in result.findings:
        vuln: dict = {
            "bom-ref": f"vuln:{finding.check_id}:{finding.server_name}",
            "id": finding.check_id,
            "source": {
                "name": "MCPAudit",
                "url": f"https://mcpaudit.app/checks/{finding.check_id}",
            },
            "ratings": [
                {
                    "source": {"name": "MCPAudit"},
                    "severity": finding.severity.value,
                }
            ],
            "description": finding.detail,
            "recommendation": finding.remediation,
            "properties": [
                {"name": "owasp-mcp", "value": finding.owasp.value},
                {"name": "mcp:server", "value": finding.server_name},
                {"name": "mcp:engine", "value": finding.engine},
            ],
            "affects": [
                {
                    "ref": f"mcp-server:{finding.server_name}",
                }
            ],
        }
        if finding.attack_tactic:
            vuln["properties"].append({"name": "attack:tactic", "value": finding.attack_tactic})
        vulnerabilities.append(vuln)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{result.scan_id}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "type": "application",
                    "vendor": "MCPAudit",
                    "name": "MCPAudit",
                    "version": "0.1.0",
                    "externalReferences": [
                        {"type": "website", "url": "https://mcpaudit.app"}
                    ],
                }
            ],
            "component": {
                "type": "application",
                "name": "MCP Configuration",
                "description": f"Scanned MCP config — hash {result.config_hash}",
                "properties": [
                    {"name": "mcp:servers-count", "value": str(result.summary.servers_scanned)},
                    {"name": "mcp:scan-id", "value": result.scan_id},
                ],
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


def _extract_package(server) -> str | None:
    if server.command in ("npx", "npm", "uvx", "pip", "pip3"):
        for arg in server.args:
            if not arg.startswith("-"):
                return arg
    return None


def _split_package(package: str) -> tuple[str, str]:
    if package.startswith("@"):
        parts = package.split("@")
        if len(parts) >= 3:
            name = "@" + parts[1]
            if "/" in parts[1]:
                name = "@" + parts[1]
            version = parts[2] if len(parts) > 2 else ""
            return name, version
        return package, ""
    if "@" in package:
        idx = package.index("@")
        return package[:idx], package[idx + 1:]
    return package, ""


def _build_purl(server, pkg_name: str, pkg_version: str) -> str:
    if server.command in ("npx", "npm"):
        ecosystem = "npm"
    elif server.command in ("uvx", "pip", "pip3"):
        ecosystem = "pypi"
    else:
        return ""
    version_part = f"@{pkg_version}" if pkg_version else ""
    # URL-encode @ in scoped npm package names
    encoded_name = pkg_name.replace("@", "%40").replace("/", "%2F") if pkg_name.startswith("@") else pkg_name
    return f"pkg:{ecosystem}/{encoded_name}{version_part}"
