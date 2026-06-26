# MCPAudit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-313%20passing-brightgreen)](apps/api/tests/)
[![Python](https://img.shields.io/badge/python-3.12-blue)](apps/api/)
[![OWASP MCP Top 10](https://img.shields.io/badge/OWASP%20MCP-Top%2010%20covered-red)](https://owasp.org/)

Security auditor for Model Context Protocol (MCP) server configurations. Paste your `claude_desktop_config.json` or `.cursor/mcp.json` — get a unified security report with every finding mapped to the **OWASP MCP Top 10**.

---

## What It Does

Every MCP server you add to Claude Desktop or Cursor gets access to your filesystem, shell, browser, or APIs. MCPAudit scans your config and tells you what risks each server introduces — before you trust it.

**50 checks across 11 modules:**

| Module | Check IDs | Category |
|--------|-----------|----------|
| `secrets.py` | SEC-001–007 | Hardcoded credentials, API keys, tokens, HTTP basic auth, cloud metadata endpoints (SSRF/IMDS) |
| `supply_chain.py` | SC-001–003, SC-005–007 | Malicious/typosquatted packages, GitHub ref deps, homoglyph names, registry override (Birsan attack) |
| `osv_lookup.py` | SC-004 | Live CVE lookup via OSV.dev |
| `tool_poisoning.py` | PI-001–005, DX-001 | Prompt injection, obfuscation, invisible Unicode, bidi overrides, data exfiltration |
| `privilege.py` | PE-001–008 | Overbroad filesystem, shell, Docker, sudo, permission bypass, path traversal |
| `shadow.py` | SH-001–006 | Unregistered servers, HTTP, homoglyphs, auto-discovery, unauthenticated SSE |
| `chain_analysis.py` | CHAIN-001–003 | Cross-server capability chains: write+exec (RCE), secrets+HTTP (exfil), amplified blast radius |
| `code_execution.py` | EX-001–003 | Inline code execution, command substitution, PowerShell encoded cmds, curl-pipe-bash |
| `audit.py` | AT-002–004 | Transport config, network binding (NeighborJack) |
| `lifecycle.py` | LF-001 | Postinstall script abuse |
| `config_level.py` | CL-001–004, EC-001 | Confused deputy, duplicate servers, security feature disable, autoApprove bypass, debug log exposure |
| `scanner.py` | AT-001, AT-005–006 | Version pinning audit, excessive server count, Docker image pinning |

Every finding includes: severity, OWASP MCP Top 10 category, CWE ID, MITRE ATT&CK tactic, and remediation guidance.

---

## Output Formats

| Format | Use Case |
|--------|----------|
| **JSON** | CI/CD integration, programmatic processing |
| **SARIF 2.1.0** | GitHub Security tab (uploads as code scanning alerts) |
| **CycloneDX 1.6 AI-BOM** | Supply chain compliance, SBOM workflows |

---

## API Endpoints

```
POST /scan          → JSON report
POST /scan/sarif    → SARIF 2.1.0
POST /scan/bom      → CycloneDX 1.6 AI-BOM
```

**Request body:**
```json
{ "config": "{ \"mcpServers\": { ... } }" }
```

**Example response:**
```json
{
  "scan_id": "abc123",
  "summary": {
    "total": 4,
    "critical": 1,
    "high": 2,
    "medium": 1,
    "risk_score": 47,
    "risk_grade": "C",
    "owasp_coverage": ["MCP01", "MCP04", "MCP09"]
  },
  "findings": [
    {
      "check_id": "SEC-001",
      "title": "AWS Access Key ID hardcoded in `AWS_ACCESS_KEY_ID`",
      "severity": "critical",
      "owasp": "MCP01",
      "cwe_id": "CWE-798",
      "remediation": "..."
    }
  ]
}
```

---

## Architecture

```
apps/web/           Next.js 15 frontend (minimal scan UI)
apps/api/           FastAPI backend
  main.py           API entrypoint
  engine/
    parser.py       JSONC-aware config parser (Claude Desktop + Cursor formats)
    scanner.py      Scan orchestrator + config-level checks
    models.py       Pydantic models (Finding, ScanResult, ScanSummary)
    sarif.py        SARIF 2.1.0 formatter (with CWE + ATT&CK)
    cyclonedx.py    CycloneDX 1.6 AI-BOM formatter
    checks/         41 check implementations
  tests/            292 tests (unit + property-based + real-world corpus)
packages/cli/       Go CLI binary (planned — Stage 2)
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15 + App Router + Tailwind |
| Backend | FastAPI (Python 3.12) + Pydantic v2 |
| CVE data | OSV.dev API (Google-maintained, no API key needed) |
| SARIF | 2.1.0 spec — GitHub Security tab compatible |
| AI-BOM | CycloneDX 1.6 |

---

## Running Locally

```bash
# API
cd apps/api
python -m venv .venv
.venv/Scripts/pip install -r requirements-dev.txt
uvicorn main:app --reload --port 8000

# Tests
.venv/Scripts/pytest tests/ -v    # 313 tests

# Frontend
cd apps/web
npm install && npm run dev         # → http://localhost:3000
```

---

## OWASP MCP Top 10 Coverage

All 10 categories covered:

| Category | Description | Checks |
|----------|-------------|--------|
| MCP01 | Token Mismanagement & Secret Exposure | SEC-001–007, EC-001 |
| MCP02 | Privilege Escalation via Scope Creep | PE-001–007, CL-001 |
| MCP03 | Tool Poisoning | PI-001–004, DX-001, SH-004, CL-002 |
| MCP04 | Supply Chain Attacks | SC-001–007, LF-001 |
| MCP05 | Command Injection & Execution | EX-001–002, PE-005 |
| MCP06 | Prompt Injection via Contextual Payloads | PI-002 |
| MCP07 | Insufficient Authentication | SH-002, SH-006, CL-003, CL-004 |
| MCP08 | Lack of Audit and Telemetry | AT-001–005 |
| MCP09 | Shadow MCP Servers | SH-001, SH-003, SH-005 |
| MCP10 | Context Injection & Over-Sharing | PE-004 |

---

## Scope & Limitations

MCPAudit is a **static config scanner**. It analyzes the JSON you paste — it does not connect to live MCP servers unless you explicitly add that in a future release.

| Capability | Status |
|------------|--------|
| Claude Desktop / Cursor `mcpServers` JSON | Supported (including JSONC comments) |
| `autoApprove`, `disabled`, `headers` | Supported |
| Secret / supply-chain / privilege checks on config fields | Supported |
| SARIF 2.1.0 + CycloneDX 1.6 AI-BOM export | Supported |
| Live tool description fetch (runtime MCP connection) | Not yet — static args/env only |
| MCP server source-code scanning | Not yet — use [mcp-audit source-scan](https://github.com/apisec-inc/mcp-audit) |
| CVE lookup (SC-004) | Requires pinned package versions |
| `SH-001` unverified package | INFO severity — flags packages outside the verified allowlist, not proof of malice |

Disabled servers (`"disabled": true`) are skipped during scanning.

---

## Contributing

Issues and pull requests are welcome. Before submitting a new check:

1. Identify the OWASP MCP Top 10 category it maps to
2. Write tests first (check the existing test structure in `apps/api/tests/`)
3. Keep false-positive rate low — include at least one "should not flag" test case
4. Add a CWE ID and remediation guidance to the Finding

---

## License

MIT — see [LICENSE](LICENSE).
