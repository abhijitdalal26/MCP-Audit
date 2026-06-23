# MCPAudit

Security auditor for Model Context Protocol (MCP) server configurations. Paste your `claude_desktop_config.json` or `.cursor/mcp.json` — get a unified security report with every finding mapped to the **OWASP MCP Top 10**.

---

## What It Does

Every MCP server you add to Claude Desktop or Cursor gets access to your filesystem, shell, browser, or APIs. MCPAudit checks your config before you trust anything.

**33 checks across 10 modules:**

| Module | Check IDs | Category |
|--------|-----------|----------|
| `secrets.py` | SEC-001–006 | Hardcoded credentials, API keys, tokens |
| `supply_chain.py` | SC-001–003, SC-005 | Malicious/typosquatted packages, GitHub ref deps |
| `osv_lookup.py` | SC-004 | Live CVE lookup via OSV.dev |
| `tool_poisoning.py` | PI-001–003, DX-001 | Prompt injection, data exfiltration patterns |
| `privilege.py` | PE-001–004 | Overbroad filesystem, shell access, admin creds |
| `shadow.py` | SH-001–005 | Unregistered servers, HTTP, homoglyphs, auto-discovery |
| `code_execution.py` | EX-001–002 | Inline code execution, command substitution |
| `audit.py` | AT-002–004 | Transport config, network binding (NeighborJack) |
| `lifecycle.py` | LF-001 | Postinstall script abuse |
| `config_level.py` | CL-001–002, EC-001 | Config-wide issues, duplicate servers |
| `scanner.py` | AT-001 | Version pinning audit |

All findings include severity, OWASP MCP Top 10 category, CWE ID, MITRE ATT&CK tactic, and remediation guidance.

---

## Output Formats

- **JSON** — full scan result with all findings
- **SARIF 2.1.0** — GitHub Security tab compatible (uploads as code scanning alerts)
- **CycloneDX 1.6 AI-BOM** — supply chain compliance

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

---

## Architecture

```
apps/web/           Next.js 15 frontend (minimal scan UI)
apps/api/           FastAPI backend
  main.py           API entrypoint
  engine/
    parser.py       JSONC-aware config parser (Claude Desktop + Cursor formats)
    scanner.py      Scan orchestrator
    models.py       Pydantic models (Finding, ScanResult, ScanSummary)
    sarif.py        SARIF 2.1.0 formatter
    cyclonedx.py    CycloneDX 1.6 AI-BOM formatter
    checks/         33 check implementations
  tests/            133 tests (unit + property-based + real-world corpus)
packages/cli/       Go CLI binary (planned)
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15 + App Router + Tailwind |
| Backend | FastAPI (Python 3.12) + Pydantic v2 |
| CVE data | OSV.dev API (Google-maintained, no API key) |
| SARIF | 2.1.0 spec — GitHub Security tab compatible |
| AI-BOM | CycloneDX 1.6 |

---

## Running Locally

```bash
# API
cd apps/api
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt
uvicorn main:app --reload --port 8000

# Tests (133/133)
.venv/Scripts/pytest tests/ -v

# Frontend
cd apps/web
npm install && npm run dev   # → http://localhost:3000
```

---

## OWASP MCP Top 10 Coverage

All 10 categories covered: MCP01 (Token Mismanagement) · MCP02 (Privilege Escalation) · MCP03 (Tool Poisoning) · MCP04 (Supply Chain) · MCP05 (Command Injection) · MCP06 (Prompt Injection) · MCP07 (Insufficient Auth) · MCP08 (Audit & Telemetry) · MCP09 (Shadow Servers) · MCP10 (Context Over-Sharing)
