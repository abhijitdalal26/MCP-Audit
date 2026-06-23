# MCPAudit — MCP Security Platform

## What This Is
A web SaaS that audits Model Context Protocol (MCP) server configurations for security vulnerabilities. Users paste their `claude_desktop_config.json` or `.cursor/mcp.json` and receive a unified security report in under 30 seconds, with every finding mapped to the OWASP MCP Top 10.

## Current State (2026-06-23)
- **Engine**: 34 check IDs across 10 modules, 153/153 tests passing
- **API**: FastAPI with `/scan`, `/scan/sarif`, `/scan/bom` endpoints
- **Frontend**: Next.js minimal UI with risk grade (A-F) display
- **Output formats**: JSON, SARIF 2.1.0 (with CWE IDs + ATT&CK tactics), CycloneDX 1.6 AI-BOM
- **OWASP coverage**: 10/10 MCP Top 10 categories

## Project Structure
```
apps/web/                  Next.js 15 frontend (minimal scan UI)
apps/api/                  FastAPI backend
  main.py                  API entrypoint — /scan, /scan/sarif, /scan/bom
  engine/
    parser.py              MCPConfig parser (claude_desktop + cursor formats)
    scanner.py             Scan orchestrator
    models.py              Pydantic models (Finding, ScanResult, ScanSummary)
    sarif.py               SARIF 2.1.0 output formatter
    cyclonedx.py           CycloneDX 1.6 AI-BOM output formatter
    checks/
      secrets.py           SEC-001–006 (25+ patterns)
      supply_chain.py      SC-001–003, SC-005
      tool_poisoning.py    PI-001–003, DX-001
      privilege.py         PE-001–005
      shadow.py            SH-001–005
      code_execution.py    EX-001–002
      osv_lookup.py        SC-004 (OSV.dev live CVE)
      audit.py             AT-002–004
      lifecycle.py         LF-001
      config_level.py      CL-001–002, EC-001
  tests/
    test_secrets.py        14 secret pattern tests
    test_engine.py         30 engine unit/integration tests
    test_shadow_audit.py   12 shadow/audit/SARIF tests
    test_advanced.py       14 lifecycle/risk-score/CycloneDX tests
    test_config_level.py   8 config-level checks tests
    test_new_checks.py     44 tests for SH-004/005, SC-005, AT-004, PE-005, CWE IDs
packages/cli/              Go CLI binary (NOT YET BUILT — Stage 2)
```

## Key Architecture Decisions
- **FastAPI over Node.js**: mcp-audit is Python-native; wrapping in Python avoids translation friction
- **Custom engine first, tool wrappers later**: All 29 checks are proprietary; subprocess wrapping of mcp-audit/tooltrust planned for Stage 2
- **Engine in apps/api/engine/ (not packages/)**: Simpler imports for MVP; extract to packages/ in Stage 2
- **SARIF output built-in**: Enables GitHub Security tab integration without extra tooling
- **CycloneDX AI-BOM built-in**: Enables supply chain compliance workflows

## Tech Stack
| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15 + App Router + Tailwind |
| Backend | FastAPI (Python 3.12) + Pydantic v2 + httpx |
| Auth | Clerk (planned — Stage 2) |
| Database | Supabase (planned — Stage 2) |
| CLI | Go (planned — Stage 2) |
| CVE data | OSV.dev API (Google-maintained, no API key) |
| SARIF | 2.1.0 spec — GitHub Security tab compatible |
| AI-BOM | CycloneDX 1.6 |

## Dev Commands
```bash
# API
cd apps/api
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt
uvicorn main:app --reload --port 8000

# Tests (78/78)
.venv/Scripts/pytest tests/ -v

# Frontend
cd apps/web
npm install && npm run dev   # → http://localhost:3000
```

## Security Check IDs (29 total)
All checks mapped to OWASP MCP Top 10:

| Module | IDs | OWASP |
|---|---|---|
| secrets.py | SEC-001–006 | MCP01, MCP04 |
| supply_chain.py | SC-001–003, SC-005 | MCP04 |
| osv_lookup.py | SC-004 | MCP04 |
| tool_poisoning.py | PI-001–003, DX-001 | MCP03, MCP06 |
| privilege.py | PE-001–005 | MCP02, MCP05, MCP10 |
| shadow.py | SH-001–005 | MCP03, MCP07, MCP09 |
| code_execution.py | EX-001–002 | MCP05 |
| audit.py | AT-002–004 | MCP08 |
| lifecycle.py | LF-001 | MCP04 |
| config_level.py | CL-001–002, EC-001 | MCP02, MCP03, MCP01 |
| scanner.py | AT-001 | MCP08 |

Full check specs: documentaion/progress/builds_log.md (not in git — Obsidian vault)

## Build Order
1. **Stage 1 (MVP — current)**: Web paste-and-scan — 29 checks, SARIF, AI-BOM
2. **Stage 2**: Go CLI + GitHub Action + Clerk auth + Supabase scan history + tooltrust subprocess wrapper
3. **Stage 3**: Teams + Stripe + scheduled scans + Slack alerts
4. **Stage 4**: LLM triage (Claude API) — semantic analysis of tool descriptions; eBPF dynamic sandbox
5. **Stage 5**: Enterprise — SIEM integration, on-prem agent, compliance reports

## Critical Risks to Watch
- OWASP MCP Top 10 category IDs may shift — store as strings, never hardcode as integers in DB schema
- OSV.dev SC-004 adds latency (3s timeout) — move to async background job in Stage 2
- LF-001 may have high false positive rate for packages that legitimately need lifecycle scripts
- Go CLI Windows ARM64 cross-compilation — test early
- Stripe India payout support — verify before going paid; fallback: Paddle or Lemon Squeezy
- tooltrust updates daily (v0.3.19 as of June 2026) — pin version when wrapping as subprocess

## Naming
Project name: **MCPAudit** | GitHub: `abhijitdalal26/MCP-Audit` (public)

## Important: Directory Rules
- `documentaion/` — NEVER push to GitHub (in .gitignore). Never modify `documentaion/research/`.
- `docs/research/` — git-tracked copy of research (read-only reference)
