# MCPAudit — MCP Security Platform

## What This Is
A web SaaS that audits Model Context Protocol (MCP) server configurations for security vulnerabilities. Users paste their `claude_desktop_config.json` or `.cursor/mcp.json` and receive a unified security report in under 30 seconds, with every finding mapped to the OWASP MCP Top 10.

## Current State (2026-06-28)
- **Engine (Python)**: 51 check IDs across 11 modules, 313/313 tests passing — powers web UI at mcpaudit.app
- **Engine (Go)**: All 51 checks ported to Go at `packages/cli/internal/engine/` — 222/222 tests passing, fully offline
- **Research**: 2 research threads complete in `docs/security-research/` — see `docs/security-research/RESEARCH_INDEX.md`
- **API**: FastAPI with `/scan`, `/scan/sarif`, `/scan/bom` endpoints
- **Frontend**: Next.js redesigned UI — sticky header, OWASP coverage grid, severity bar, findings grouped by server with CWE/ATT&CK shown, CLI section
- **CLI**: Go binary at `packages/cli/` — **offline by default** (zero data sent), `--api-url` opt-in for remote API, text/json/sarif/bom output, `--fail-on` for CI gating, `--no-network` for fully air-gapped use, `mcpaudit scan` (no args) auto-detects Claude Desktop / Cursor config
- **Output formats**: JSON, SARIF 2.1.0 (with CWE IDs + ATT&CK tactics), CycloneDX 1.6 AI-BOM
- **OWASP coverage**: 10/10 MCP Top 10 categories
- **Claude Desktop config path (Windows)**: `C:\Users\abhijit\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json`

## Project Structure
```
apps/web/                  Next.js 15 frontend (redesigned — OWASP grid, severity bar, grouped findings)
packages/cli/              Go CLI binary (mcpaudit) — OFFLINE by default, --api-url for remote
  main.go                  Entrypoint
  cmd/                     Cobra commands: scan, version
  internal/client/         HTTP client wrapping /scan, /scan/sarif, /scan/bom (remote mode only)
  internal/output/         text (colored terminal) + json formatters
  internal/engine/         Go offline engine — 51 checks, zero network by default
    engine.go              Public API: Scan(), ScanToSARIF(), ScanToBOM()
    scanner.go             Orchestrator + AT-001/005/006 + risk score + severity sort
    sarif.go               SARIF 2.1.0 output formatter
    cyclonedx.go           CycloneDX 1.6 AI-BOM output formatter
    models/models.go       Finding, ScanResult, ScanSummary (json-tagged, matches Python API)
    parser/parser.go       JSONC parser + MCPConfig extraction
    checks/                11 check modules (51 checks total)
  Makefile                 build / cross / test targets
  go.mod, go.sum           Dependencies: cobra v1.8, fatih/color v1.17, google/uuid v1.6
apps/api/                  FastAPI backend
  main.py                  API entrypoint — /scan, /scan/sarif, /scan/bom
  engine/
    parser.py              MCPConfig parser (claude_desktop + cursor formats)
    scanner.py             Scan orchestrator
    models.py              Pydantic models (Finding, ScanResult, ScanSummary)
    sarif.py               SARIF 2.1.0 output formatter
    cyclonedx.py           CycloneDX 1.6 AI-BOM output formatter
    checks/
      secrets.py           SEC-001–007 (includes HTTP basic auth + cloud metadata endpoint)
      supply_chain.py      SC-001–003, SC-005–007 (uv run --with, homoglyphs, registry override)
      tool_poisoning.py    PI-001–005, DX-001 (both scan args + env var values)
      privilege.py         PE-001–008 (incl. sudo/elevated cmds, permission bypass, path traversal)
      shadow.py            SH-001–006 (incl. unauthenticated SSE endpoint)
      code_execution.py    EX-001–003 (+ PowerShell encoded cmd + curl|bash)
      osv_lookup.py        SC-004 (OSV.dev live CVE)
      audit.py             AT-002–004
      lifecycle.py         LF-001
      config_level.py      CL-001–003, EC-001 (+ security feature disable detection)
      chain_analysis.py    CHAIN-001–003 (cross-server capability chain analysis)
  tests/
    test_secrets.py        14 secret pattern tests
    test_engine.py         30 engine unit/integration tests
    test_shadow_audit.py   12 shadow/audit/SARIF tests
    test_advanced.py       14 lifecycle/risk-score/CycloneDX tests
    test_config_level.py   8 config-level checks tests
    test_new_checks.py     44 tests for SH-004/005, SC-005, AT-004, PE-005, CWE IDs
    test_approval_headers.py  approval-headers tests (new, unstaged)
packages/cli/              Go CLI binary (built — thin HTTP client, see offline note below)
docs/
  vault/                   Obsidian workspace — personal notes, build logs (gitignored)
  product-research/        Pre-build strategy/competitive research markdown (gitignored)
  security-research/       Technical research modules — unicode steganography, cross-server chains (gitignored)
  specs/                   Canonical check specifications — git-tracked
    checks-reference.md    All 51 check IDs: severity, OWASP, CWE, description
  architecture/            ADRs and system design docs — git-tracked
    EXECUTION-PLAN.md      Master plan for website + CLI execution (read this before starting Phase 2+)
    ADR-001-website-design.md   Tool-first single-page design decision
    ADR-002-deployment.md  Vercel (web) + Railway (API) deployment strategy
    ADR-003-cli-design.md  Go thin HTTP client CLI architecture
```

## Key Architecture Decisions
- **FastAPI over Node.js**: mcp-audit is Python-native; wrapping in Python avoids translation friction
- **Custom engine first, tool wrappers later**: All 51 checks are proprietary; subprocess wrapping of mcp-audit/tooltrust planned for Stage 2
- **Engine in apps/api/engine/ (not packages/)**: Simpler imports for MVP; extract to packages/ in Stage 2
- **SARIF output built-in**: Enables GitHub Security tab integration without extra tooling
- **CycloneDX AI-BOM built-in**: Enables supply chain compliance workflows

## CLI Offline Mode — Critical Roadmap Item
**Current problem:** The CLI sends the user's config (which may contain secrets) to the remote API to run checks. For a security tool this is a trust contradiction — users are asked to send their AWS keys and DB passwords to a third-party server.

**Industry standard:** Every major security CLI (Trivy, Grype, Gitleaks, Trufflehog, osv-scanner) runs fully offline. All written in Go. Single static binary, no network required, no data leaves the machine.

**Target state:** Port the 51 Python checks to Go so the CLI runs entirely locally.
```
Current:  CLI (Go) → network → API (Python) → engine runs → results back
Target:   CLI (Go) → engine runs locally → results  ← zero network, zero data sent
```

**Why Go (not TypeScript) for the engine port:**
- Single static binary, no runtime dependency
- Cross-compiles to linux/darwin/windows/arm64 trivially
- Fast startup (<50ms vs Node's ~500ms) — matters for CI
- Industry standard: Trivy, Grype, Nuclei, Gitleaks, Trufflehog, osv-scanner are all Go
- TypeScript requires Node runtime — a supply chain risk ironic for a security tool

**Migration path (Stage 2):**
1. Port engine checks to Go in `packages/cli/internal/engine/`
2. CLI detects no `--api-url` flag → runs local engine
3. Keep Python API for the web UI (web users still send data, but add explicit privacy notice)
4. Add `--offline` flag as explicit local-only mode

**Web UI privacy note to add:** A one-liner under the textarea — "Your config is processed on our server and not stored. For sensitive configs, use the CLI which runs locally."

## Tech Stack
| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15 + App Router + Tailwind |
| Backend | FastAPI (Python 3.12) + Pydantic v2 + httpx |
| Auth | Clerk (planned — Stage 2) |
| Database | Supabase (planned — Stage 2) |
| CLI | Go (built — thin HTTP client; offline engine port is Stage 2) |
| CVE data | OSV.dev API (Google-maintained, no API key) |
| SARIF | 2.1.0 spec — GitHub Security tab compatible |
| AI-BOM | CycloneDX 1.6 |

## Dev Commands
```bash
# API
cd apps/api
python -m venv .venv && .venv/Scripts/pip install -r requirements-dev.txt
uvicorn main:app --reload --port 8000

# Tests (313/313)
.venv/Scripts/pytest tests/ -v

# Frontend
cd apps/web
npm install && npm run dev   # → http://localhost:3000

# CLI (Go — requires Go 1.22+, installed at C:\Users\abhijit\AppData\Local\go\bin\go.exe)
cd packages/cli
go build -ldflags="-X main.Version=0.1.0" -o bin/mcpaudit.exe .
go test ./...
./bin/mcpaudit.exe scan <config.json> --api-url http://localhost:8000
```

## Security Check IDs (51 total)
All checks mapped to OWASP MCP Top 10:

| Module | IDs | OWASP |
|---|---|---|
| secrets.py | SEC-001–008 (incl. HTTP basic auth, IMDS endpoints, credentials in URL) | MCP01, MCP04 |
| supply_chain.py | SC-001–003, SC-005–007 (uv run --with, homoglyphs, registry override) | MCP04 |
| osv_lookup.py | SC-004 | MCP04 |
| tool_poisoning.py | PI-001–005, DX-001 (incl. invisible Unicode, env var scan) | MCP03, MCP06 |
| privilege.py | PE-001–009 (incl. path traversal, permission bypass, sudo, dangerous Docker caps) | MCP02, MCP05, MCP10 |
| shadow.py | SH-001–006 (incl. unauthenticated SSE endpoint detection) | MCP03, MCP07, MCP09 |
| code_execution.py | EX-001–003 (incl. PowerShell encoded cmd, curl|bash) | MCP05 |
| audit.py | AT-002–004 | MCP08 |
| lifecycle.py | LF-001 | MCP04 |
| config_level.py | CL-001–003, EC-001 (incl. TLS bypass, auth disable) | MCP02, MCP03, MCP01, MCP07 |
| scanner.py | AT-001, AT-005, AT-006 (Docker image tag pinning) | MCP08, MCP04 |
| chain_analysis.py | CHAIN-001–003 | MCP02 |

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

## Documentation Directory Guide
All documentation lives under `docs/`. Each subdirectory has a specific purpose — write new content in the right place:

| Directory | Git? | Purpose — what goes here |
|---|---|---|
| `docs/vault/` | No | Obsidian personal workspace — build logs, session notes, findings, raw ideas. NEVER modify or delete anything here. |
| `docs/product-research/` | No | Pre-build research reference — competitive analysis, naming, pitch, tech stack decisions, roadmap (00–10 markdown files). Read-only reference. |
| `docs/security-research/` | No | Technical security research that fed into check implementations — unicode steganography, cross-server chain analysis (Python + RESEARCH.md). |
| `docs/specs/` | Yes | Canonical check specifications — document each check ID (what it fires on, CWE mapping, OWASP category, false positive guidance). Add a file per module or per check. |
| `docs/architecture/` | Yes | Architecture decision records (ADRs), system design docs, data flow diagrams, stage roadmap rationale. |

**Rule:** If it's a personal note or reference → `vault/`. If it's a check definition → `specs/`. If it's a design decision → `architecture/`.
