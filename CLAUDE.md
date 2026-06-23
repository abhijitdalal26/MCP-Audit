# MCPAudit — MCP Security Platform

## What This Is
A web SaaS that audits Model Context Protocol (MCP) server configurations for security vulnerabilities. Users paste their `claude_desktop_config.json` or `.cursor/mcp.json` and receive a unified security report in under 30 seconds, with every finding mapped to the OWASP MCP Top 10.

## Project Structure
```
apps/web/              Next.js 15 + Shadcn/ui frontend
apps/api/              FastAPI (Python 3.12) backend — scan orchestrator
packages/cli/          Go CLI binary (cross-platform, single static binary)
packages/scan-engine/  Core Python scan engine (wraps mcp-audit + tooltrust)
.github/workflows/     CI/CD pipelines
docs/research/         Pre-build research (DO NOT delete — active reference)
```

## Key Architecture Decisions
- **FastAPI over Node.js**: mcp-audit is Python-native; wrapping in Python avoids translation friction
- **Inngest for job queue**: scans take 10–60s; Inngest is serverless-native, no Redis to manage
- **Go CLI**: single static binary, cross-platform, no runtime dependency — critical for pre-commit hooks
- **Wrap existing tools first**: subprocess calls to mcp-audit + tooltrust; custom proprietary checks in parallel
- **Supabase RLS**: Row Level Security ensures org scan isolation at DB level, not application level
- **Open scan engine / closed dashboard**: Socket.dev model — build community trust via OSS, monetize via SaaS

## Tech Stack
| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15 + App Router + Shadcn/ui + Tailwind |
| Backend | FastAPI (Python 3.12) + Pydantic v2 |
| Auth | Clerk (orgs, API keys, SAML SSO built-in) |
| Database | Supabase (PostgreSQL + RLS) |
| Job Queue | Inngest (serverless-native, step-level observability) |
| CLI | Go (single binary, Homebrew + npm + direct download) |
| CI | GitHub Actions Marketplace — SARIF output to GitHub Security tab |
| Payments | Stripe |
| Hosting | Vercel (frontend) + Railway (FastAPI workers) |
| Secrets scan | Regex (25+ patterns) via custom engine |
| Supply chain | OSV.dev API (Google-maintained CVE database) |

## Dev Commands
(Fill in as each layer is built)

## Security Check IDs
20 checks across 5 categories, all mapped to OWASP MCP Top 10:
- SEC-001 to SEC-006: Secrets & Credentials (MCP01)
- SC-001 to SC-004: Supply Chain (MCP04)
- PI-001 to PI-002: Tool Poisoning / Prompt Injection (MCP03, MCP06)
- PE-001 to PE-004: Privilege Escalation (MCP02, MCP07)
- SH-001 to SH-003: Shadow Servers (MCP09)
- AT-001: Audit & Telemetry (MCP08)

Full check specs in: docs/research/05_features_and_roadmap.md

## Build Order
1. **Stage 1 (MVP)**: Web paste-and-scan — Next.js + FastAPI + mcp-audit + tooltrust subprocess wrappers
2. **Stage 2**: Go CLI + GitHub Action + Clerk auth + Supabase scan history
3. **Stage 3**: Teams + Stripe (Free/Pro $25/Team $99) + scheduled scans + Slack alerts
4. **Stage 4**: LLM triage layer via Claude API — reduce ~78% false positive rate
5. **Stage 5**: VS Code extension (only if 500+ paying users or 100+ GitHub Action installs)

## What to Read Before Building Each Stage
Stage 1: `docs/research/02_social_demand.md` → `04_competitive_analysis.md` → `05_features_and_roadmap.md` → `03_tech_stack.md` → `01_existing_tools.md`

## Critical Risks to Watch
- Verify mcpscan.ai feature depth before building — if they already do paste-and-scan well, Stage 1 needs a differentiated angle
- mcp-audit and tooltrust update frequently — keep subprocess wrappers behind a thin abstraction layer
- OWASP MCP Top 10 category IDs may shift — store as strings, never hardcode as integers in DB schema
- Go CLI Windows ARM64 cross-compilation — test early, it catches most build issues
- Stripe India payout support — verify before going paid; fallback: Paddle or Lemon Squeezy

## Naming
Project name: **MCPAudit**
GitHub repo: `mcpaudit` (public)
Alternatives that were available at research time: MCPWatch, ToolSentry, MCPRadar, MCPShield, MCPSentinel
