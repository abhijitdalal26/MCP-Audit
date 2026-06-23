# MCPAudit — MCP Security Platform

> Paste your MCP config. Get a security report in 30 seconds.

MCPAudit audits Model Context Protocol (MCP) server configurations for security vulnerabilities — secrets exposure, supply chain risks, privilege escalation, prompt injection, and more — with every finding mapped to the **OWASP MCP Top 10**.

---

## The Problem

Every time you add an MCP server to Claude Desktop, Cursor, or Windsurf, you're granting that server access to your filesystem, shell, browser, or APIs. Most people paste the config JSON from a README without knowing what they're actually trusting.

The numbers make this urgent:
- **8,000+** publicly exposed MCP servers with no authentication (Censys, 2026)
- **40+ CVEs** filed against MCP implementations in the first 60 days of 2026
- **106 zero-days** found across 39,884 MCP repositories (academic study)
- **150M+** affected downloads across vulnerable MCP packages
- NSA, DoD, and OWASP have all published formal MCP security guidance in 2026
- The 4 existing open-source audit tools have no web UI and ~78% false positive rates

---

## What MCPAudit Does

Paste your `claude_desktop_config.json` or `.cursor/mcp.json` — get a unified, actionable security report in under 30 seconds. No install required for the free tier.

### 20 Security Checks Across 5 Categories

| Category | Checks | OWASP Mapping |
|----------|--------|---------------|
| **Secrets & Credentials** | AWS keys, GitHub PATs, database URLs, API keys, JWT secrets, unpinned versions | MCP01 |
| **Supply Chain** | CVE scan via OSV.dev, typosquatting detection, unverified packages, known-malicious packages | MCP04 |
| **Tool Poisoning & Prompt Injection** | Suspicious tool description keywords, hidden instructions, excessively long descriptions | MCP03, MCP06 |
| **Privilege Escalation** | Over-broad filesystem access, shell execution, admin credential patterns, DB write access | MCP02, MCP07 |
| **Shadow Servers** | Unregistered servers, HTTP without TLS, package/transport mismatch | MCP09 |

---

## Who It's For

| Audience | Problem | Solution |
|----------|---------|----------|
| **AI tool users** (Claude Desktop, Cursor, Windsurf) | "Is this MCP server safe to install?" | Paste-and-scan in 30 seconds, no account needed |
| **MCP server builders** | "Is my server safe to publish?" | Pre-publish audit + OWASP compliance report + security badge |
| **Security teams** | "What do our developers have installed?" | Team dashboard + GitHub Action CI gate + SARIF output |

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Web App (Next.js 15)  │  CLI (Go)  │  GitHub Action │
└──────────────┬──────────────────────────────────────┘
               │
       FastAPI Backend (Python 3.12)
               │
    ┌──────────┴──────────┐
    │    Scan Engines      │
    ├──────────────────────┤
    │  mcp-audit (APIsec)  │  secrets, API inventory
    │  tooltrust (AgentSafe)│  supply chain, 16 rules
    │  Custom checks        │  OWASP MCP Top 10 coverage
    └──────────────────────┘
               │
    Inngest (async job queue) → Supabase (results + history)
```

---

## Tech Stack

| Layer | Technology | Reason |
|-------|-----------|--------|
| Frontend | Next.js 15 + Shadcn/ui + Tailwind | Ecosystem + zero-DevOps Vercel deploy |
| Backend | FastAPI (Python 3.12) | Native to Python scan tools |
| Auth | Clerk | 30-min setup, org/team + API keys built-in |
| Database | Supabase (PostgreSQL) | Row Level Security for org isolation |
| Job Queue | Inngest | Serverless-native, no Redis to manage |
| CLI | Go (single static binary) | No runtime dependency, cross-platform |
| CI Integration | GitHub Actions Marketplace | Native SARIF → GitHub Security tab |
| Payments | Stripe | Standard |
| Hosting | Vercel (frontend) + Railway (API) | Zero DevOps for MVP |

---

## Project Structure

```
mcpaudit/
├── apps/
│   ├── web/              # Next.js 15 frontend
│   └── api/              # FastAPI backend (scan orchestrator)
├── packages/
│   ├── cli/              # Go CLI binary (cross-platform)
│   └── scan-engine/      # Core Python scan engine
├── .github/
│   ├── workflows/        # CI/CD pipelines
│   └── ISSUE_TEMPLATE/   # Bug report & feature request templates
├── docs/
│   └── research/         # Pre-build research (competitive analysis, tech decisions)
├── CLAUDE.md
└── README.md
```

---

## Roadmap

| Stage | Scope | Timeline |
|-------|-------|----------|
| **1 — MVP** | Web paste-and-scan, OWASP-mapped report, shareable links, no account needed | Month 1–3 |
| **2 — CLI + CI** | Go CLI (`npx mcpaudit scan`), GitHub Action, auth, scan history | Month 3–6 |
| **3 — Teams** | Team dashboard, Stripe subscriptions (Free/Pro/Team), scheduled scans, Slack alerts | Month 6–9 |
| **4 — Triage** | LLM-assisted false-positive reduction (Claude API, from ~78% FP to near 0%) | Month 9–15 |
| **5 — Enterprise** | On-prem agent, SIEM integration, SAML SSO, custom check rules, compliance reports | Month 15+ |

---

## Pricing (Planned)

| Tier | Price | Key Limits |
|------|-------|-----------|
| Free | $0 | 10 scans/month, no account needed, JSON report |
| Pro | $25/mo | Unlimited scans, scan history, CLI + CI access, SARIF export |
| Team | $99/mo | Org dashboard, scheduled scans, Slack alerts, SAML SSO |
| Enterprise | Custom | On-prem agent, SLA, SIEM, custom rules |

---

## Status

**Pre-build — research complete, development starting.**

Full pre-build research (competitive analysis, naming, tech stack decisions, feature specs, development plan) lives in [`docs/research/`](docs/research/).
