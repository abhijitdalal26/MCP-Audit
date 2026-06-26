# MCP Security Platform — Pre-Build Research Index
*Research completed: 2026-06-22*

---

## TL;DR for Decision-Making

**The opportunity is real.** $40M+ VC has already validated the MCP security category. NSA, DoD, and OWASP have all published formal guidance. Security incidents are happening monthly. The 4 existing open-source tools have a combined ~238 GitHub stars and zero web UIs — the gap is confirmed.

**The name "MCPGuard" is taken** by at least 3 products (usemcpguard.io, mcpguardapp.com, Virtue AI). Pick a new name before anything else.

**The differentiable angle:** unified web UI for individual devs + OWASP MCP Top 10 mapping + false-positive reduction via semantic analysis. Enterprise competitors (Operant AI, Runlayer, Helmet Security) ignore the solo dev / open-source maintainer segment entirely.

---

## Research Files

| # | File | What's Inside |
|---|------|---------------|
| 01 | [01_existing_tools.md](01_existing_tools.md) | Deep technical breakdown of all 4 tools + skill-audit-mcp. Capabilities, gaps, stars, licenses, tech stacks. |
| 02 | [02_social_demand.md](02_social_demand.md) | Reddit, HN, X/Twitter signals. CVE list. Incident timeline. Competitor map. VC investment table. |
| 03 | [03_tech_stack.md](03_tech_stack.md) | Recommended stack with rationale. MCP config JSON schema. Code samples. Cost table. |
| 04 | [04_competitive_analysis.md](04_competitive_analysis.md) | Competitor breakdown (enterprise vs. CLI tools vs. registries). Socket.dev business model analog. Differentiation matrix. |
| 05 | [05_features_and_roadmap.md](05_features_and_roadmap.md) | 20 security checks mapped to OWASP MCP Top 10. GitHub Action CI YAML. Tier pricing. MVP → V2 → V3 roadmap. |
| 06 | [06_naming.md](06_naming.md) | Name availability check for 10+ candidates. Top 3 recommendations. Newly discovered competitors found during search. |
| 07 | [07_pitch_onepager.md](07_pitch_onepager.md) | Ready-to-post Reddit + HN validation posts. Landing page copy. Success/failure criteria for the validation test. |
| 08 | [08_development_plan.md](08_development_plan.md) | Full 5-stage build plan. What surface to build when (web/CLI/GitHub Action/VS Code). Timeline. Critical path risks. |
| 09 | [09_research_papers_and_new_findings.md](09_research_papers_and_new_findings.md) | Clickable research paper links (foundational + 2026 MCP-specific). New technical findings: eBPF sandboxing, WASM client-side scanning, gVisor/Firecracker, horizontal-scroll exploit (PI-003), proactive crawler strategy, version pinning. |
| 10 | [10_product_overview.md](10_product_overview.md) | Simple product explanation. Two audiences (consumer vs. builder), 18 use cases total, volume vs. money strategy split. |

---

## Key Decisions to Make Before Building

### 1. Name (Urgent)
MCPGuard is taken. Options to explore:
- **MCPScan** — descriptive, not taken (verify)
- **AuditMCP** — action-oriented
- **ShieldMCP** — security framing
- **MCPLens** — inspection/visibility framing
- **ToolSentry** — tool-level security

### 2. Target User (Pick One for MVP)
- **Solo dev / OSS maintainer** — underserved, low CAC, builds community
- **Enterprise security team** — high ACV, long sales cycles, already crowded

Recommendation: **Solo dev for MVP**, enterprise upsell at V2.

### 3. Open Source vs. Closed
Socket.dev ships a closed SaaS on top of open methodology. Consider open-sourcing the scan engine, keeping the dashboard closed. This builds trust, gets GitHub stars, and funnels users to the paid UI.

### 4. Wrapping Strategy
The 4 existing tools can be wrapped via subprocess calls or reimplemented. Recommendation:
- **mcp-audit**: subprocess (Python) — most mature, do not rewrite
- **tooltrust**: subprocess (Go binary) — actively maintained, trust the binary
- **mcpserver-audit**: skip for MVP (educational, low automation value)
- **mcp-security-audit**: skip (just npm audit, implement natively)

---

## Recommended Stack (from 03_tech_stack.md)

```
Frontend:  Next.js 15 + Shadcn/ui + Tailwind
Backend:   FastAPI (Python) — wraps scan tools via asyncio.subprocess
Auth:      Clerk
DB:        Supabase (Postgres + RLS for org isolation)
Queue:     Inngest (async scan jobs, zero Redis ops)
CLI:       Go binary (single static binary, cross-platform)
Payments:  Stripe
Hosting:   Vercel (frontend) + Railway (FastAPI backend)
CI:        GitHub Actions marketplace action
```

---

## Competitive Moat Summary

| Competitor class | Their gap | Your angle |
|-----------------|-----------|------------|
| Enterprise SaaS (Operant, Runlayer, Helmet) | $$$, no self-serve, no free tier | Free tier, paste-and-scan in 30s |
| CLI tools (mcp-audit, tooltrust) | No web UI, no teams, no history | Unified dashboard + trend over time |
| MCP Registries (Glama, mcp.run) | Trust scores, not security audits | Deep OWASP-mapped reports |
| mcpserver-audit (CSA) | Educational tutor, not automated | Automated CI-ready scanner |

**Key differentiator to build toward:** Semantic false-positive reduction. Pattern tools have ~78% FP rate. An LLM-assisted triage layer that explains *why* a finding is a real risk (not just "this looks like a secret") is a genuine moat.

---

## The Numbers at a Glance

- **40+ CVEs** filed against MCP implementations in 60 days (early 2026)
- **8,000+** publicly exposed unauthenticated MCP servers (Censys scan)
- **150M+** affected downloads across vulnerable MCP packages
- **106 zero-days** found in 39,884 MCP repos (academic study)
- **$40M VC** already deployed in MCP security category
- **mcp-audit**: 150 stars | **tooltrust**: 16 stars | **mcpserver-audit**: 19 stars

---

## Next Steps

1. **Pick a name** — search GitHub + Product Hunt + domain registrar
2. **Validate with 10 devs** — post on r/LocalLLaMA or HN "Show HN: I built X" with a landing page
3. **MVP scope** — paste MCP JSON → run mcp-audit + tooltrust → unified report → shareable link
4. **Read in order:** 02 (demand) → 04 (competition) → 05 (features) → 03 (stack) → 01 (tools)
