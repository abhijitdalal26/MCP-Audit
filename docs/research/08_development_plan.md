# Development Plan — MCP Security Platform
*From zero to shipped product, stage by stage*

---

## What You're Actually Building

A combination of three surfaces:

| Surface | What it is | When to ship |
|---------|-----------|-------------|
| **Web App** | Primary product — paste config, get report, team dashboard | MVP + all stages |
| **CLI tool** | `npx mcpwatch scan` or `pip install mcpwatch` — for power users and CI | Stage 2 |
| **GitHub Action** | `uses: mcpwatch/scan@v1` in CI workflows | Stage 2 |
| **Browser Extension** | NOT recommended — adds attack surface, complex permissions, low leverage | Skip |
| **VS Code Extension** | Nice-to-have for V3 — shows inline warnings in config files | Stage 3 |

**No Chrome extension.** The web app covers paste-and-scan. The GitHub Action covers CI. A Chrome extension adds complexity without solving a problem the other surfaces don't already cover.

---

## Stage 0 — Validate Before Building (1–2 weeks)

**Goal:** Confirm demand is real before writing a line of product code.

Tasks:
- [ ] Verify mcpscan.ai feature depth — if it already does paste-and-scan well, you need a different angle from day 1
- [ ] Pick a name — MCPWatch recommended (check domain + GitHub org availability)
- [ ] Post validation pitch on r/LocalLLaMA and HN (see `07_pitch_onepager.md`)
- [ ] Set up a waitlist landing page (Carrd or Framer, 2 hours) with email capture
- [ ] Read the OWASP MCP Top 10 — understand the exact 10 categories
- [ ] Download and run mcp-audit and tooltrust locally on your own config — understand their output format

**Go/No-Go criteria:** 20+ upvotes on Reddit OR 5+ people asking when it ships → proceed. Under 10 → interview the commenters before proceeding.

---

## Stage 1 — MVP (4–6 weeks)

**Goal:** Working web app, ephemerally scans a pasted MCP JSON config, returns unified report. No account required.

### What to build
- [ ] **Config parser** — accept Claude Desktop (`claude_desktop_config.json`), Cursor (`.cursor/mcp.json`), VS Code (`settings.json` MCP section), and raw MCP server JSON
- [ ] **Scan engine** — FastAPI backend that runs mcp-audit + tooltrust as subprocesses and merges output
- [ ] **Report renderer** — Next.js page showing findings by severity (Critical / High / Medium / Low / Info), each mapped to OWASP MCP Top 10 category
- [ ] **Shareable link** — SHA256 hash of the config generates a deterministic report URL, no database needed for anonymous scans
- [ ] **Landing page** — headline, paste box, scan button, sample report

### What NOT to build in Stage 1
- No user accounts
- No scan history
- No team features
- No payments
- No CLI
- No GitHub Action

### Tech stack for Stage 1
```
Frontend:   Next.js 15 + Tailwind + Shadcn/ui
Backend:    FastAPI (Python 3.12)
Scan tools: mcp-audit (subprocess) + tooltrust binary (subprocess)
Hosting:    Vercel (frontend) + Railway (FastAPI)
Domain:     mcpwatch.io (or chosen name)
```

### Stage 1 done when:
- You can paste your own `claude_desktop_config.json` and get a real report in < 30 seconds
- Report shows at least 10 distinct check categories
- Shareable link works
- Page loads fast on mobile

---

## Stage 2 — CLI + CI Integration (3–4 weeks after Stage 1)

**Goal:** Power users can run scans locally and in CI pipelines.

### What to build
- [ ] **CLI tool** — Go binary (`mcpwatch scan ./claude_desktop_config.json`) that calls the same FastAPI backend. Distribute via Homebrew, npm (`npx mcpwatch`), and direct binary download.
- [ ] **GitHub Action** — `uses: mcpwatch/scan@v1` with inputs for config path, fail-on-severity threshold, and output format (SARIF for GitHub Security tab integration)
- [ ] **SARIF output** — pipe findings into GitHub's native security dashboard (this is free differentiation — most competitors don't do SARIF)
- [ ] **Basic auth + scan history** — Clerk for login, Supabase to store scan results, basic dashboard showing past scans

### Tech stack additions
```
CLI:        Go (single static binary, cross-platform)
Auth:       Clerk
DB:         Supabase (Postgres)
CI:         GitHub Actions marketplace
Output:     SARIF 2.1 format
```

### Stage 2 done when:
- A developer can add `mcpwatch/scan@v1` to their GitHub Action workflow in < 5 minutes
- SARIF findings show up in the GitHub Security tab
- Users can log in and see their scan history

---

## Stage 3 — Team Features + Payments (4–6 weeks after Stage 2)

**Goal:** Make money. Support teams and organizations.

### What to build
- [ ] **Org accounts** — invite team members, shared scan history, role-based access
- [ ] **Scheduled scans** — scan a repo or config on a cron schedule, alert on new findings
- [ ] **Stripe integration** — Free / Pro ($25/mo) / Team ($99/mo) tiers
- [ ] **Slack/Discord alerts** — notify team when a new critical finding appears
- [ ] **MCP Registry correlation** — cross-reference server names against known-malicious list and community audit-db
- [ ] **Trend dashboard** — how has your config's risk score changed over time?

### Pricing (suggested)
| Tier | Price | Limits |
|------|-------|--------|
| Free | $0 | Unlimited anonymous scans, no history |
| Pro | $25/mo | Scan history, shareable reports, CLI access |
| Team | $99/mo | Org dashboard, scheduled scans, Slack alerts, SAML SSO |
| Enterprise | Custom | On-prem scan engine, SLA, audit exports |

---

## Stage 4 — Semantic Triage (the moat) (6–8 weeks after Stage 3)

**Goal:** Reduce the ~78% false positive rate that kills trust in pattern-based scanners.

This is the feature no competitor has. Pattern-based tools flag everything that *looks* like a secret or injection vector. Most of those are false positives. An LLM-assisted triage layer that reads the context and explains *why* a finding is a real risk — with a confidence score — is a genuine moat.

### What to build
- [ ] **Triage layer** — for each finding, call Claude API with the surrounding context and ask: "Is this actually exploitable? What's the realistic attack scenario?"
- [ ] **Confidence scoring** — show P(real risk) next to each finding, not just severity
- [ ] **Plain English explanations** — "This API key is in a server that calls Stripe. If an attacker reads it, they can charge customers or issue refunds."
- [ ] **False positive feedback loop** — let users mark findings as FP, use that to fine-tune the triage prompts

### Tech stack addition
```
LLM: Claude API (claude-sonnet-4-6 for triage, claude-haiku-4-5 for bulk classification)
```

---

## Stage 5 — VS Code Extension (Stage 3+ only if demand warrants)

**Goal:** Show inline warnings in config files as the user edits them.

Only build this if:
- You have 500+ paying users and multiple have requested it
- OR your GitHub Action has 100+ installs

It's a nice-to-have, not a core surface. The web app and CLI cover all the use cases. The extension just reduces friction for VS Code users editing configs directly.

---

## Full Timeline (optimistic)

| Stage | Duration | Cumulative |
|-------|----------|-----------|
| 0 — Validate | 2 weeks | Week 2 |
| 1 — MVP web app | 6 weeks | Week 8 |
| 2 — CLI + CI | 4 weeks | Week 12 |
| 3 — Teams + Payments | 6 weeks | Week 18 |
| 4 — Semantic Triage | 8 weeks | Week 26 |
| 5 — VS Code Extension | 4 weeks | Week 30 (if warranted) |

**Realistic solo-founder pace:** add 50% to each estimate. MVP at ~Week 12, first revenue at ~Week 27.

---

## Critical Path Risks

1. **mcpscan.ai already does the MVP** — verify this first. If it does, Stage 1 needs a 10x better UX or a killer feature they lack.
2. **mcp-audit and tooltrust update frequently** — your subprocess wrappers will break. Plan for a thin abstraction layer.
3. **The OWASP MCP Top 10 may shift** — don't hardcode category IDs into your DB schema, store them as strings.
4. **Go CLI cross-compilation** — test on Windows ARM64 early, it catches most build issues.
5. **Stripe in India** — verify Stripe supports your country for receiving payouts. If not, use Paddle or Lemon Squeezy as alternatives.

---

## What to Read Before Starting Stage 1

In order:
1. `02_social_demand.md` — know your customer
2. `04_competitive_analysis.md` — know what you're up against
3. `06_naming.md` — pick a name
4. `05_features_and_roadmap.md` — know what checks to implement
5. `03_tech_stack.md` — know how to build it
6. `01_existing_tools.md` — know what you're wrapping
