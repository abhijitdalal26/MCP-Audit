# MCPGuard.io — Tech Stack Research

> Last updated: 2026-06-22  
> Purpose: Inform the final architecture decision before build begins.

---

## 1. What We're Building (Stack Scope)

A web SaaS where users paste their MCP config JSON and receive a unified security audit across multiple engines. Requires:

- **Frontend**: SPA/SSR dashboard with real-time scan progress
- **Backend API**: Orchestrates scan engines (Python + Go tools), returns results
- **Job queue**: Async scan processing (scans can take 10–60s)
- **Database**: Stores scan history, user accounts, org data, API keys
- **Auth**: User/org/team management with API key generation
- **CLI**: Distributable binary users install locally or in CI
- **CI integration**: GitHub Action that gates PRs

---

## 2. Frontend

### Verdict: **Next.js 15 (App Router)**

| Framework | Bundle size | Ecosystem | DX | SaaS fit | Verdict |
|---|---|---|---|---|---|
| Next.js 15 | ~80–90KB baseline | Massive (Shadcn, Radix, react-query) | Good | ★★★★★ | **Pick this** |
| SvelteKit | ~15–25KB | Smaller (fewer SaaS UI kits) | Excellent | ★★★★ | Good but fewer libs |
| Remix | Medium | Growing | Great | ★★★ | Overkill for MVP |

**Why Next.js 15:**
- Shadcn/ui gives production-quality dashboard components in minutes
- Vercel deployment = zero DevOps for frontend
- React ecosystem: Recharts/Tremor for dashboard charts, react-dropzone for config uploads
- All auth providers (Clerk, Supabase) have first-class Next.js SDKs
- SvelteKit wins on bundle size but MCP security buyers are enterprise — DX maturity matters more than 50KB

**Key libraries:**
- `shadcn/ui` — dashboard UI components
- `@tanstack/react-query` — server state + polling for scan status
- `recharts` or `@tremor/react` — risk score charts
- `react-dropzone` — drag-and-drop config upload
- `zod` — client-side config validation
- `next-themes` — dark mode (security tool users love dark mode)

---

## 3. Backend / API

### Verdict: **FastAPI (Python) as primary + Next.js API routes for thin BFF**

The existing audit tools (mcp-audit by APIsec) are **Python-native**. ToolTrust is Go. Wrapping them in a Node.js layer adds unnecessary translation friction.

**Architecture:**
```
Browser → Next.js API route (thin BFF) → FastAPI service → scan engines
                                              ↓
                                        Job queue (Redis + BullMQ or Inngest)
                                              ↓
                                        Worker processes
                                           ├── mcp-audit (Python subprocess)
                                           ├── tooltrust-scanner (Go binary)
                                           ├── mcpserver-audit checks (Python)
                                           └── Custom checks (Python)
```

**How to wrap Python CLI tools in a web API (FastAPI pattern):**
```python
import asyncio
import subprocess
from fastapi import FastAPI, BackgroundTasks

async def run_scan(config_path: str) -> dict:
    proc = await asyncio.create_subprocess_exec(
        "mcp-audit", "scan", "--format", "json", config_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    return json.loads(stdout)
```

**Key Python libraries for the scan service:**
- `fastapi` — async REST API
- `pydantic` v2 — config schema validation and result modeling
- `asyncio.subprocess` — non-blocking CLI tool execution
- `python-json-logger` — structured logging for SIEM
- `redis` (async) — job queue and scan result caching
- `celery` or `arq` — task worker (arq is lighter, async-native)
- `httpx` — async HTTP for OSV.dev and registry lookups

**Why not pure Node.js backend:**
- `mcp-audit` is Python — subprocess calls from Node add overhead and error handling complexity
- Python async is fully capable for this workload
- SAST-style checks are easier to write in Python (regex, AST parsing)

---

## 4. Auth

### Verdict: **Clerk** for MVP, plan migration to Better Auth at scale

| Option | Free tier | Cost at 100K MAU | DX | Org/team support | API keys |
|---|---|---|---|---|---|
| Clerk | 10K MAU | ~$1,800/mo | ★★★★★ | Built-in | Built-in |
| Supabase Auth | 50K MAU | ~$25/mo | ★★★ | Manual | Manual |
| Better Auth | Self-hosted | ~$0 + infra | ★★★★ | Plugin-based | Plugin-based |
| Auth.js | Self-hosted | ~$0 + infra | ★★★ | Limited | Manual |

**For MVP:** Clerk is the right call. 30-minute setup, pre-built UI components, org/team management out of the box, API key generation, and free up to 10K MAU. A security product can't ship with half-baked auth — Clerk removes that risk entirely.

**Migration path:** At ~5K MAU, evaluate Better Auth (open-source, self-hosted, same feature set). The migration is 2–3 days of work.

**Clerk features relevant to MCPGuard:**
- Organizations (for team plans)
- API key management
- Audit logs (users can see who ran scans)
- SAML SSO (for enterprise plan)

---

## 5. Database

### Verdict: **Supabase (PostgreSQL)**

- **Free tier**: 500MB, 2 projects
- **Pro tier**: $25/month, unlimited MAU, 8GB storage
- **Advantages**: Row Level Security ties perfectly to org-scoped scan data (users only see their org's scans), pgvector available for future AI similarity features, realtime subscriptions for live scan progress
- **Alternative**: Neon (serverless Postgres, good for variable workloads) — consider if cold starts matter

**Schema sketch:**
```sql
users (id, clerk_id, email, plan, created_at)
orgs (id, name, plan, seats, created_at)
org_members (org_id, user_id, role)
scans (id, org_id, user_id, config_hash, status, created_at, completed_at)
scan_findings (id, scan_id, engine, severity, check_id, title, detail, remediation)
api_keys (id, org_id, hash, label, last_used_at)
ci_integrations (id, org_id, repo, schedule, slack_webhook)
```

---

## 6. Job Queue for Async Scans

### Verdict: **Inngest** for MVP (serverless-native, zero Redis ops)

Scans take 10–60 seconds. Users need real-time progress. This is exactly what a job queue is for.

| Option | Setup complexity | Redis needed | Observability | Serverless-native | Cost at 50K scans/mo |
|---|---|---|---|---|---|
| **Inngest** | Low | No | ★★★★★ | Yes | ~$0–$75 |
| Trigger.dev | Low-medium | No | ★★★★★ | Yes | ~$0–$100 |
| BullMQ | High | Yes (managed) | ★★★ | No | ~$15 (Redis only) |
| Celery + Redis | High | Yes | ★★★ | No | ~$15 (Redis only) |

**Inngest for MVP because:**
- No Redis to provision — critical for fast MVP
- Step-by-step scan workflow fits naturally: `step.run("run-mcp-audit")` → `step.run("run-tooltrust")` → `step.run("aggregate-results")`
- Fan-out: run 4 scan engines in parallel, aggregate
- Built-in replay for debugging failed scans
- Free tier: 50K function runs/month

**Inngest scan workflow:**
```typescript
export const runScan = inngest.createFunction(
  { id: "run-security-scan" },
  { event: "scan/submitted" },
  async ({ event, step }) => {
    const [mcpAudit, toolTrust, cslAudit] = await Promise.all([
      step.run("mcp-audit", () => callScanEngine("mcp-audit", event.configPath)),
      step.run("tooltrust", () => callScanEngine("tooltrust", event.configPath)),
      step.run("csa-audit", () => callScanEngine("csa-audit", event.configPath)),
    ]);
    return step.run("aggregate", () => aggregateResults([mcpAudit, toolTrust, cslAudit]));
  }
);
```

---

## 7. Hosting / Deployment

### Verdict: **Vercel (frontend) + Railway (FastAPI workers)**

| Layer | Service | Cost |
|---|---|---|
| Frontend (Next.js) | Vercel | Free → $20/mo (Pro) |
| API + Workers (FastAPI) | Railway | $5/mo → pay-per-use |
| Database | Supabase | Free → $25/mo |
| Redis (if needed) | Railway Redis or Upstash | $0 (Inngest avoids this) |
| File storage (configs) | Supabase Storage or S3 | Negligible |

**Alternatives at scale:**
- Fly.io: excellent for Python workers that need global distribution
- Render: simpler than Railway, slightly more expensive
- GCP Cloud Run: scales to zero, good for bursty scan workloads

---

## 8. CLI Distribution

### Verdict: **Go binary** (primary) + **npm package** (secondary for JS devs)

**Go binary advantages:**
- Single static binary, no runtime dependency (no Python install needed)
- `go build` → cross-compile for Windows/Mac/Linux/ARM in one command
- ~5MB binary vs Python's venv overhead
- Fast startup (milliseconds) — critical for pre-commit hooks

**Distribution:**
```bash
# Homebrew (macOS/Linux)
brew install mcpguard/tap/mcpguard

# npm (CI environments, Node.js devs)
npx mcpguard@latest scan

# Direct download
curl -fsSL https://mcpguard.io/install.sh | sh

# GitHub Releases (versioned binaries for all platforms)
```

**CLI → API architecture:**
```
mcpguard scan mcp.json
  └─ If --local flag: run engines locally (bundled binaries)
  └─ Default: POST /api/scan → get scan_id → poll /api/scan/{id} → display results
```

**API key auth:** `mcpguard login` stores key in `~/.config/mcpguard/config.toml`

---

## 9. CI Integration (GitHub Action)

**Published to GitHub Actions Marketplace** as `mcpguard/scan-action`

```yaml
# .github/workflows/mcp-audit.yml
name: MCP Security Audit
on: [pull_request, push]

jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mcpguard/scan-action@v1
        with:
          config-path: '.mcp.json'       # or claude_desktop_config.json
          api-key: ${{ secrets.MCPGUARD_API_KEY }}
          fail-on-severity: 'high'       # block PRs on high/critical
          output-format: 'sarif'         # uploads to GitHub Security tab
```

The action uses the CLI binary, calls the MCPGuard API, and optionally uploads SARIF results to GitHub's code scanning alerts.

---

## 10. Payment

**Stripe** — no alternatives worth considering at MVP stage.

```
Free:     5 scans/month, 1 user, JSON report
Pro:      $25/month — unlimited scans, 5 users, all report formats, CI integration
Team:     $99/month — unlimited users, SAML SSO, scheduled scans, Slack alerts
Enterprise: Custom — on-prem agent, SLA, custom checks, SIEM integration
```

Stripe integration: `stripe-node` SDK + webhooks for subscription lifecycle. Use Clerk's metadata to store `plan` and `stripe_customer_id`.

---

## 11. MCP Config Format (What We're Parsing)

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/user/"],
      "env": {
        "API_KEY": "sk-abc123"
      }
    },
    "github": {
      "command": "uvx",
      "args": ["mcp-server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_xyz"
      }
    }
  }
}
```

### Cursor (`.cursor/mcp.json` or `~/.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": {
        "POSTGRES_CONNECTION_STRING": "postgresql://user:pass@localhost/db"
      }
    }
  }
}
```

### What to extract and audit:
- `command` + `args[0]` → package name/binary → check against registry + OSV.dev for vulnerabilities
- `env` values → scan for secrets using 25+ regex patterns (AWS keys, GitHub PATs, Stripe keys, database URLs, JWT secrets, etc.)
- `args` → check for shell injection patterns (unquoted, user-controlled values)
- Package version pins → unpinned = supply chain risk (rug pull vector)
- Permissions implied by args → filesystem paths (over-broad?), database access (read/write?), network access

---

## 12. Summary — Recommended Stack

| Layer | Tool | Rationale |
|---|---|---|
| Frontend | Next.js 15 + Shadcn/ui | Ecosystem + speed to ship |
| Backend | FastAPI (Python 3.12) | Native to Python scan tools |
| Auth | Clerk | 30-min setup, org/team built-in |
| Database | Supabase (Postgres) | RLS for org isolation + free tier |
| Job queue | Inngest | Zero-infra async, step-level observability |
| Hosting | Vercel + Railway | Zero DevOps for MVP |
| CLI | Go binary | Single binary, fast, cross-platform |
| CI | GitHub Action | Marketplace distribution |
| Payments | Stripe | Standard |
| Secrets scan | Regex + HyperScan | 25+ patterns, sub-millisecond |
| Supply chain | OSV.dev API | Free, Google-maintained vulnerability DB |

---

## Sources

- [mcp-audit GitHub (apisec-inc)](https://github.com/apisec-inc/mcp-audit)
- [ToolTrust on Glama](https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner)
- [Next.js vs SvelteKit 2026 — DEV Community](https://dev.to/paulthedev/sveltekit-vs-nextjs-in-2026-why-the-underdog-is-winning-a-developers-deep-dive-155b)
- [Inngest vs Trigger.dev vs BullMQ 2026](https://www.buildmvpfast.com/blog/inngest-vs-trigger-dev-vs-bullmq-background-jobs-nextjs-2026)
- [Clerk vs Supabase Auth vs NextAuth 2026](https://makerkit.dev/blog/tutorials/better-auth-vs-clerk)
- [FastAPI async background tasks](https://fastapi.tiangolo.com/async/)
- [Socket.dev pricing](https://socket.dev/pricing)
