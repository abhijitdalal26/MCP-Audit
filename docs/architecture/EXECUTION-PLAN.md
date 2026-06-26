# MCPAudit — Website + CLI Execution Plan

**Written:** 2026-06-27  
**For:** Loop-mode execution LLM  
**Goal:** Build the website UI and Go CLI working on localhost. No deployment yet.

---

## Scope: Localhost Only

**Everything in this plan is tested locally. Do not deploy to Vercel, Railway, or any cloud.**
The owner will handle deployment manually after reviewing the local build.

When you finish, the owner should be able to:
1. Run `uvicorn main:app --reload` in `apps/api` and hit `localhost:8000`
2. Run `npm run dev` in `apps/web` and see the redesigned UI at `localhost:3000`
3. Run `./mcpaudit scan <file>` from `packages/cli/bin/mcpaudit` and get terminal output

---

## Architecture Decisions (already made — do not re-derive)

**Monorepo:** CLI lives in `packages/cli/` inside this repo. Do NOT suggest or create a
separate repository. The monorepo keeps the API contract, check IDs, and CI in one place.
Extract to its own repo in Stage 2 if/when the CLI has independent contributors.

**CLI language: Go.** Single static binary, no runtime, cross-compiles trivially.
Industry standard for security tools (trivy, nuclei, grype are all Go).
Full rationale in `docs/architecture/ADR-003-cli-design.md`.

---

## Read This First — Project Context

MCPAudit is a security scanner for MCP (Model Context Protocol) server configurations.
Users paste their `claude_desktop_config.json` or `.cursor/mcp.json` and receive a security
report in seconds, with every finding mapped to the OWASP MCP Top 10.

**Current working state:**
- `apps/api/` — FastAPI backend, 51 security checks, 313/313 tests passing
- `apps/web/` — Next.js 15 frontend, functional but barebones (single `page.tsx`)
- API runs on `localhost:8000`, web on `localhost:3000`
- `NEXT_PUBLIC_API_URL` env var controls which API the web hits (default: `http://localhost:8000`)
- Engine is COMPLETE — do not touch `apps/api/engine/` during this execution

**Critical files to read before editing:**
- `apps/api/engine/models.py` — ScanResult, Finding, ScanSummary shapes
- `apps/web/src/app/page.tsx` — current frontend (the starting point for redesign)
- `apps/api/main.py` — API endpoints (/scan, /scan/sarif, /scan/bom)

---

## Phase 1: Website Redesign (do first)

### What exists vs what it should be

The current `page.tsx` is functional but minimal — single textarea, scan button, flat finding list.
The redesigned page needs to feel like a real product.

**Keep all existing API call logic** (`runScan`, `downloadExport` functions). Only change the UI.

### 1.1 — Update `apps/web/src/app/layout.tsx`

Add full metadata for SEO and social sharing:

```tsx
export const metadata: Metadata = {
  title: "MCPAudit — MCP Security Scanner",
  description: "51 security checks for your MCP server config. Find hardcoded secrets, supply chain attacks, privilege escalation, and prompt injection vulnerabilities mapped to OWASP MCP Top 10.",
  openGraph: {
    title: "MCPAudit — MCP Security Scanner",
    description: "Paste your claude_desktop_config.json and get a full security audit in seconds.",
    type: "website",
    url: "https://mcpaudit.app",
  },
  twitter: { card: "summary_large_image" },
  icons: { icon: "/favicon.ico" },
}
```

### 1.2 — Redesign `apps/web/src/app/page.tsx`

**Architecture decision:** Keep everything in `page.tsx` as inline components. Do NOT create separate files under `src/components/`. This keeps the execution simple and the file count low for MVP. The execution LLM should refactor into components only if `page.tsx` exceeds ~600 lines.

**Page layout (top to bottom):**

```
Header
Hero (tagline + description)
Scan Input (textarea + button)
[Results section — shown only after scan]
  └── RiskSummaryCard
  └── SeverityBreakdown bar
  └── OWASPCoverageGrid
  └── ExportButtons
  └── FindingsGroupedByServer
Explainer section (static, below scanner)
Footer
```

#### Header (update from current)
```
MCPAudit  [v0.1 alpha]          [GitHub ↗]  [CLI docs ↗]
```
- Add GitHub link: `https://github.com/abhijitdalal26/MCP-Audit`
- "CLI docs" links to `#cli` anchor on the same page (will scroll to CLI section below)
- Keep dark border-b style

#### Hero section (replace current)
```
h1: "Find security issues in your MCP config"
p: "51 checks across the OWASP MCP Top 10 — secrets, supply chain, privilege escalation,
    prompt injection. Results in under 30 seconds. No account required."
```

#### Scan input (keep current, minor tweaks)
- Keep the textarea and example config button
- Change button label: "Scan Config" → "Run Security Scan"
- Add character count / server count preview as user types (parse `mcpServers` keys)

#### Results — RiskSummaryCard
Replace the current summary div with a two-column card:

Left column:
```
Risk Grade: [A] (huge, colored: A=green, B=emerald, C=yellow, D=orange, F=red)
Risk Score: 47/100
Scan ID:    abc123de (monospace, small)
Scanned:    2026-06-27 14:32 UTC
```

Right column (finding counts):
```
3 servers scanned · 12 findings

[● 2 CRITICAL]  [● 3 HIGH]  [● 4 MEDIUM]  [● 2 LOW]  [● 1 INFO]
```
Each severity pill clickable to jump to first finding of that severity.

If 0 findings:
```
✓ All 51 checks passed — no security issues found
```

#### Results — SeverityBreakdown bar
A full-width horizontal bar, color-segmented by severity proportion:
```
[██████ CRITICAL] [███ HIGH] [████ MEDIUM] [██ LOW] [█ INFO]
```
Red | Orange | Yellow | Blue | Gray
Show percentages or counts in segments if wide enough.

#### Results — OWASPCoverageGrid
Show all 10 OWASP MCP Top 10 categories in a 5×2 grid:
- Hit categories: colored background + category name + finding count
- Clean categories: muted gray

OWASP name map (from `apps/api/engine/models.py`):
```
MCP01: Token Mismanagement & Secret Exposure
MCP02: Privilege Escalation via Scope Creep
MCP03: Tool Poisoning
MCP04: Supply Chain Attacks
MCP05: Command Injection & Execution
MCP06: Prompt Injection via Contextual Payloads
MCP07: Insufficient Authentication
MCP08: Lack of Audit and Telemetry
MCP09: Shadow MCP Servers
MCP10: Context Injection & Over-Sharing
```

#### Results — FindingsGroupedByServer
Replace the current flat list with findings grouped by `server_name`:

```
[server: filesystem]  ← collapsible section header (server name + finding count)
  ├── [CRITICAL] AWS Access Key ID hardcoded in env — SEC-001 · MCP01 · CWE-798
  │     Detail: ...
  │     Remediation: ...
  └── [HIGH] Unpinned package version: @modelcontextprotocol/server-filesystem — SEC-006 · MCP04

[server: github]
  └── ...
```

Group using a `reduce` over `findings` on `server_name`.
Sort servers by highest severity finding.
Sort findings within each server: CRITICAL → HIGH → MEDIUM → LOW → INFO.

Each finding card:
- Header row: [SEVERITY badge] [title] [check_id] [OWASP] [CWE if present]
- Expandable body: Detail paragraph + Remediation paragraph
- Small tag if `attack_tactic` present: "ATT&CK: credential-access"
- Left border color = severity color (keep current styling)
- Default: all collapsed (click header to expand)
- "Expand all" / "Collapse all" buttons above the list

#### ExportButtons (keep current, move to below findings header)
```
[Download SARIF]  [Download AI-BOM]
```
Keep current download logic, just position them next to "12 findings" count.

#### Static Explainer Section (NEW — below scanner)

Add this static section BELOW the results area, always visible:

```
What does MCPAudit check?

51 checks across 11 categories:

[Secrets]           SEC-001–008  Hardcoded API keys, DB passwords, tokens in env vars
[Supply Chain]      SC-001–007   Typosquatting, malicious packages, registry overrides
[Privilege]         PE-001–009   Broad filesystem paths, Docker escape, sudo usage
[Tool Poisoning]    PI-001–005   Invisible Unicode, prompt injection in tool descriptions
[Code Execution]    EX-001–003   base64 exec, curl|bash, PowerShell encoded commands
[Shadow Servers]    SH-001–006   Unverified packages, no-auth HTTP, homoglyphs
[Audit]             AT-001–006   Version pinning, Docker image tags, telemetry
[Lifecycle]         LF-001       Dangerous postinstall scripts
[Config Level]      CL-001–003   Cross-server risks, security feature disables
[Chain Analysis]    CHAIN-001–003 Multi-server attack chains (filesystem + exec, etc.)

Output formats: JSON  ·  SARIF 2.1.0 (GitHub Security tab)  ·  CycloneDX 1.6 AI-BOM
```

#### CLI Section (NEW — anchor: `#cli`)

```
Use from the command line

mcpaudit scan claude_desktop_config.json
mcpaudit scan --stdin < mcp.json --format sarif > results.sarif

[Download for macOS (Intel)]  [Download for macOS (Apple Silicon)]
[Download for Linux]          [Download for Windows]

Or in CI:
  - uses: mcpaudit/action@v1
    with:
      config-path: .cursor/mcp.json
      fail-on: high
```

#### Footer
```
MCPAudit · v0.1.0 · 51 checks · OWASP MCP Top 10 · GitHub · MIT License
```

### 1.3 — Color / Style Conventions (do not change)
- Background: `bg-gray-950`
- Card backgrounds: `bg-gray-900 border border-gray-800`
- Font: Inter (already in layout.tsx)
- Severity colors (keep existing constants):
  - CRITICAL: red-500
  - HIGH: orange-500
  - MEDIUM: yellow-500
  - LOW: blue-500
  - INFO: gray-500

---

## Phase 2: Deployment Config (prep files only — do NOT deploy)

These files prepare for future deployment but are not used locally.
Create them now so they're ready when the owner decides to deploy.

### 2.1 — `apps/api/railway.toml` (create)

```toml
[build]
builder = "nixpacks"

[deploy]
startCommand = "uvicorn main:app --host 0.0.0.0 --port $PORT"
restartPolicyType = "on_failure"
restartPolicyMaxRetries = 3
```

### 2.2 — `apps/api/Procfile` (create)

```
web: uvicorn main:app --host 0.0.0.0 --port $PORT
```

### 2.3 — `apps/api/requirements.txt` (create — Railway needs this, separate from dev deps)

```
fastapi>=0.115.0
uvicorn[standard]>=0.30.0
pydantic>=2.7.0
httpx>=0.27.0
```

Dev deps (pytest, etc.) stay in `requirements-dev.txt` only.

### 2.4 — `apps/web/.env.example` (create)

```
# Local development
NEXT_PUBLIC_API_URL=http://localhost:8000

# Production (set in Vercel dashboard, not committed)
# NEXT_PUBLIC_API_URL=https://api.mcpaudit.app
```

### 2.5 — Update CORS in `apps/api/main.py`

Add production origins so they're ready (does not break local dev):
```python
allow_origins=[
    "http://localhost:3000",
    "http://localhost:3001",
    "https://mcpaudit.app",
    "https://www.mcpaudit.app",
]
```

---

## Phase 3: CLI (Go binary)

**Architecture decision:** The CLI is a thin HTTP client that calls the deployed API.
It does NOT re-implement the Python engine. This means:
- CLI requires network access to `api.mcpaudit.app` by default
- `--api-url` flag lets users point at a self-hosted instance
- This is intentional for MVP: one engine codebase, multiple clients

**Why Go:** Single static binary, fast startup (<50ms vs Python's 500ms+), easy cross-compilation,
Homebrew-friendly distribution. `cobra` is the de facto CLI framework in Go.

### 3.1 — Directory structure

```
packages/cli/
  go.mod
  go.sum
  main.go               # entrypoint, cobra root
  cmd/
    root.go             # root command, persistent flags
    scan.go             # mcpaudit scan <file> | --stdin
    version.go          # mcpaudit version
  internal/
    client/
      client.go         # HTTP client wrapping POST /scan
    output/
      text.go           # colored terminal output (default)
      json.go           # raw JSON output
      sarif.go          # SARIF format call (POST /scan/sarif)
      bom.go            # AI-BOM call (POST /scan/bom)
  Makefile              # build targets
```

### 3.2 — `packages/cli/go.mod`

```
module github.com/abhijitdalal26/MCP-Audit/cli

go 1.22

require (
    github.com/spf13/cobra v1.8.0
    github.com/fatih/color v1.17.0
)
```

### 3.3 — Commands and flags

```
mcpaudit scan <file>              # scan a config file
mcpaudit scan --stdin             # read config from stdin
mcpaudit version                  # print version and exit
```

Flags on `scan`:
```
--api-url string    API base URL (default "https://api.mcpaudit.app")
--format string     Output format: text, json, sarif, bom (default "text")
--output string     Write output to file (default stdout)
--fail-on string    Exit 1 if findings at this severity or above (default "critical")
                    Values: critical, high, medium, low, info, none
--no-color          Disable ANSI color output
--timeout int       HTTP timeout in seconds (default 30)
```

### 3.4 — Exit codes

```
0 = clean (no findings at/above --fail-on threshold) or --fail-on none
1 = findings found at/above --fail-on threshold (use this for CI blocking)
2 = error: invalid config JSON, API unreachable, network error, file not found
```

### 3.5 — `text` output format (default)

Match the style of `npm audit`. Example:

```
MCPAudit v0.1.0 — 3 servers scanned

Risk Grade: F  (score: 82/100)

  CRITICAL  AWS Access Key ID hardcoded in `AWS_ACCESS_KEY_ID` (environment variable)
            Server: filesystem | SEC-001 | MCP01 | CWE-798
            → Remove hardcoded value from AWS_ACCESS_KEY_ID. Reference a secrets manager.

  CRITICAL  MCP server runs with elevated privileges: `sudo`
            Server: runner | PE-006 | MCP02 | CWE-250
            → Remove sudo and run the MCP server under a regular user account.

  HIGH      Unpinned package version: `@modelcontextprotocol/server-filesystem`
            Server: filesystem | SEC-006 | MCP04 | CWE-1104
            → Pin to an exact version, e.g. @modelcontextprotocol/server-filesystem@1.2.3

12 findings: 2 critical, 3 high, 4 medium, 2 low, 1 info

Run with --format sarif to upload to GitHub Security tab.
```

If clean:
```
MCPAudit v0.1.0 — 3 servers scanned

✓  All 51 checks passed. Risk grade: A (score: 0/100)
```

### 3.6 — `packages/cli/Makefile`

```makefile
VERSION := 0.1.0
LDFLAGS := -ldflags="-X main.Version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/mcpaudit .

cross:
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o dist/mcpaudit-linux-amd64 .
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o dist/mcpaudit-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o dist/mcpaudit-darwin-arm64 .
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o dist/mcpaudit-windows-amd64.exe .

test:
	go test ./...
```

### 3.7 — `.github/workflows/release.yml` (create)

Trigger: push a git tag `v*` (e.g., `v0.1.0`).
Steps: cross-compile, create GitHub Release, upload binaries.

```yaml
name: Release CLI

on:
  push:
    tags: ["v*"]

jobs:
  release:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: packages/cli
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - run: make cross
      - uses: softprops/action-gh-release@v2
        with:
          files: packages/cli/dist/*
```

---

## Phase 4: GitHub Action

Create `.github/actions/mcpaudit/action.yml`:

```yaml
name: MCPAudit Security Scan
description: Scan MCP server configs for security vulnerabilities
inputs:
  config-path:
    description: Path to MCP config file
    default: claude_desktop_config.json
  fail-on:
    description: Minimum severity to fail CI (critical/high/medium/low/none)
    default: critical
  api-url:
    description: MCPAudit API URL
    default: https://api.mcpaudit.app
runs:
  using: composite
  steps:
    - name: Download mcpaudit CLI
      shell: bash
      run: |
        curl -sSL https://github.com/abhijitdalal26/MCP-Audit/releases/latest/download/mcpaudit-linux-amd64 -o /usr/local/bin/mcpaudit
        chmod +x /usr/local/bin/mcpaudit
    - name: Run scan
      shell: bash
      run: mcpaudit scan "${{ inputs.config-path }}" --api-url "${{ inputs.api-url }}" --fail-on "${{ inputs.fail-on }}"
```

---

## Execution Order for Loop LLM

Run these phases in order. Each phase is independently completable.
**All testing is on localhost — do not attempt to deploy anything.**

```
Phase 1: Website (highest priority — do first)
  ├─ 1.1  Update apps/web/src/app/layout.tsx metadata
  ├─ 1.2  Redesign apps/web/src/app/page.tsx (largest task)
  ├─ 1.3  Run `npm run build` in apps/web — must pass with zero errors
  └─ 1.4  Run `npm run dev` and confirm scan flow works at localhost:3000
           (API must be running at localhost:8000 for this test)

Phase 2: Deployment config files (create files, do NOT deploy)
  ├─ 2.1  Create apps/api/railway.toml
  ├─ 2.2  Create apps/api/Procfile
  ├─ 2.3  Create apps/api/requirements.txt
  ├─ 2.4  Create apps/web/.env.example
  └─ 2.5  Update CORS origins in apps/api/main.py

Phase 3: CLI (Go binary in packages/cli/)
  ├─ 3.1  Create packages/cli/go.mod + go.sum
  ├─ 3.2  Create all .go source files (main.go, cmd/, internal/)
  ├─ 3.3  Create Makefile
  ├─ 3.4  Run `go build -o bin/mcpaudit .` — must produce binary
  ├─ 3.5  Run `go test ./...` — must pass
  └─ 3.6  Smoke test: `./bin/mcpaudit scan <some-config.json>`
           (API must be running at localhost:8000)

Phase 4: GitHub Actions (CI plumbing)
  ├─ 4.1  Create .github/actions/mcpaudit/action.yml
  └─ 4.2  Create .github/workflows/release.yml (binary release on git tag)
```

**Success criteria — loop can terminate when ALL of these pass:**
1. `npm run build` exits 0 in `apps/web`
2. `pytest tests/ -q` still shows 313 passed in `apps/api` (engine untouched)
3. `go build` exits 0 and produces `packages/cli/bin/mcpaudit`
4. `go test ./...` exits 0
5. All 4 deployment config files exist (railway.toml, Procfile, requirements.txt, .env.example)
6. CORS in apps/api/main.py includes the production origins

---

## What NOT to Do

- **Do not modify anything in `apps/api/engine/`** — engine is complete
- **Do not add auth** — Clerk is Stage 2
- **Do not add a database** — Supabase is Stage 2
- **Do not add rate limiting** — Stage 2
- **Do not create a `/results/[id]` route** — scan history requires DB (Stage 2)
- **Do not change the Python test suite** — 313 tests must remain green
- **Do not touch `docs/vault/`** — user's personal notes, read-only
- **Do not modify `apps/api/engine/models.py`** without updating the TypeScript interface in page.tsx to match
