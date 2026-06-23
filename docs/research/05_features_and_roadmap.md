# MCPGuard.io — Features, Security Checks & Roadmap

> Last updated: 2026-06-22  
> Purpose: Define exactly what to build, in what order, and why.

---

## 1. Security Checks to Implement (20 Specific Checks)

Each check maps to the OWASP MCP Top 10 and is assigned a severity level.

### Secrets & Credentials (OWASP MCP01)
| ID | Check | Severity | How |
|---|---|---|---|
| SEC-001 | **AWS credentials in env vars** — detect `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` | CRITICAL | Regex on `env` block |
| SEC-002 | **GitHub/GitLab PATs** — detect `ghp_`, `gho_`, `ghs_`, `glpat-` prefixes | CRITICAL | Regex |
| SEC-003 | **Database connection strings with credentials** — `postgresql://user:pass@`, `mysql://`, `mongodb+srv://user:pass@` | CRITICAL | Regex |
| SEC-004 | **Generic API key patterns** — `sk-`, `pk_live_`, `rk_live_`, Stripe keys, OpenAI keys | HIGH | Regex (25+ patterns from mcp-audit) |
| SEC-005 | **JWT secrets or signing keys** — `eyJ` base64 prefix, `JWT_SECRET`, `SIGNING_KEY` vars | HIGH | Regex + var name matching |
| SEC-006 | **Unpinned package versions** — `npx -y @scope/package` without version pin = rug pull risk | MEDIUM | args parsing |

### Supply Chain (OWASP MCP04)
| ID | Check | Severity | How |
|---|---|---|---|
| SC-001 | **Known malicious packages** — offline blacklist + OSV.dev lookup | CRITICAL | Blocklist + OSV.dev API |
| SC-002 | **Typosquatting detection** — `@modelcontextprotcol/` (missing letter), `mcp-serv3r`, etc. | HIGH | Edit-distance comparison against known-good registry |
| SC-003 | **Unverified/unofficial registry packages** — not in official MCP registry or Glama | MEDIUM | Registry API lookup |
| SC-004 | **Package CVE scan** — any CVEs in the npm/PyPI package at specified version | HIGH | OSV.dev API |

### Tool Poisoning & Prompt Injection (OWASP MCP03, MCP06)
| ID | Check | Severity | How |
|---|---|---|---|
| PI-001 | **Suspicious tool description keywords** — "ignore previous instructions", "do not reveal", "system prompt", "override" | HIGH | Keyword scan on fetched tool descriptions (requires server fetch) |
| PI-002 | **Excessively long tool descriptions** — >2000 chars in description = injection hiding space | MEDIUM | Length check |

### Privilege Escalation & Permissions (OWASP MCP02, MCP07)
| ID | Check | Severity | How |
|---|---|---|---|
| PE-001 | **Filesystem MCP with root/home paths** — `server-filesystem /` or `/Users` (overly broad) | HIGH | args path analysis |
| PE-002 | **Shell execution capabilities** — MCP server args that suggest shell access (`--exec`, `--shell`, `subprocess`) | HIGH | args keyword matching |
| PE-003 | **Admin/root privilege patterns** — env vars like `SUDO_PASSWORD`, `ROOT_TOKEN`, `ADMIN_KEY` | HIGH | Var name matching |
| PE-004 | **Database write access** — connection strings without `?readOnly=true` for servers that claim read-only | MEDIUM | Connection string parsing |

### Shadow Servers & Config Issues (OWASP MCP09)
| ID | Check | Severity | How |
|---|---|---|---|
| SH-001 | **Server not in any known registry** — command/package not found in MCP registry, Glama, or Smithery | MEDIUM | Registry API |
| SH-002 | **HTTP server without TLS** — `url: http://` (non-TLS MCP server URL) | HIGH | URL scheme check |
| SH-003 | **Localhost-only server with external package** — mismatch between claimed local-only and fetched-from-npm | LOW | args analysis |

### Audit & Telemetry (OWASP MCP08)
| ID | Check | Severity | How |
|---|---|---|---|
| AT-001 | **No version pinning across any server** — entire config has zero pinned versions = no reproducibility | MEDIUM | Global config analysis |

---

## 2. What MCP Config Data Gets Audited

### Claude Desktop (`~/.config/claude/claude_desktop_config.json` or `%APPDATA%\Claude\claude_desktop_config.json`)
Fields extracted and analyzed:
```
mcpServers.[name].command       → binary/runtime (node, npx, uvx, python, docker, etc.)
mcpServers.[name].args          → package name + version + path args
mcpServers.[name].env           → ALL env vars → secret scanning
mcpServers.[name].url           → HTTP/SSE server URL → TLS check, domain check
mcpServers.[name].transport     → stdio vs sse vs http
```

### Cursor (`.cursor/mcp.json` or `~/.cursor/mcp.json`)
Same schema as Claude Desktop `mcpServers` block.

### Windsurf, VS Code Copilot, Continue.dev
Slight schema variations — all produce similar JSON. MCPGuard normalizes on ingest.

### What the tool does NOT receive:
- Tool descriptions (require connecting to the server at runtime) — Phase 2 feature
- Conversation history or prompt data — never collected
- Actual secret values in reports (masked after detection: `sk-abc1...9xyz`)

---

## 3. MVP vs V2 vs V3

### MVP (Month 1–3) — "Paste and Scan"
**Goal**: Fastest possible path from "paste config" to "security report"

Core features:
- [ ] Web UI: paste MCP config JSON → run unified scan → see findings
- [ ] Engines integrated: mcp-audit (secrets, API inventory), tooltrust (supply chain, 16 static rules)
- [ ] Finding display: severity-sorted list with title, detail, remediation link
- [ ] Report export: JSON, Markdown, PDF
- [ ] Auth: Clerk (email/password + GitHub OAuth)
- [ ] Free tier: 5 scans/month
- [ ] CLI: `mcpguard scan mcp.json` (Go binary)
- [ ] Basic scan history (last 10 scans)

**What to skip in MVP:**
- Org/team features
- Scheduled scans
- CI GitHub Action (just document the CLI method)
- Slack integration
- CSA mcpserver-audit engine (it requires Claude Desktop runtime — needs wrapper work)

**Success metric**: 100 scans from real users in month 1

---

### V2 (Month 3–6) — "Team & CI"
**Goal**: Convert free users to paid, unlock CI market

New features:
- [ ] Orgs and team plans (Clerk orgs)
- [ ] GitHub Action on Marketplace (`mcpguard/scan-action@v1`)
- [ ] SARIF output → GitHub Security tab integration
- [ ] Scheduled scans (daily/weekly cron on saved configs)
- [ ] Slack webhook alerts on new findings
- [ ] API key generation for CI
- [ ] AI-BOM export (CycloneDX 1.6) — via mcp-audit engine
- [ ] AIVSS scoring display (from CSA taxonomy)
- [ ] MCP registry correlation (check each server against official registry + Glama)

**Pricing launch**: Free → Pro ($25/mo) → Team ($99/mo)

---

### V3 (Month 6–12) — "Enterprise"
**Goal**: Land enterprise contracts; become the compliance reference

New features:
- [ ] On-premises agent (Docker) — for enterprises that can't send configs to cloud
- [ ] Dynamic analysis (actually connect to MCP server, fetch tool descriptions, scan for prompt injection in descriptions)
- [ ] SIEM integration (webhook/Splunk/Datadog events for every finding)
- [ ] Custom check rules (YARA-like DSL for enterprise-specific patterns)
- [ ] Remediation workflow (open GitHub issue or PR with fix suggestion on click)
- [ ] Compliance report: OWASP MCP Top 10 coverage report, SOC 2 evidence export
- [ ] SSO (SAML via Clerk enterprise)
- [ ] Audit log (who scanned what, when, from which IP)
- [ ] CVE advisory subscriptions (email/Slack when a new CVE affects one of your configured servers)

---

## 4. CI Integration — Exact Implementation

### GitHub Action (in `.github/actions/scan/action.yml`):
```yaml
name: 'MCPGuard Security Scan'
description: 'Audit MCP server configurations for security vulnerabilities'
inputs:
  config-path:
    description: 'Path to MCP config file'
    required: false
    default: '.mcp.json'
  api-key:
    description: 'MCPGuard API key'
    required: true
  fail-on-severity:
    description: 'Fail if findings at or above this severity: critical, high, medium, low'
    required: false
    default: 'high'
  output-sarif:
    description: 'Upload findings as SARIF to GitHub Security tab'
    required: false
    default: 'true'

runs:
  using: 'composite'
  steps:
    - name: Download MCPGuard CLI
      shell: bash
      run: |
        curl -fsSL https://mcpguard.io/install.sh | sh
    - name: Run scan
      shell: bash
      run: |
        mcpguard scan "${{ inputs.config-path }}" \
          --format sarif \
          --output mcpguard-results.sarif \
          --fail-on ${{ inputs.fail-on-severity }}
      env:
        MCPGUARD_API_KEY: ${{ inputs.api-key }}
    - name: Upload SARIF
      if: always() && inputs.output-sarif == 'true'
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: mcpguard-results.sarif
```

**What the CI flow looks like for the user:**
1. Commit changes to `mcp.json`
2. PR opened → GitHub Action runs → MCPGuard scans config
3. If CRITICAL finding: PR blocked, GitHub Security tab shows finding
4. If MEDIUM finding: PR passes with warning annotation
5. Developer clicks finding → opens MCPGuard web UI with full remediation guide

---

## 5. Free vs Paid Tier Design

| Feature | Free | Pro ($25/mo) | Team ($99/mo) | Enterprise |
|---|---|---|---|---|
| Scans/month | 10 | Unlimited | Unlimited | Unlimited |
| Users | 1 | 3 | Unlimited | Unlimited |
| Scan engines | mcp-audit + tooltrust | All 4 engines | All 4 + custom | All + custom DSL |
| Scan history | 7 days | 1 year | 3 years | Custom |
| CI GitHub Action | No | Yes | Yes | Yes |
| API access | No | Yes | Yes | Yes |
| SARIF export | No | Yes | Yes | Yes |
| AI-BOM (CycloneDX) | No | Yes | Yes | Yes |
| Scheduled scans | No | No | Yes (daily/weekly) | Yes |
| Slack alerts | No | No | Yes | Yes |
| SIEM integration | No | No | No | Yes |
| On-prem agent | No | No | No | Yes |
| SAML SSO | No | No | No | Yes |
| Compliance report | No | No | Yes | Yes |
| Support | Community | Email | Priority | Dedicated |

**Free tier conversion triggers:**
- Hit 10 scan limit → upgrade CTA
- Try to download SARIF → upgrade CTA
- Try to set up CI → upgrade CTA
- Add a second team member → upgrade CTA

---

## 6. MCP Server Registry — Current State

### Official registry: https://registry.modelcontextprotocol.io/
- Launched September 2025 (preview)
- Community-maintained, not a security review
- Can be queried via API to check if a server is "known"
- Source: https://github.com/modelcontextprotocol/registry

### Other registries MCPGuard should correlate against:
| Registry | URL | Size | Security checks |
|---|---|---|---|
| Official MCP Registry | registry.modelcontextprotocol.io | Growing | None (listing only) |
| Glama | glama.ai/mcp/servers | 44,392 | Basic (tooltrust integration) |
| Smithery | smithery.ai | 7,000+ | None |
| ModelContextProtocol-Security audit-db | github.com/ModelContextProtocol-Security/audit-db | Growing | Security assessments |
| CSA vulnerability-db | github.com/ModelContextProtocol-Security | Growing | AIVSS scores |

**MCPGuard's registry strategy**: Aggregate all registries. A server in multiple registries = higher trust score. A server in no registry = flag as UNKNOWN (Shadow Server, MCP09).

---

## 7. Formal Security Taxonomy (What We Map To)

### OWASP MCP Top 10 (2025/2026 — beta)
The primary compliance framework MCPGuard should report against:

| ID | Name | Checks we implement |
|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | SEC-001–006 |
| MCP02 | Privilege Escalation via Scope Creep | PE-001–004 |
| MCP03 | Tool Poisoning | PI-001–002 |
| MCP04 | Supply Chain Attacks | SC-001–004 |
| MCP05 | Command Injection & Execution | PE-002, SEC-006 |
| MCP06 | Prompt Injection via Contextual Payloads | PI-001–002 |
| MCP07 | Insufficient Authentication | SH-002, AT-001 |
| MCP08 | Lack of Audit and Telemetry | AT-001 |
| MCP09 | Shadow MCP Servers | SH-001–003 |
| MCP10 | Context Injection & Over-Sharing | PE-004 (partial) |

**Key marketing message**: "MCPGuard covers 9 of 10 OWASP MCP Top 10 risks"

### AIVSS (AI Vulnerability Scoring System)
- Used by CSA's mcpserver-audit
- AI-specific variant of CVSS
- MCPGuard should display AIVSS scores alongside severity labels
- Adds credibility with enterprise security buyers

### MITRE ATT&CK (adjacent)
- mcpserver-audit references ATT&CK alignment
- For enterprise reports, map findings to ATT&CK tactics (Initial Access, Credential Access, Privilege Escalation, etc.)

### Broader academic taxonomy (March 2026):
- arxiv.org/pdf/2603.18063 — "Comprehensive Threat Taxonomy for MCP" (MCP-38 taxonomy)
- Classify attacks by architectural layer: Model/LLM → MCP Host → MCP Client → MCP Server → Transport → Registry

---

## 8. Differentiation Summary — Why MCPGuard Wins

### Against fragmented CLI tools (mcp-audit, tooltrust):
1. **Web UI** — no install, paste and scan in 30 seconds
2. **Unified results** — one report instead of running 3 CLIs and merging output manually
3. **Historical tracking** — "did this new MCP server introduce new findings vs last week?"
4. **Team features** — security teams can share findings, assign remediation owners
5. **Compliance output** — OWASP MCP Top 10 coverage report, AI-BOM, SARIF

### Against doing nothing (most teams):
6. **The threat is real and documented** — NSA advisory + 106 zero-days + real breaches
7. **Zero friction** — paste JSON, click scan, get report. No Python install, no config

### Against general SAST tools (Snyk, Checkmarx):
8. **MCP-specific checks** — general SAST tools do not model MCP tool descriptions, MCP protocol compliance, or MCP-specific attack patterns (Tool Poisoning, Rug Pulls, Shadow Servers)
9. **Config-file first** — scanning the claude_desktop_config.json is not something Snyk/Semgrep does

### Moats to build over time:
- **Threat intelligence**: proprietary database of malicious MCP packages (like Socket.dev's malware DB)
- **Registry integration**: become the security data layer for official MCP registry
- **AI-native checks**: LLM-based tool description analysis for prompt injection (zero false-positive rate is a competitive advantage here)
- **First mover**: no web SaaS exists today in this exact space

---

## 9. Open Questions (Decide Before Building)

1. **Self-hosted vs cloud-only?** Enterprise buyers will want on-prem. But that's V3, not MVP. MVP is cloud-only.
2. **Do we build our own scan engine or wrap existing?** Wrap first (faster), build proprietary checks in parallel. Custom engine is the moat.
3. **Do we accept the MCP config JSON directly, or read from GitHub repo?** Both — web UI takes paste, CI integration reads from repo.
4. **Pricing: per-user or per-scan?** Per-user/per-seat is simpler to reason about. Per-scan is fairer for bursty usage. Start per-user, add scan packs later.
5. **Name: MCPGuard.io?** Domain check needed. Alternatives: MCPScan.io, MCPShield.io, GuardMCP.io.

---

## Sources

- [OWASP MCP Top 10 — Practical DevSecOps](https://www.practical-devsecops.com/owasp-mcp-top-10/)
- [MCP Security Comprehensive Threat Taxonomy — arxiv](https://arxiv.org/pdf/2603.18063)
- [We Urgently Need Privilege Management in MCP — arxiv](https://arxiv.org/pdf/2507.06250)
- [Official MCP Registry](https://registry.modelcontextprotocol.io/)
- [ModelContextProtocol-Security audit-db](https://github.com/ModelContextProtocol-Security/audit-db)
- [MCP Security — OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [State of MCP Server Security 2025 — Astrix](https://astrix.security/learn/blog/state-of-mcp-server-security-2025/)
- [ToolTrust Scanner details — Glama](https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner)
- [mcp-audit v1.0 release](https://github.com/apisec-inc/mcp-audit/blob/main/RELEASE_v1.0.0.md)
- [MCP Security Top 10 Practitioner Threat Model — Amine Raji](https://aminrj.com/posts/owasp-mcp-top-10/)
- [Checkmarx 11 Emerging MCP Risks](https://checkmarx.com/zero-post/11-emerging-ai-security-risks-with-mcp-model-context-protocol/)
- [COSAI Secure Design for Agentic Systems — MCP Security](https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md)
- [MCP Server Security Audit 2026 — AppSecSanta](https://appsecsanta.com/research/mcp-server-security-audit-2026)
- [Auditing MCP for Over-Privileged Tool Capabilities — arxiv](https://arxiv.org/html/2603.21641v1)
