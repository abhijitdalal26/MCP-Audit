# MCPGuard.io — Competitive Analysis & Market Research

> Last updated: 2026-06-22  
> Purpose: Map the current landscape to find the differentiation gap.

---

## 1. Market Signal: Is Demand Real?

**Yes. Unambiguously.**

### Security incident data (not hype — actual CVEs and breaches):
- **106 zero-day vulnerabilities** found in 39,884 MCP server repos (academic scan, May 2026)
- **12,520 MCP services** publicly exposed on the internet; ~40% with **no authentication** (Censys, 2026)
- **53% rely on static long-lived secrets** (API keys/PATs with no rotation) — Astrix research, 5,205 servers
- **150GB of government data** compromised via MCP-facilitated Claude attack (Dec 2025–Jan 2026, Mexican agencies)
- **Anthropic's own Git MCP server** had path validation bypass + argument injection + unsafe repo init (Nov 2025)
- **CVE-2026-22252, CVE-2025-49596, CVE-2025-54994, CVE-2025-54136** — MCP-specific CVEs accumulating fast
- **Trojanized Oura MCP server** deployed StealC infostealer (Feb 2026)
- **NSA published Cybersecurity Information Sheet** on MCP security (2026)
- **OWASP published MCP Top 10** (beta, 2025/2026)
- **Cloud Security Alliance** launched dedicated MCP Security initiative

### Growth metrics:
- Glama registry: **44,392 MCP servers** indexed (2026)
- Unofficial registries: 16,000–17,000 servers
- Anthropic donated MCP to Linux Foundation's Agentic AI Foundation (AAIF) in Dec 2025 — now a multi-vendor standard (OpenAI, Google, Microsoft, AWS, Cloudflare, Bloomberg)
- MCP is no longer Anthropic-specific — it's the standard protocol for AI tools

### Community signals:
- Hacker News discussions on building MCP security monitors (active threads)
- VentureBeat, Dark Reading, The Hacker News all running MCP security coverage weekly
- Trend Micro identified 102 MCP-specific CVEs
- Academic papers: arxiv.org/pdf/2603.18063 (Comprehensive Threat Taxonomy, March 2026), arxiv.org/pdf/2507.06250 (Privilege Management Measurement)

---

## 2. The Existing Tools (What We're Unifying)

### Tool 1: mcp-audit (APIsec Inc.)
- **Repo**: https://github.com/apisec-inc/mcp-audit
- **License**: MIT (open source)
- **Language**: Python 58.5%, JavaScript 22.7%
- **What it does**:
  - Scans Claude Desktop / Cursor / VS Code configs
  - Detects 25+ secret patterns (AWS keys, GitHub PATs, database passwords, API tokens)
  - Catalogs API endpoints accessible to AI agents (database, REST, SSE, cloud)
  - Identifies configured LLM models (OpenAI, Anthropic, Google, Ollama, etc.)
  - Source code scanning: detects shell-injection sinks (`child_process.exec`, `subprocess.run(shell=True)`)
  - Generates AI-BOM in CycloneDX 1.6 format
  - SARIF output for GitHub Security integration
- **Strengths**: Most feature-complete, production-ready (v1.0), SARIF support
- **Weaknesses**: CLI-only, Python install required, no web UI, no unified dashboard, no team features

### Tool 2: mcpserver-audit (Cloud Security Alliance / ModelContextProtocol-Security)
- **Repo**: https://github.com/ModelContextProtocol-Security/mcpserver-audit
- **License**: Open source (CSA community project)
- **Language**: Operates as an MCP server (runs inside Claude Desktop/Cursor — not a standalone CLI)
- **What it does**:
  - Static code analysis for common security patterns/anti-patterns
  - Dependency scanning for known vulnerabilities
  - Configuration review
  - MCP Protocol compliance verification
  - AI-specific threat checks: prompt injection, model manipulation, training data poisoning, indirect prompt injection
  - Uses **AIVSS** (AI Vulnerability Scoring System) — maps to CWE, NIST, OWASP, ISO 27001, MITRE ATT&CK
- **Ecosystem**: Part of a larger suite (mcpserver-finder, mcpserver-builder, mcpserver-operator, audit-db, vulnerability-db)
- **Strengths**: CSA legitimacy, comprehensive AI-specific checks, community audit database
- **Weaknesses**: NOT a standalone tool — requires Claude Desktop to run, no web interface, hard to integrate into CI, operates as a tutoring assistant not an automated scanner

### Tool 3: tooltrust-scanner (AgentSafe-AI, on Glama)
- **Repo/page**: https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner
- **License**: MIT
- **Language**: **Go**
- **What it does**:
  - 16 static analysis rules (AS-001 through AS-017) covering:
    - Prompt injection in tool descriptions
    - Excessive permissions (exec, network, database, filesystem)
    - Arbitrary code execution capabilities
    - Supply chain via OSV database lookups
    - Known malware via offline blacklists
    - Privilege escalation patterns (admin/root/sudo)
    - Insecure secret handling
    - Typosquatting / tool shadowing
    - Missing rate limits
    - Suspicious npm lifecycle scripts
  - Assigns trust grades A–F
  - **Zero LLM calls** — pure static analysis, runs in milliseconds
  - Detected LiteLLM supply chain exploit (March 24, 2026) before widespread disclosure
  - Offline blacklist catches known-compromised packages instantly
- **Strengths**: Fast, deterministic, Go binary (no deps), supply chain focus, offline-capable
- **Weaknesses**: No web UI, CLI-only, no org management, no historical tracking

### Tool 4: mcp-security-audit (qianniuspace)
- **Repo**: https://github.com/qianniuspace/mcp-security-audit
- **npm**: `mcp-security-audit`
- **Language**: Node.js/TypeScript
- **What it does**: Audits **npm package dependencies** for known CVEs using npm registry data. Provides severity levels, CVSS scores, CVE references, fix recommendations. Compatible with npm/pnpm/yarn.
- **Scope**: Narrower than the others — focused specifically on npm dependency vulnerabilities within MCP projects, not MCP config files
- **Strengths**: Fills the npm supply chain gap
- **Weaknesses**: Narrowly scoped, no config-level analysis, no web UI

### Also in the ecosystem:
- **Cisco mcp-scanner v4.3.0** — YARA-based, enterprise-focused (not open source)
- **mcp-scan (Invariant Labs) v0.4.3** — academic tool from the researchers who disclosed Tool Poisoning Attacks
- **MCPAmpel** (on Glama) — aggregates findings from 16 scanning engines into trust scores
- **Glama Inspector** — https://glama.ai/mcp/inspector — web-based MCP server inspection tool

---

## 3. What Does NOT Exist Yet (The Gap)

| Capability | mcp-audit | tooltrust | mcpserver-audit | MCPGuard (proposed) |
|---|---|---|---|---|
| Web UI | No | No | No | **Yes** |
| Paste config, get report instantly | No (CLI) | No (CLI) | No (Claude Desktop) | **Yes** |
| Unified multi-engine results | No | No | No | **Yes** |
| Historical scan tracking | No | No | No | **Yes** |
| Team/org management | No | No | No | **Yes** |
| CI GitHub Action | mcp-audit has `--exit-code` | Has GitHub Action | No | **Yes (marketplace)** |
| Scheduled scans | No | No | No | **Yes** |
| Slack/email alerts | No | No | No | **Yes** |
| API access for automation | No | No | No | **Yes** |
| AI-BOM generation | Yes | No | No | Yes (via mcp-audit) |
| SARIF output | Yes | No | No | Yes (via mcp-audit) |
| MCP registry correlation | Partial | No | No | **Yes (full)** |
| Remediation guidance UI | No | No | No | **Yes** |
| Supply chain checks | No | Yes | No | **Yes** |
| AIVSS scoring | No | No | Yes | **Yes** |

---

## 4. Closest Commercial Analogs

### Socket.dev (best analog — study this model)
- **What**: Supply chain security for npm, PyPI, Go packages
- **Model**: Free tier (unlimited public repos) → $25/month Pro → Enterprise custom
- **GitHub integration**: GitHub App that PRs automatically get dependency risk analysis as PR comments
- **Key feature**: Proactive, not reactive — blocks malicious packages before they're installed
- **Revenue**: Raised Series A, commercially successful
- **The analog for MCPGuard**: Socket catches bad npm packages; MCPGuard catches bad MCP servers. Same positioning, different protocol layer.
- **Pricing source**: https://socket.dev/pricing

### Snyk
- **What**: Developer security platform — vulnerabilities in code, open source, containers, IaC
- **Model**: Free for individuals → $25/month Developer → $62/month Team → Enterprise
- **Key insight**: Snyk succeeded by meeting developers in their workflow (IDE plugin, CLI, CI), not by building a separate security dashboard. Follow this: CLI first, web second.

### 42Crunch / APIsec
- **What**: API security testing — static analysis of OpenAPI specs for security issues
- **Model**: Freemium → Enterprise
- **Relevance**: mcp-audit is literally made by APIsec Inc. — they built the CLI but left the SaaS platform gap open intentionally (or as future product)

### Checkmarx / Semgrep
- **What**: SAST tools with SaaS dashboards
- **Relevance**: Checkmarx already has an MCP security article. These will enter the MCP space — first mover advantage matters.

---

## 5. Is the Cloud Security Alliance (CSA) a Threat?

**Short answer: No — they're a legitimacy signal, not a competitor.**

- CSA's mcpserver-audit is intentionally NOT a SaaS product — it's an educational/community tool
- CSA doesn't build or sell commercial security products — they publish standards and frameworks
- Their audit-db is a community database — MCPGuard could **integrate and contribute to it** as a trust signal
- CSA backing = free credibility for the space overall
- Partnership opportunity: "MCPGuard implements CSA's MCP Security checklist"

---

## 6. Is Glama a Threat?

**Partial competitor — they're a registry/marketplace, not a security audit platform.**

- Glama has 44,392 MCP servers indexed and a basic inspector tool
- They host ToolTrust but don't own it; they're a distribution channel
- Glama's focus: discovery and hosting. MCPGuard's focus: security auditing of user configs
- **Integration opportunity**: MCPGuard could become Glama's recommended security partner, or offer a "Scan in MCPGuard" button from Glama listings

---

## 7. Regulatory Tailwinds

- **NSA Cybersecurity Information Sheet on MCP** (2026) — enterprise buyers now have NSA guidance that says "audit your MCP servers"
- **EU AI Act** — AI systems must be auditable; MCP server config is an attack surface
- **SOC 2 / ISO 27001** — security teams need evidence of MCP server audits for compliance
- **OWASP MCP Top 10** (beta) — once final, it becomes the reference checklist that CISOs demand compliance with
- **AI Bill of Materials (AI-BOM)** — CycloneDX 1.6 format is emerging as the standard; mcp-audit already generates this; MCPGuard can provide it as a deliverable

---

## 8. Who Pays for This?

### Individual developers (Free tier conversion funnel)
- Developer installs MCPGuard CLI for pre-commit hook
- Uses web UI occasionally for free
- Converts to Pro when they join a team or need CI integration

### Engineering teams / startups (Pro: $25/month)
- Using Claude/Cursor heavily, have MCP servers configured
- Need CI gate + team visibility + historical tracking

### Security teams at companies (Team: $99/month)
- CISOs being asked "are our MCP servers secure?" after NSA advisory
- Need compliance evidence, scheduled scans, Slack alerts

### Enterprises (Enterprise: custom)
- On-prem deployment (can't send config JSON to a cloud service)
- Custom SIEM integration
- Custom check rules
- SLA + support

---

## Sources

- [mcp-audit GitHub](https://github.com/apisec-inc/mcp-audit)
- [mcpserver-audit GitHub (CSA)](https://github.com/ModelContextProtocol-Security/mcpserver-audit)
- [tooltrust on Glama](https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner)
- [qianniuspace mcp-security-audit](https://github.com/qianniuspace/mcp-security-audit)
- [State of MCP Server Security 2025 — Astrix](https://astrix.security/learn/blog/state-of-mcp-server-security-2025/)
- [MCP Security Crisis 2026 — ChatForest](https://chatforest.com/builders-log/mcp-security-crisis-2026-unauthenticated-servers-viper-nsa-owasp-builder-guide/)
- [Censys: MCP Servers on the Internet](https://censys.com/blog/mcp-servers-on-the-internet/)
- [Socket.dev pricing](https://socket.dev/pricing)
- [Checkmarx MCP Security Risks](https://checkmarx.com/learn/mcp-security-risks-real-world-incidents-and-security-controls/)
- [The Hacker News — MCP coverage](https://thehackernews.com/search/label/MCP)
- [SmartLoader attack on MCP](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html)
- [Glama MCP Registry](https://glama.ai/mcp/servers)
- [Official MCP Registry](https://registry.modelcontextprotocol.io/)
- [ModelContextProtocol-Security GitHub org](https://github.com/ModelContextProtocol-Security)
- [OWASP MCP Top 10 — Practical DevSecOps](https://www.practical-devsecops.com/owasp-mcp-top-10/)
- [Timeline of MCP Breaches — AuthZed](https://authzed.com/blog/timeline-mcp-breaches)
- [7 MCP Registries Worth Checking Out — Nordic APIs](https://nordicapis.com/7-mcp-registries-worth-checking-out/)
