# Existing MCP Security Tools — Deep Research
(date: 2026-06-22)

---

## Table of Contents
1. [Tool 1: mcp-audit (APIsec Inc.)](#1-mcp-audit--apisec-inc)
2. [Tool 2: mcpserver-audit (Cloud Security Alliance / ModelContextProtocol-Security)](#2-mcpserver-audit--cloud-security-alliance)
3. [Tool 3: tooltrust-scanner (AgentSafe-AI)](#3-tooltrust-scanner--agentsafe-ai)
4. [Tool 4: mcp-security-audit (qianniuspace)](#4-mcp-security-audit--qianniuspace)
5. [Tool 5: skill-audit-mcp (eltociear)](#5-skill-audit-mcp--eltociear)
6. [Critical Finding: MCPGuard Already Exists](#6-critical-finding-mcpguard-already-exists)
7. [Comparative Summary Table](#7-comparative-summary-table)
8. [Key Gaps Across All Tools](#8-key-gaps-across-all-tools)
9. [References](#references)

---

## 1. mcp-audit — APIsec Inc.

**Repo:** https://github.com/apisec-inc/mcp-audit  
**Stars:** 150 | **Forks:** 41 | **License:** MIT | **Open Issues:** 1  
**Latest Release:** v1.0.0 (January 15, 2026)  
**Primary Language:** Python (58.5%), JavaScript (22.7%), HTML (6%), TypeScript (4.4%)

### What It Detects

**Config-level scanning (`scan` command):**
- 25+ secret patterns: AWS keys, GitHub PATs, database credentials, API tokens
- Exposed APIs: database connections, REST endpoints, SaaS integrations, cloud services
- AI model configs: OpenAI, Anthropic, Google, Meta, Mistral, Ollama
- Risk flags: shell access, filesystem permissions, unverified sources

**Source-level scanning (`source-scan`, v1.1):**
- Code-level vulnerabilities in MCP server source (JS/TS/Python)
- "Prompt In, Shell Out" injection patterns
- Unsanitized tool arguments passed to shell-spawning APIs
- Maps findings to OWASP LLM Top 10 (2025)

### How It Works
Two operational modes:
1. **Web App** — scans GitHub repositories via personal access tokens
2. **CLI Tool** — discovers and analyzes MCP configs on local disk (Claude Desktop, Cursor, VS Code, Windsurf, Zed)

Matches against a registry of 50+ known MCPs plus custom pattern libraries. 100% local execution for CLI mode; no telemetry.

### Input Format
- Local filesystem paths (MCP configs auto-discovered)
- GitHub repository URLs (web app)
- MCP server source code directories

### Output Formats
- Table (human-readable, default)
- JSON (CI/CD integration)
- CSV / Markdown
- **CycloneDX 1.6** (AI-BOM — supply chain compliance)
- **SARIF** (GitHub / GitLab Security tab integration)
- PDF reports (email delivery)

### Risk Classification

| Level | Scope | Examples |
|-------|-------|---------|
| Critical | Full system access | Database admin, shell, cloud IAM |
| High | Write access | Filesystem mutations, API writes |
| Medium | Read + limited write | SaaS integrations, restricted DB |
| Low | Read-only | Public APIs, memory storage |

### Key CLI Commands
```bash
mcp-audit scan [--secrets-only|--apis-only|--models-only]
mcp-audit source-scan ./path [--format json|sarif] [--exit-code]
mcp-audit registry [--risk critical] lookup "name"
mcp-audit explain risk-flag-name
```

### API / Programmatic Interface
- GitHub API (via PAT for web app)
- CycloneDX 1.6 spec
- SARIF output (standard format)
- CI/CD exit-code gating

### Known Limitations
- Does NOT detect runtime environment variable secrets
- Does NOT detect dynamically generated configurations
- Does NOT detect secrets in external vaults (AWS Secrets Manager, HashiCorp Vault)
- Cannot access private repos outside scope
- Cannot parse encrypted/obfuscated values
- Misses MCPs in non-standard locations
- "A clean scan does not mean zero risk" — their own caveat

### Assessment
**Most mature tool in the group.** Has the widest feature set, SBOM output, CI/CD integration, and a maintained registry of known MCPs. Best-positioned for enterprise compliance use cases. However, still CLI/web-app based with no unified dashboard across multiple scan engines.

---

## 2. mcpserver-audit — Cloud Security Alliance

**Repo:** https://github.com/ModelContextProtocol-Security/mcpserver-audit  
**Stars:** 19 | **Forks:** 4 | **License:** Apache-2.0 | **Open Issues:** 1  
**Commits:** 21 total on main branch  
**Organization:** ModelContextProtocol-Security (Cloud Security Alliance community project)

### What It Detects

**MCP-Specific Threats:**
- Prompt injection attacks
- Confused deputy vulnerabilities
- Token theft / OAuth issues
- Data exfiltration risks
- Protocol violations
- Cross-origin security issues

**AI-Specific Vulnerabilities:**
- Direct/indirect prompt manipulation
- Model manipulation attacks
- Training data poisoning
- Output interception
- Context poisoning
- Model denial-of-service

**Standard Categories:**
- Credential management failures
- Network security issues
- Dependency vulnerabilities
- Configuration weaknesses

### How It Works
**NOT a traditional automated scanner.** Operates as an MCP server that runs inside AI-compatible clients (Claude Desktop, etc.). It functions as a "knowledgeable security tutor" — it teaches users to identify vulnerabilities rather than purely automating detection.

Technical analysis methods:
1. Static code analysis (pattern detection)
2. Dependency scanning (known CVEs)
3. Configuration review
4. Protocol compliance verification
5. Permission analysis

Uses **AIVSS (AI Vulnerability Scoring System)** — combines traditional CVSS with AI-specific risk factors.

### Input Format
- Source code files from MCP servers
- Dependency manifests
- Configuration files
- Project structure

### Output Format
- Vulnerability findings with AIVSS/CVSS scores
- CWE mappings
- Risk assessment reports
- Remediation guidance
- Security education summaries
- Findings publishable to community `audit-db` and `vulnerability-db`

### Three-Tool Ecosystem
1. **mcpserver-audit** (this) — finds vulnerabilities
2. **mcpserver-builder** — fixes identified issues
3. **mcpserver-operator** — secure deployment guidance

### Known Limitations
- "Many vulnerability types exist but don't have dedicated check files yet"
- Educational focus over comprehensive automation
- Designed as expert advisor, not complete implementation
- Low adoption (19 stars)
- No standalone CLI; must run through MCP-compatible client
- Technology is primarily prompt/configuration-based, not compiled code

### Assessment
**Legitimacy signal is high** (Cloud Security Alliance backing), but **product maturity is low**. The educational approach is interesting but not what developers need for rapid CI/CD security gates. The AIVSS scoring is a novel contribution worth watching. The `audit-db` community database is a differentiator if it grows.

---

## 3. tooltrust-scanner — AgentSafe-AI

**Repo:** https://github.com/AgentSafe-AI/tooltrust-scanner  
**Glama page:** https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner  
**Stars:** 16 | **Forks:** 6 | **License:** MIT | **Open Issues:** 0  
**Latest Release:** v0.3.19 (June 21, 2026 — actively maintained)  
**Primary Language:** Go (97.8%)

### What It Detects — 19 Security Rules

| Rule | Severity | What It Catches |
|------|----------|----------------|
| AS-001 | Critical | Adversarial prompts in tool descriptions |
| AS-002 | High/Low | Over-broad permission surfaces |
| AS-003 | High | Tool name vs. permission mismatches |
| AS-004 | High/Critical | Known CVEs in dependencies via OSV |
| AS-005 | High | Privilege escalation patterns |
| AS-006 | Critical | Arbitrary code execution patterns |
| AS-007 | Info | Missing tool descriptions/schemas |
| AS-008 | Critical | Confirmed compromised packages (LiteLLM, Trivy, Langflow) |
| AS-009 | Medium | Typosquatting detection |
| AS-010 | Medium | Insecure credential handling |
| AS-011 | Low | Missing DoS resilience configs |
| AS-012 | High | Tool set changes without version bumps |
| AS-013 | High/Medium | Tool shadowing/duplication |
| AS-014 | Info | Missing dependency inventory |
| AS-015 | Medium/High | Suspicious npm lifecycle scripts |
| AS-016 | Critical | Malicious IOC package detection |
| AS-017 | Medium | Data exfiltration descriptions |
| AS-018 | Info | Embedded MCP server detection |
| AS-019 | High | Unauthenticated MCP route exposure |

### How It Works
Pure **static analysis** — no LLM calls, no data exfiltration. Four-step process:
1. **Parse** — connects to live MCP servers or reads JSON tool definitions
2. **Analyze** — runs 19 static rules against tool name, description, schema, permissions
3. **Grade** — assigns numeric risk score → letter grade (A–F)
4. **Enforce** — maps to policy: ALLOW / REQUIRE_APPROVAL / BLOCK

**Offline embedded blacklist** of confirmed supply-chain attacks (zero network dependency for blacklist checks). Optional CVE lookups via OSV for dependency scanning.

### Grading System
- **A/B:** ALLOW
- **C/D:** REQUIRE_APPROVAL
- **F:** BLOCK

Research: 207 MCP servers analyzed, 3,235 tools → only 10% achieved Grade A; 70% had at least one finding; 16 servers had arbitrary code execution patterns.

### Input Format
- Live MCP server connections (stdio transport)
- JSON tool definition blobs
- MCP config files (`.mcp.json`, `~/.claude.json`)

### Output
- Risk reports with grades and enforcement decisions
- JSON scan results
- **ToolTrust Directory** — public grades at `tooltrust.dev`
- Badge system (Grade A certification)

### MCP Tools Exposed
| Tool | Function |
|------|---------|
| `tooltrust_scan_config` | Scan all servers in local MCP config |
| `tooltrust_scan_server` | Launch and scan specific server |
| `tooltrust_scanner_scan` | Scan raw JSON tool definitions |
| `tooltrust_lookup` | Query ToolTrust Directory |
| `tooltrust_list_rules` | Show all built-in rules |

### Installation
```bash
# One-line
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash

# Go
go install github.com/AgentSafe-AI/tooltrust-scanner/cmd/tooltrust-scanner@latest

# npx
npx -y tooltrust-mcp
```

### GitHub Actions Integration
Integrates as GitHub Action with `fail-on` parameter.

### Known Limitations
- AS-012 (tool drift detection) only runs in ToolTrust Directory pipeline, not local CLI
- Primarily evaluates **tool-level** metadata, not full server source code
- No semantic/LLM-based analysis
- Low star count despite being most technically polished of the four tools

### Assessment
**Most technically refined tool** in the group. Pure Go, offline-capable, deterministic, fast (milliseconds), CI-ready. The A–F grading system is intuitive. The ToolTrust Directory is a genuine differentiator — a public reputation database for MCP servers. The supply-chain blacklist is a strong practical feature. **Primary gap: only assesses tool definitions, not full source code analysis or secret scanning.**

---

## 4. mcp-security-audit — qianniuspace

**Repo:** https://github.com/qianniuspace/mcp-security-audit  
**Glama page:** https://glama.ai/mcp/servers/@qianniuspace/mcp-security-audit  
**Stars:** 53 | **Forks:** 9 | **License:** MIT | **Open Issues:** 0  
**Latest Release:** v1.0.4 (February 21, 2025)  
**Commits:** 23 total  
**Primary Language:** TypeScript (71.1%), JavaScript (22.6%), Docker (6.3%)

### What It Detects
**npm package dependency vulnerabilities only:**
- CVE identifiers and GitHub advisory IDs
- CVSS scoring and attack vectors
- CWE references
- Severity: critical, high, moderate, low
- Automated fix recommendations with target version numbers

### How It Works
Integrates with **npm registry API** for real-time vulnerability scanning. Cross-references project dependencies against known security advisories. Not a static code analyzer — purely dependency vulnerability lookup.

### Input Format
- npm package names (provided via MCP tool calls)
- Project dependency manifests

### Output Format
JSON objects containing:
- Package name, current version, detected severity
- CVE/advisory references and descriptions
- Fix availability and target upgrade version
- CVSS score and attack vector
- Request timestamp and package manager type

### Installation
```bash
# Via Smithery
npx -y @smithery/cli install @qianniuspace/mcp-security-audit --client claude

# Via npx direct
npx -y mcp-security-audit
```

### Compatibility
- Cursor IDE
- Cline extension
- Claude Desktop (via Smithery)

### Known Limitations
- **Scope is extremely narrow**: npm packages only — no Python, no Go, no Ruby
- Does not scan MCP configurations
- Does not detect secrets, prompt injection, or supply chain attacks
- No source code analysis
- Last significant update: February 2025 (relatively old)
- Depends entirely on npm registry API availability

### Assessment
**Most limited tool in the group.** Essentially a thin wrapper over `npm audit` delivered as an MCP server. Useful as a building block but not a security product in itself. The narrow npm-only scope means it solves only one layer of a multi-layer problem.

---

## 5. skill-audit-mcp — eltociear

**Glama page:** https://glama.ai/mcp/servers/eltociear/skill-audit-mcp  
**GitHub:** https://github.com/eltociear/skill-audit-mcp (inferred)  
**Primary Language:** Python  
**Distribution:** npm, Docker, GitHub Action, MCP server, hosted API

### What It Detects — 68 Attack Patterns (4 severity levels)
- Credential exfiltration patterns
- Arbitrary code execution
- Prompt injection
- Obfuscation techniques
- External downloads (unauthorized)
- Supply chain attack patterns

Complements companion tool **secrets-audit-mcp** which detects leaked credentials across 32 provider types.

### How It Works
**Static pattern scanner** (like a specialized linter for MCP servers, skills, and plugins). Generates:
- Security findings with risk scoring (0–100 scale: SAFE → CRITICAL)
- SARIF output for GitHub Code Scanning integration

### Input Format
- Source code files and directories of MCP servers
- AI agent skills
- Plugins

### Output Format
- Risk score (0-100)
- SARIF (GitHub Security tab integration)
- JSON
- Human-readable report

### Deployment Options
1. Docker: `docker run --rm -v "$PWD:/work" ghcr.io/eltociear/skill-audit-mcp:v1 --path /work`
2. CLI: `npx @eltociear/skill-audit-mcp --path ./server.py`
3. GitHub Action (CI/CD workflow)
4. MCP Server (Claude Desktop/Cursor)
5. Pre-commit hook
6. **Hosted API** ($0.01 USDC per scan via x402 micropayment; 1,000 free scans/month)

### Pricing
Free open-source; optional paid x402 API for server-side batch scanning.

### Known Limitations
- Pattern-based: susceptible to false positives (as documented in the AppSecSanta audit — ~78% FP rate for YARA-style scanning)
- Python-based scanner for a mixed-language ecosystem
- No config-level scanning (secrets in env vars, API configs)
- No runtime monitoring

### Assessment
**Good breadth of pattern coverage** (68 patterns) and **best deployment flexibility** of any tool. The hosted API with x402 micropayments is a novel monetization approach. The SARIF integration for GitHub is strong for DevSecOps workflows. **Key gap: high false positive rate inherent to pattern-based approaches.**

---

## 6. Critical Finding: MCPGuard Already Exists

**The proposed brand name "MCPGuard.io" is already taken.** Multiple products use the MCPGuard name:

### MCPGuard (mcpguardapp.com)
Built by **ZentriTools**. Web-based scanner:
- Enter package name/URL → security report
- Detects: CVEs, OAuth bypass, injection vectors, supply chain risks, runtime behavior
- Pricing: Free (3 scans/day) / Pro $9/mo / Team $49/mo
- Launched in response to April 2026 critical CVE disclosures

### MCPGuard (usemcpguard.io)
- Scans GitHub repositories for MCP server vulnerabilities
- Returns 403 on direct access (private/beta?)

### MCPGuard (Virtue AI)
- AI-powered scanner built into VirtueAgent platform
- Uses LLM to understand code semantics
- Has scanned 700+ open-source MCP servers
- Found critical vulnerabilities in 78% of implementations

### MCPGuard (Research Paper)
- arXiv: 2510.23673 — academic tool, not productized

**Implication:** Any new product needs a different brand name and must differentiate clearly from these existing MCPGuard products.

---

## 7. Comparative Summary Table

| Dimension | mcp-audit | mcpserver-audit | tooltrust | mcp-security-audit | skill-audit-mcp |
|-----------|-----------|----------------|-----------|-------------------|----------------|
| Stars | 150 | 19 | 16 | 53 | N/A |
| Language | Python+JS | Prompt-based | Go | TypeScript | Python |
| Active? | Yes (2026) | Yes (2026) | Yes (daily) | No (2025) | Yes (2026) |
| Config scan | ✅ | ❌ | ✅ (tool defs) | ❌ | ❌ |
| Source scan | ✅ | ✅ | ❌ | ❌ | ✅ |
| Secret scan | ✅ 25+ patterns | ❌ | ❌ | ❌ | ✅ (via companion) |
| Dep scan | ❌ | ✅ | ✅ CVEs via OSV | ✅ npm only | ❌ |
| Prompt injection | ✅ | ✅ | ✅ AS-001 | ❌ | ✅ |
| Supply chain | ✅ | ✅ | ✅ (blacklist) | ❌ | ✅ |
| Runtime monitor | ❌ | ❌ | ❌ | ❌ | ❌ |
| CI/CD | ✅ SARIF/JSON | ❌ | ✅ GitHub Action | ❌ | ✅ GitHub Action |
| AI-BOM/SBOM | ✅ CycloneDX | ❌ | ❌ | ❌ | ❌ |
| Web UI | ✅ (GitHub scan) | ❌ | ❌ | ❌ | ❌ (hosted API) |
| License | MIT | Apache-2.0 | MIT | MIT | OSS + paid API |
| LLM-based | ❌ | Partial | ❌ | ❌ | ❌ |
| Grading system | Risk levels | AIVSS | A–F | CVE severity | 0-100 score |

---

## 8. Key Gaps Across All Tools

### Gap 1: No Unified Input → Report Interface
No tool accepts a raw MCP config JSON blob in a browser and returns a consolidated report combining multiple scanners. Users currently must run 2–3 separate tools and manually synthesize results.

### Gap 2: High False Positive Rates
The April 2026 AppSecSanta audit found ~78% false positive rate in YARA-based scanning. No tool has solved semantic understanding of tool descriptions to distinguish normal documentation from adversarial prompts.

### Gap 3: No Cross-Tool Correlation
Each tool sees only its own results. No product correlates: "This server has a secret in the config (mcp-audit) AND the source has a prompt injection (skill-audit) AND the dependency has a known CVE (tooltrust)" — all in one finding.

### Gap 4: No Runtime Monitoring at Scale
All tools are point-in-time scanners. None offer continuous behavioral baselining across sessions or cross-session drift detection (flagged as critical gap in PipeLab state-of-security report).

### Gap 5: No Unified Audit Log Schema
Identified by PipeLab as a missing standard: no cross-tool format for MCP audit logs that allows aggregation and analysis.

### Gap 6: Individual Developer UX is Broken
Developers using Claude Desktop or Cursor must install 3+ tools, learn different CLIs, and manually correlate results. The on-ramp friction kills adoption of any individual tool.

### Gap 7: Team/Org-Level Visibility
No tool provides a team dashboard showing the security posture of all MCP servers used across a development team. Every tool is single-user.

### Gap 8: Supply Chain Verification (SBOM + Provenance)
PipeLab identifies "supply chain verification (SBOM, provenance, hash-pinning enforcement)" as missing. mcp-audit does CycloneDX AI-BOM, but doesn't enforce hash pinning or verify provenance chains.

---

## References

All URLs visited during research:

- https://github.com/apisec-inc/mcp-audit
- https://github.com/ModelContextProtocol-Security/mcpserver-audit
- https://github.com/ModelContextProtocol-Security/audit-db
- https://github.com/ModelContextProtocol-Security/mcpserver-finder
- https://github.com/ModelContextProtocol-Security
- https://github.com/AgentSafe-AI/tooltrust-scanner
- https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner
- https://github.com/qianniuspace/mcp-security-audit
- https://glama.ai/mcp/servers/@qianniuspace/mcp-security-audit
- https://glama.ai/mcp/servers/eltociear/skill-audit-mcp
- https://glama.ai/mcp/servers/eltociear/mcp-security-audit
- https://mcpguardapp.com/
- https://usemcpguard.io/
- https://arxiv.org/abs/2510.23673
- https://arxiv.org/html/2510.23673v1
- https://pipelab.org/blog/state-of-mcp-security-2026/
- https://appsecsanta.com/research/mcp-server-security-audit-2026
- https://www.truefoundry.com/blog/best-mcp-security-tools
- https://www.akto.io/blog/mcp-security-tools
- https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html
- https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
- https://mcpscan.ai/
- https://github.com/cisco-ai-defense/mcp-scanner
- https://tooltrust.dev
- https://blog.virtueai.com/2025/08/22/mcpguard-first-agent-based-mcp-scanner-to-protect-ai-agents/
- https://www.csoonline.com/article/4181230/claude-code-has-an-mcp-security-problem-and-your-developers-are-already-using-it.html
- https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-security-crisis-20260504-csa-styled/
