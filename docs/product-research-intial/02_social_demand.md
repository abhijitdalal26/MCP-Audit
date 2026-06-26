# Social & Community Demand Research — MCP Security
**Date: 2026-06-22** | Research compiled for MCPGuard.io concept evaluation

---

## CRITICAL FINDING UPFRONT: The Name "MCPGuard" Is Already Taken

Before anything else — **MCPGuard already exists as multiple products**:

| Brand | URL | Description |
|---|---|---|
| MCPGuard (Azentiq Nexus Pte Ltd) | https://usemcpguard.io/ | Commercial SaaS, GitHub repo scanning, real-time vulnerability reports |
| MCPGuard App | https://mcpguardapp.com/ | Real-time monitoring of live MCP connections, checks against CVE database |
| MCPGuard (Virtue AI) | https://blog.virtueai.com/2025/08/22/mcpguard-first-agent-based-mcp-scanner-to-protect-ai-agents/ | Agent-based scanner built into VirtueAgent platform |
| MCPGuard (ArXiv paper) | https://arxiv.org/pdf/2510.23673 | Academic paper: "MCPGuard: Automatically Detecting Vulnerabilities in MCP Servers" |
| mcp-guard (open source) | https://github.com/SaravanaGuhan/mcp-guard | Open-source CLI tool on GitHub |

**The brand name cannot be used as-is without IP/brand collision risk.** The concept of a unified dashboard is still valid — just needs a different name.

---

## 1. The Security Problem Is Real and Growing Fast

### Timeline of MCP Security Incidents (Monthly Cadence)

| Month | Incident | Impact |
|---|---|---|
| April 2025 | WhatsApp MCP chat history exfiltrated via tool poisoning | Demonstrated real rug-pull attack |
| May 2025 | GitHub MCP prompt injection leaking private repo contents | Developers affected |
| June 2025 | MCP Inspector unauthenticated RCE (CVE-2025-49596, CVSS 9.4); Asana cross-tenant data exposure | Active exploitation |
| July 2025 | mcp-remote OS command injection (CVE-2025-6514) — 437,000+ developer environments affected | Massive scale |
| August 2025 | Anthropic Filesystem MCP sandbox escape | Core product affected |
| September 2025 | Postmark MCP insider attack — BCC'd all emails to attacker for 2 weeks (~300 orgs); Flowise RCE | First confirmed supply chain via MCP |
| October 2025 | Smithery platform breach — path traversal exposed env credentials for 3,000+ hosted MCP apps; Figma/Framelink command injection | Platform-level compromise |
| November 2025 | Shai-Hulud 2.0 npm worm targets MCP packages specifically | Supply chain escalation |
| January 2026 | Gemini MCP Tool 0-day (CVE-2026-0755, CVSS 9.8) — unauthenticated RCE | Cross-platform |
| February 2026 | Malicious Oura MCP clone distributing StealC malware | Registry supply chain |
| March 2026 | nginx-ui MCP auth bypass (CVE-2026-33032, CVSS 9.8) — 2,600+ instances exposed | |
| April 2026 | Core Anthropic MCP STDIO design flaw affecting 150M+ downloads; RCE in Letta AI, LangFlow, Windsurf | Systemic |

**Source:** https://authzed.com/blog/timeline-mcp-breaches

### Named CVEs in the MCP Layer (2025 alone)
- CVE-2025-6514
- CVE-2025-49596
- CVE-2025-54136
- CVE-2025-54994

---

## 2. Developer Pain Points — Documented & Real

Research from Astrix Security (2025) scanning 5,200+ open-source MCP server implementations:
- **88%** require credentials
- **53%** use insecure long-lived static secrets (API keys, PATs)
- Only **8.5%** use OAuth (the recommended method)
- Fewer than **30%** of AI systems had any structured audit trails of agent tool access

Research from Equixly (March 2025):
- **43%** of tested MCP implementations had command injection vulnerabilities
- **30%** vulnerable to SSRF attacks
- **22%** allowed arbitrary file access
- **492** internet-exposed MCP servers with zero authentication found by Trend Micro

**Source:** https://astrix.security/learn/blog/state-of-mcp-server-security-2025/  
**Source:** https://equixly.com/blog/2025/03/29/mcp-server-new-security-nightmare/

---

## 3. Institutional Validation — Not Just Developer Chatter

### Government & Standards Bodies Have Weighed In

| Organization | Output |
|---|---|
| **NSA** | Published "Model Context Protocol (MCP) Security" advisory: https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf |
| **DoD / media.defense.gov** | Published MCP security guidance June 2, 2026: https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF |
| **OWASP** | Published OWASP MCP Top 10 (beta, 2025): https://owasp.org/www-project-mcp-top-10/ |
| **Cloud Security Alliance** | Backing ModelContextProtocol-Security project: https://labs.cloudsecurityalliance.org/agentic/agentic-mcp-security-best-practices-v1/ |
| **Anthropic, AWS, Microsoft, OpenAI** | MCP maintainers published joint enterprise security roadmap: https://thenewstack.io/mcp-maintainers-enterprise-roadmap/ |
| **CoSAI (Coalition for Secure AI)** | Agentic AI working group covering MCP: https://github.com/cosai-oasis/ws4-secure-design-agentic-systems/blob/main/model-context-protocol-security.md |

### Research Papers

| Paper | Link |
|---|---|
| "A First Look at the Security Issues in the Model Context Protocol Ecosystem" | https://arxiv.org/abs/2510.16558 |
| "Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning" | https://arxiv.org/abs/2603.22489 |
| "MCP-DPT: A Defense-Placement Taxonomy and Coverage Analysis for MCP Security" | https://arxiv.org/pdf/2604.07551 |
| "Auditing MCP Servers for Over-Privileged Tool Capabilities" | https://arxiv.org/html/2603.21641v1 |
| "MCPGuard: Automatically Detecting Vulnerabilities in MCP Servers" | https://arxiv.org/pdf/2510.23673 |
| "New Prompt Injection Attack Vectors Through MCP Sampling" (Palo Alto Unit42) | https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/ |

---

## 4. Hacker News — Discussion Evidence

Multiple active HN threads on MCP security (all accessible):

| Thread | URL |
|---|---|
| "I just published some notes on MCP security and prompt injection" (Simon Willison) | https://news.ycombinator.com/item?id=43632112 |
| "Model Context Protocol (MCP): Landscape, Security Threats and Research Direction" | https://news.ycombinator.com/item?id=43686305 |
| "Everything wrong with MCP" | https://news.ycombinator.com/item?id=43676771 |
| "Enterprise-Grade Security for the Model Context Protocol (MCP)" | https://news.ycombinator.com/item?id=44397262 |
| "Zero-Touch OAuth for MCP" | https://news.ycombinator.com/item?id=48592163 |

Simon Willison's original blog post on MCP prompt injection: https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/

**Reddit:** Direct Reddit scraping returned no results via web search — the site: operator is unreliable for this kind of query. Recommend manually checking r/ClaudeAI, r/cursor, r/LocalLLaMA for current sentiment.

---

## 5. VC Investment — The Money Is Flowing

**Total disclosed funding for pure-play MCP security: ~$40 million across 4 startups**

| Company | Amount | Investors | Notes |
|---|---|---|---|
| Operant AI | $13.5M Series A | SineWave, Felicis | Pivoted toward MCP security |
| Runlayer | $11M seed | Khosla Ventures, Felicis | 8 unicorn customers in 4 months |
| Helmet Security | $9M | SYN Ventures | End-to-end MCP lifecycle protection |
| Manufact | $6.3M seed | Peak XV | Feb 2026; "MCP as USB-C for AI" thesis |

**Source:** https://venturebeat.com/infrastructure/manufact-raises-usd6-3m-as-mcp-becomes-the-usb-c-for-ai-powering-chatgpt-and  
**Source:** https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/

**Broader context:** VC firms invested **$14B+ in cybersecurity globally in 2025** (strongest year since 2021 peak).

---

## 6. Enterprise Demand — Compliance Is Now a Driver

- **EU AI Act** enforcement with penalties up to 7% of global revenue
- **Cisco State of AI Security 2026**: Only 29% of organizations feel prepared to secure agentic AI — 71% running AI agents they cannot monitor
- **MCP Security Engineer salaries**: $152,000–$210,000; Lead Architects $200,000–$280,000+ (20–30% premium over general security roles)
- MCP security listed as a required skill in enterprise procurement/compliance checklists

**Source:** https://www.practical-devsecops.com/mcp-security-jobs-salaries-2026/

---

## 7. Existing Tool Landscape (The Fragmentation Problem Is Real)

### The 4 Tools Mentioned in the Original Idea

| Tool | Stars (GitHub) | Maintainer | Focus | Limitations |
|---|---|---|---|---|
| apisec-inc/mcp-audit | ~150 | APIsec (commercial) | Config scanning: secrets, APIs, AI-BOM. 8 MCP clients supported. | CLI-only, no web UI |
| ModelContextProtocol-Security/mcpserver-audit | ~19 | Cloud Security Alliance (community) | Source code scanning, AIVSS scoring, CWE mapping, educational focus | Very low adoption, CLI/chat agent |
| tooltrust-scanner (AgentSafe-AI) | Not found | AgentSafe-AI on Glama | Pre-install gate: grades A–F, 16 static rules, detects compromised packages | No web UI, scanner-only |
| qianniuspace/mcp-security-audit | N/A | Community | Audits npm dependencies only, not MCP-specific threat model | Very narrow scope |

**Source for mcp-audit:** https://github.com/apisec-inc/mcp-audit  
**Source for mcpserver-audit:** https://github.com/ModelContextProtocol-Security/mcpserver-audit  
**Source for tooltrust:** https://github.com/AgentSafe-AI/tooltrust-scanner

### Other Existing Competitors (Not in Original Scope)

| Tool/Product | Type | Notes |
|---|---|---|
| MCPGuard (usemcpguard.io) | Commercial SaaS | Already uses your proposed brand name |
| MCPGuardApp (mcpguardapp.com) | Commercial SaaS | Real-time CVE monitoring |
| Virtue AI MCPGuard | Embedded in VirtueAgent | Agent-based scanner |
| mcp-scan | Open-source CLI | v0.4.3 actively used in audits |
| Cisco mcp-scanner | Enterprise CLI | v4.3.0, used in April 2026 audit |
| Lasso Security | VC-backed startup | MCP-specific security |
| Straiker.ai | Commercial | Tool poisoning + rug pull prevention |
| TrueFoundry MCP Gateway | Platform | Unified dashboard + billing |
| MintMCP | Platform | SaaS security gateway |
| Operant AI MCP Gateway | Commercial | VC-backed ($13.5M) |

**Source:** https://mcpmanager.ai/blog/mcp-security-tools/  
**Source:** https://www.truefoundry.com/blog/best-mcp-security-tools

---

## 8. OWASP MCP Top 10 (2025, Beta)

The authoritative threat taxonomy every audit tool maps to:

1. MCP01:2025 — Token Mismanagement & Secret Exposure
2. MCP02:2025 — Supply Chain Compromise
3. MCP03:2025 — Command Injection
4. MCP04:2025 — Prompt Injection
5. MCP05:2025 — Tool Poisoning
6. MCP06:2025 — [Listed in beta; categories still stabilizing]
7. MCP07:2025 — Insufficient Authentication & Authorization
8. MCP08:2025 — [Listed in beta]
9. MCP09:2025 — Shadow MCP Servers (ungoverned deployments)
10. MCP10:2025 — Context Over-Sharing

**Source:** https://owasp.org/www-project-mcp-top-10/  
**Source:** https://pipelab.org/learn/owasp-mcp-top10/

---

## 9. Market Scale Context

- **10,000+** active public MCP servers confirmed by Anthropic (December 2025)
- **17,000+** total deployed MCP servers per Helmet Security research
- **44,392** open-source MCP servers in the Glama registry alone
- MCP adopted by: Claude, Cursor, VS Code, Windsurf, Zed, GitHub Copilot, ChatGPT, Gemini, Microsoft Copilot
- **150M+ downloads** affected by the April 2026 core STDIO design flaw

---

## 10. Key Articles to Read

| Article | URL |
|---|---|
| Simon Willison: MCP and prompt injection | https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/ |
| Palo Alto Unit42: MCP attack vectors | https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/ |
| Authzed: Full incident timeline | https://authzed.com/blog/timeline-mcp-breaches |
| Checkmarx: 11 emerging MCP risks | https://checkmarx.com/zero-post/11-emerging-ai-security-risks-with-mcp-model-context-protocol/ |
| Equixly: MCP servers — the new security nightmare | https://equixly.com/blog/2025/03/29/mcp-server-new-security-nightmare/ |
| PipeLab: State of MCP Security 2026 | https://pipelab.org/blog/state-of-mcp-security-2026/ |
| AppSec Santa: MCP Server Security Audit 2026 findings | https://appsecsanta.com/research/mcp-server-security-audit-2026 |
| Dev Genius: "I Built an Open-Source Security Scanner for MCP Servers" | https://blog.devgenius.io/i-built-an-open-source-security-scanner-for-mcp-servers-heres-why-f2842acfbc64 |
| Glasp: MCP Security 2026 — Tool Poisoning & Supply Chain | https://glasp.co/articles/mcp-security-tool-poisoning-supply-chain |
| Astrix: State of MCP Server Security 2025 Report | https://astrix.security/learn/blog/state-of-mcp-server-security-2025/ |
| SentinelOne: MCP Security Complete Guide | https://www.sentinelone.com/cybersecurity-101/cybersecurity/mcp-security/ |
| Adversa AI: Top 25 MCP Vulnerabilities | https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/ |
| TrueFoundry: Best MCP Security Tools in 2026 | https://www.truefoundry.com/blog/best-mcp-security-tools |
| Practical DevSecOps: MCP Security Guide 2026 | https://www.practical-devsecops.com/mcp-security-guide/ |

---

## 11. Demand Verdict

**Is demand real?** Yes — unambiguously.

Evidence:
- Monthly security incidents with real victims since April 2025
- NSA and DoD publishing advisories
- OWASP Top 10 for MCP published
- $40M in VC investment in MCP security specifically
- 71% of enterprises can't properly monitor their AI agents (Cisco)
- 437,000+ developer environments already compromised in one incident
- 44,000+ MCP servers in the wild with no unified security posture visibility

**Is the "fragmented tools, no unified dashboard" gap real?** Partially. The gap was more open in 2025. By mid-2026, several commercial products (TrueFoundry, MintMCP, MCPGuard) are filling the unified dashboard space. The window is narrowing but not closed — especially for:
- Individual developers / small teams (most tools target enterprise)
- CLI + web combo with OWASP MCP Top 10 as the output framework
- CI integration that wraps multiple underlying scanners

**The brand name "MCPGuard" is taken.** The project needs a different name before any further work.

---

*Sources summary: NSA, DoD, OWASP, Cloud Security Alliance, Palo Alto Unit42, Checkmarx, SentinelOne, Authzed, Astrix Security, Equixly, Glasp, PipeLab, AppSec Santa, Dev Genius, Cisco, Practical DevSecOps, VentureBeat, Crunchbase, GitHub (multiple repos)*
