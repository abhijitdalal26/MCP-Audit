# Research Papers & New Technical Findings
*Additions from supplemental LLM research — items not covered in files 01–08*

---

## 1. MCP-Specific Research Papers (2026)

These three papers directly inform scanning logic. Two are from 2026 and the links weren't provided by the source — search titles on Google Scholar / arXiv / SPIE / MDPI to find them.

---

### Paper A — McpSafetyScanner (SPIE, June 2026)

**Title:** "MCP safety audit: LLMs with the model context protocol allow major security exploits"  
**Venue:** SPIE, June 2026  
**Link:** *Search title on [SPIE Digital Library](https://www.spiedigitallibrary.org/) — direct URL not provided by source*

**Why it matters:**  
Introduces `McpSafetyScanner` — an **agentic scanner** that uses an LLM to automatically generate adversarial test cases against live MCP servers. Instead of static patterns, it actively tries to exploit the server and observes the result. Detects code execution and credential theft attack paths that static analysis misses.

**What to borrow:**  
The Stage 4 LLM triage layer could adopt this agentic adversarial testing approach — not just "does this look bad?" but "can I actually exploit this?" This is the direction for the moat.

---

### Paper B — Horizontal Scrolling Exploit (MDPI, May 2026)

**Title:** "Model Context Protocol Threat Modeling and Analysis of Vulnerabilities to Prompt Injection with Tool Poisoning"  
**Venue:** MDPI, May 2026  
**Link:** *Search title on [MDPI](https://www.mdpi.com/) — direct URL not provided by source*

**Why it matters:**  
Proves that **traditional static validation fails against prompt-based manipulation**. Key finding: malicious parameters can be hidden in approval dialogs by exploiting **horizontal scrolling in desktop clients** (Claude Desktop, Cursor). The visible portion of the dialog looks safe; the injected payload is off-screen to the right.

**What to borrow:**  
Add a check (PI-003) that flags tool descriptions or parameter schemas exceeding a width threshold, or containing content that would be cut off in standard dialog rendering. This is a concrete, novel check no existing tool does.

---

### Paper C — eBPF Runtime Monitoring (arXiv, March 2026)

**Title:** "Auditing MCP Servers for Over-Privileged Tool Capabilities"  
**Link:** https://arxiv.org/html/2603.21641v1 *(already in 05_features_and_roadmap.md sources)*

**What's new here (not captured before):**  
The paper's implementation, `mcp-sec-audit`, uses a **dual-stream analysis**:
1. Static inspection of Python source code
2. **Dynamic eBPF monitoring inside a Docker sandbox** — captures syscalls and file I/O at the kernel level during live execution

This is the technical blueprint for deep runtime analysis (Stage 4 / Enterprise tier). eBPF tracing gives ground-truth evidence of what a server actually does at runtime, not just what its code claims. This is what justifies the "compute-heavy enterprise tier" vs. static free tier split.

---

## 2. Foundational Academic Papers (Pre-2026)

These are the papers that established the theoretical basis for MCP security threats. Useful for credibility when pitching enterprises and for grounding the scanning heuristic engine.

---

### Indirect Prompt Injection (Foundational)

**Title:** "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"  
**Authors:** Greshake et al. (2023)  
**Link:** https://arxiv.org/abs/2302.12173

Foundational work on how data returned by tools can manipulate the host agent. This is the theoretical basis for what PI-001 (suspicious tool description keywords) and PI-002 (excessively long descriptions) detect.

---

### Prompt Injection Taxonomy

**Title:** "Prompt Injection Attacks on LLM-Integrated Applications"  
**Authors:** Liu et al. (2023)  
**Link:** https://arxiv.org/abs/2306.05499

Provides a formal taxonomy of injection channels including tool descriptions and returned data. Maps directly to the OWASP MCP03/MCP06 checks.

---

### Red Teaming via LLM

**Title:** "Red Teaming Language Models with Language Models"  
**Authors:** Perez et al. (2022)  
**Link:** https://arxiv.org/abs/2202.03286

Methodology for automated adversarial discovery — the ancestor of the McpSafetyScanner approach above. Useful for designing the Stage 4 agentic triage system.

---

### Supply Chain on Package Managers

**Title:** "Towards Measuring Supply Chain Attacks on Package Managers for Interpreted Languages"  
**Authors:** Duan et al. (2021)  
**Link:** https://arxiv.org/abs/2002.01139

Grounds the SC-001–SC-004 supply chain checks in academic literature. Useful when writing the enterprise pitch ("our checks are grounded in peer-reviewed research").

---

### Capability-Based Sandboxing (Apple)

**Title:** "Genie: Secure, Capability-Based AI Assistants"  
**Authors:** Apple (2024)  
**Link:** *Search "Apple Genie capability-based AI" — paper is from Apple Research, not on arXiv as of knowledge cutoff*

Practical sandboxing approach for limiting agent capabilities at the tool level. Directly parallels the eBPF + Docker sandbox approach for dynamic MCP server execution.

---

## 3. New Implementation Techniques

These were not in the existing research files and are relevant to architecture decisions.

---

### WASM / Pyodide for Client-Side Scanning

**Concept:** For the "paste config" free tier, compile Python scanners (mcp-audit) to WebAssembly using Pyodide, so the MCP config **never leaves the user's browser**. The scan runs entirely client-side.

**Why it matters:** The #1 objection from security-conscious users is "I'm not uploading my config with API keys to a random SaaS." Client-side scanning eliminates this objection entirely and is a marketing differentiator.

**Trade-off:** WASM builds are larger and slower than native. Acceptable for lightweight config scanning; not viable for full source code analysis or eBPF runtime monitoring.

**Suggested tier split:**
- Free tier: client-side WASM scan (zero data leaves browser)
- Pro/Team: server-side scan with full engine suite (user accepts ToS on data handling)

---

### gVisor (runsc) for Sandbox Execution

**What:** Google's gVisor intercepts syscalls in userspace, providing a lightweight kernel sandbox around untrusted processes. Faster to spin up than a full VM; harder to escape than standard Docker.

**Where to use:** When executing an actual MCP server for dynamic analysis (Stage 4 / Enterprise). Use `docker run --runtime=runsc` to get gVisor isolation around the server process.

**Compared to standard Docker:** Standard Docker shares the host kernel. If an MCP server has a container escape, it's on your host. gVisor intercepts at the syscall layer, limiting blast radius.

---

### Firecracker MicroVMs for Serverless Dynamic Scanning

**What:** AWS's Firecracker provides sub-100ms VM boot times with real hardware isolation. Used natively by AWS Lambda under the hood.

**Where to use:** If hosting dynamic scans on AWS Lambda (pay-per-invocation), Firecracker gives true VM isolation per scan without dedicated EC2 instances. Each scan gets a fresh, isolated microVM.

**Cost implication:** Suitable for the enterprise tier's "on-demand deep scan" feature. Not cost-effective for high-frequency free-tier scans.

---

### Version Pinning Strategy for Upstream Tools

**Problem:** mcp-audit and tooltrust evolve independently. An upstream update that changes their JSON output format breaks your normalization layer silently.

**Solution options:**
1. Docker images with tagged versions — `apisec/mcp-audit:1.0.0` — your backend calls the container, not the binary directly
2. Git submodules pinned to specific commit SHAs
3. Abstract the tool calls behind an adapter interface so swapping versions only requires changing the adapter, not the report renderer

**Why this matters now:** tooltrust is updated almost daily (v0.3.19 as of June 21, 2026). Without version pinning, a prod deploy at 3am can break because upstream pushed a new output field.

---

## 4. New Strategic Angles

### Proactive Crawler for Zero-Latency Reports

**Concept:** Run a background crawler that continuously scans public GitHub repos and Glama listings for MCP server configs. Cache the scan results. When a user pastes a config that references a known public server (`npx @modelcontextprotocol/server-filesystem`), return the cached report **instantly** instead of running a scan on-demand.

**Why it's a differentiator:** Competing tools all scan on-demand. If you've already scanned the 7,000 most popular Smithery servers and cached the results, your tool appears dramatically faster for the common case.

**Risk:** Must not cache or store user-specific configs (the parts with API keys). Only cache results for the server package itself, not the user's `env` block.

---

### Co-Marketing with Glama/tooltrust

**Angle:** Rather than competing with tooltrust's web UI, position your platform as a **meta-layer** that calls their scanner as one input and adds the others. This reframes Glama/tooltrust from "competitor" to "partner data source." Pitch: "MCPGuard drives traffic to your scanner results via our unified report; tooltrust grades get featured prominently."

**Practical implication:** If tooltrust's API becomes available, call it server-side rather than running the binary. This also means tooltrust's rule updates automatically flow into your reports.

---

## 5. New Attack Pattern to Add as a Check

### PI-003: Horizontal-Scroll Hidden Injection

**Source:** Paper B above (MDPI, May 2026)

**What it detects:** Tool descriptions or parameter `description` fields that are very long on a single line (no newlines) — content that would be horizontally scrolled in a dialog box, hiding the malicious portion off-screen.

**Implementation:** Check if any tool description or parameter description has a single line > 300 characters without whitespace wrapping. Flag as MEDIUM. If it also contains injection keywords, escalate to HIGH.

**Why no existing tool catches this:** Static keyword scanners look for known bad phrases. This check targets the *delivery mechanism* (scroll hiding) regardless of payload content.
