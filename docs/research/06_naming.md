# Naming Research — MCP Security Platform
*Research date: 2026-06-23*

---

## Name Availability Results

| Name | Status | Notes |
|------|--------|-------|
| MCPGuard | **TAKEN** | usemcpguard.io, mcpguardapp.com, Virtue AI — 3 separate products |
| MCPScan | **TAKEN** | mcpscan.ai (web service), antgroup/MCPScan (GitHub), Snyk acquired Invariant Labs' mcp-scan |
| MCPLens | **TAKEN** | Exists as MCP server on Glama (TypeScript project, vmsfigueredo/mcplens) |
| MCPVault | **TAKEN** | mcpvault.org (Obsidian bridge), bitbonsai/mcpvault on GitHub |
| ToolSentry | **Likely free** | No results found for this name |
| MCPWatch | **Likely free** | No product found — generic MCP security articles only |
| MCPRadar | **Likely free** | No results found |
| MCPSafe | Not checked | — |
| SentryMCP | Not checked | Note: Sentry.io is a big brand — potential confusion |
| AuditMCP | Not checked | Directional but available likely |

**Always verify with a domain registrar (Namecheap, Porkbun) and GitHub org search before committing.**

---

## Newly Discovered Competitors (found during name search)

These were NOT in the original research — they emerged from the naming searches:

- **AgentAuditKit** — GitHub Marketplace Action for MCP security scanning. Finds misconfigurations, hardcoded secrets, tool poisoning, rug pulls, trust boundary violations across 13 agent platforms. This is a direct competitor to the CI integration angle.
- **LuciferForge/mcp-security-audit** — Purpose-aware scoring, injection testing, compliance checks. Scores 0-100, grades A-F. More sophisticated than the original 4 tools.
- **Proximity** — Open-source MCP security scanner covered by Help Net Security (Oct 2025).
- **mcpscan.ai** — Web-based scanner (paste config, get report). This is exactly the MVP described in 00_INDEX.md. Verify feature depth before building the same thing.

**Action: Read mcpscan.ai before writing a single line of code.** If it already does the paste-and-scan flow well, the MVP needs to be differentiated from day 1.

---

## Recommended Names (Top 3)

### 1. MCPWatch
- Clean, two syllables, brandable
- "Watch" implies continuous monitoring — maps to the runtime monitoring gap nobody has filled
- mcpwatch.io likely available
- No existing product found

### 2. ToolSentry  
- Not MCP-specific — works even if MCP gets renamed/replaced
- "Sentry" = guard/watchman, strong security connotation
- Avoids confusion with Sentry.io because it's a different category (dev tools vs. security audit)
- toolsentry.io likely available

### 3. MCPRadar
- "Radar" = detecting threats before they hit you
- Good for the "know what's in your environment" positioning
- mcpradar.io likely available

---

## 5 Fresh Name Ideas (Snyk/Socket/Semgrep style)

These are short, not literally descriptive, and feel like a real startup:

1. **Vectara** — no, taken. But the pattern: short, invented word
2. **Fathom** — "fathom your MCP stack" — depth/insight metaphor. Check availability.
3. **Clearbit** — already taken, but the pattern works: clear + bit
4. **Lockstep** — security + orchestration metaphor. Check availability.
5. **Prism** — refract/reveal what's hidden in your tools. Likely taken.
6. **Verdant** — too vague
7. **Quiltt** — too abstract

Better approach: combine a security verb with a short suffix:
- **Skopeio** (scope/observe) — check
- **Vanta** — taken (SOC2 compliance startup)
- **Cloakd** — check
- **Scanrift** — check (scan + adrift/exposed)
- **Warden** — likely taken but check warden.io or warden.dev

**Honest recommendation:** Go with **MCPWatch** for now. It's literal enough that people understand it, brandable enough for a product, and the "watch" framing lets you expand into runtime monitoring as V2 without a rebrand.

---

## Sources

- [mcpscan.ai](https://mcpscan.ai/)
- [antgroup/MCPScan — GitHub](https://github.com/antgroup/MCPScan)
- [Snyk agent-scan (formerly mcp-scan)](https://github.com/invariantlabs-ai/mcp-scan)
- [MCP-Scan on Thoughtworks Technology Radar](https://www.thoughtworks.com/en-us/radar/tools/mcp-scan)
- [mcplens on Glama](https://glama.ai/mcp/servers/vmsfigueredo/mcplens)
- [mcpvault.org](https://mcpvault.org/)
- [bitbonsai/mcpvault — GitHub](https://github.com/bitbonsai/mcpvault)
- [AgentAuditKit — GitHub Marketplace](https://github.com/marketplace/actions/agentauditkit-mcp-security-scan)
- [LuciferForge/mcp-security-audit — GitHub](https://github.com/LuciferForge/mcp-security-audit)
- [Proximity open-source scanner — Help Net Security](https://www.helpnetsecurity.com/2025/10/29/proximity-open-source-mcp-security-scanner/)
