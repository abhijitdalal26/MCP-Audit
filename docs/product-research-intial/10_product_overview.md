# Product Overview — What We're Actually Building

---

## What It Is (One Line)

> "Paste your MCP config or connect your repo — we tell you every security risk before it reaches production or before you install a server you shouldn't trust."

---

## The Two Audiences

### Audience 1 — Normal User (MCP Consumer)
Someone using Claude Desktop, Cursor, Windsurf etc. with a bunch of MCP servers installed. Not a security person. Has no idea how many permissions they've silently approved, what those servers are accessing, or what data is being sent where.

### Audience 2 — MCP Builder / Developer
Someone actively building and shipping an MCP server. Wants to pass a security bar before going to production or publishing to Glama/Smithery.

---

## Use Cases

### Audience 1 — Normal User (MCP Consumer)

1. **"What does this MCP server actually have access to?"**
   They installed a filesystem MCP and have no idea it can read their entire home directory, not just the project folder they intended.

2. **"Is this MCP server sending my data somewhere?"**
   Does it make outbound network calls? To where? Does the tool description hint at exfiltration?

3. **"How many permissions have I silently approved?"**
   They clicked "approve" 50 times in Cursor and have no memory of what they allowed.

4. **"Is this package legit or a fake?"**
   They installed `@modelcontextprotcol/filesystem` (typo, one missing letter) and don't know it's a typosquatted malicious package.

5. **"Is this MCP server trying to manipulate my AI?"**
   The tool description contains hidden instructions that change how Claude behaves without the user knowing (tool poisoning).

6. **"Does this server have any known security vulnerabilities?"**
   The npm package it uses has a CVE filed against it last week.

7. **"Which of my 12 installed servers is the riskiest?"**
   Ranked risk overview so they know where to focus first.

8. **"I found this MCP server on Reddit, is it safe to install?"**
   Pre-install check before adding it to their config.

9. **"Can I share my MCP config with my team without leaking secrets?"**
   They have API keys in the env block and don't realize it.

---

### Audience 2 — MCP Builder / Developer

1. **"Is my server safe to publish?"**
   Scan before pushing to npm or listing on a public registry like Glama or Smithery.

2. **"Did I accidentally hardcode a secret?"**
   API key, DB password, or token left in the source code.

3. **"Are my tool descriptions clean?"**
   No accidental phrasing that could be detected as prompt injection by scanners or flagged by enterprise security teams.

4. **"Am I requesting more permissions than I need?"**
   Over-broad filesystem or shell access that would fail a security review.

5. **"Do my dependencies have CVEs?"**
   Before shipping v1.0, check every npm/PyPI package in the dependency tree.

6. **"Will this pass a CI security gate?"**
   Run the scan in GitHub Actions on every PR — fail the build if a critical finding appears.

7. **"What's my OWASP MCP Top 10 coverage?"**
   Compliance checklist for enterprise customers who ask "are you OWASP compliant?"

8. **"Did my latest update introduce a new risk?"**
   Diff between last scan and current scan — surface only what's new, not everything again.

9. **"Can I get a security badge for my repo?"**
   Grade A certification to put in the README and signal trust to users installing the server.

---

### Overlap — Both Audiences

- **"Give me a shareable report"** — consumer sharing with IT security, builder sharing with a customer's security team.
- **"Alert me when something changes"** — a server they trust today gets a new CVE tomorrow, or a tool description changes unexpectedly.

---

## Why the Volume vs. Money Split Matters

| | Consumer (Audience 1) | Builder (Audience 2) |
|---|---|---|
| Volume | High — far more people install MCP servers than build them | Lower |
| Willingness to pay | Low — expects free tier | Higher — professional need, has a budget |
| Conversion path | Free paste-and-scan → upgrade when they hit team features | CLI + GitHub Action → Pro/Team from day one |
| Marketing channel | Reddit, Twitter, word of mouth | GitHub, HN, dev newsletters, MCP registries |

**Strategy:** Consumer volume drives traffic and free-tier signups. Builder use cases drive paid conversion and enterprise revenue.
