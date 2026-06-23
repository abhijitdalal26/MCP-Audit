# Validation Pitch — MCP Security Platform
*Use this to test real demand before building*

---

## Reddit Post (r/LocalLLaMA or r/ClaudeAI)

**Title:** I'm building a tool that audits your Claude/Cursor MCP config for security issues — would you use it?

---

Every time you add an MCP server to Claude Desktop or Cursor, you're giving that server access to your filesystem, shell, browser, or APIs. Most of us just paste the config JSON from a README without knowing what we're actually trusting.

I'm building a web tool where you paste your `claude_desktop_config.json` or `.cursor/mcp.json` and get back a security report in under 30 seconds. No signup required for the free scan.

**Why now:**
- NSA published an MCP security advisory in May 2026
- OWASP released the MCP Top 10 — a formal vulnerability taxonomy for MCP servers
- Censys found 8,000+ publicly exposed MCP servers with no authentication
- 40+ CVEs filed against MCP implementations in the first 60 days of 2026
- The 4 open-source audit tools that exist have no web UI, no unified report, and ~78% false positive rates

**What it checks:**
1. Exposed secrets — API keys, tokens, database passwords hardcoded in server configs
2. Shadow APIs — MCP tools that make undisclosed external calls
3. Privilege escalation — servers requesting more permissions than their stated purpose
4. Supply chain risk — known-malicious package names, typosquatting in server paths
5. Prompt injection surfaces — tool descriptions that could hijack your AI's behavior

**Free tier:** unlimited personal scans, shareable report links, no account needed.
**Paid:** team dashboard, scan history, GitHub Action CI integration, Slack alerts.

The question I actually want answered before I spend 3 months on this: **Do you audit your MCP servers before adding them? If not — why not, and would a tool like this change that?**

(Happy to share more technical details about how the scan engine works in comments.)

---

## Hacker News Version

**Show HN: MCPWatch — paste your MCP config, get a security report**

---

**First comment (from OP):**

I've been auditing MCP server configs for a side project and noticed a few things:

1. The existing CLI tools (mcp-audit, tooltrust-scanner) are solid but have no web UI. The barrier to a first scan is too high for most devs.
2. Pattern-based scanners flag ~78% false positives. I'm adding an LLM triage layer that explains *why* a finding is a real risk, not just "this string looks like a secret."
3. Nobody has mapped findings to OWASP's MCP Top 10 yet. The taxonomy exists but nothing implements it.

The MVP is simple: paste JSON, get a report. No backend stores your config — scans run ephemerally. The report is shareable via a hash URL (SHA256 of the config, so it's deterministic and doesn't require a database for anonymous scans).

Stack: Next.js 15 frontend, FastAPI backend (wraps mcp-audit and tooltrust-scanner as subprocesses), Supabase for scan history on paid tier, Inngest for async job queue.

Looking for two things:
- Would you use this before adding an MCP server to Claude Desktop or Cursor?
- What checks are you most worried about that I haven't listed?

Repo will be open-source (scan engine). Dashboard is closed-source for now, but I'll open-source if there's community interest.

---

## Quick Landing Page Copy (for pre-launch validation)

**Headline:** Know what your MCP servers can actually do.

**Subhead:** Paste your Claude Desktop or Cursor config. Get a security report in 30 seconds. Free, no account required.

**CTA:** Scan My Config →

**Social proof hook:** NSA, DoD, and OWASP have all published MCP security guidance in 2026. Your AI tools are only as safe as the servers they connect to.

---

## What to measure from the validation post

Post it. Wait 48 hours. A green light to build looks like:
- 20+ upvotes on Reddit OR 100+ HN points
- At least 5 comments describing a *specific* pain point ("I had this exact problem when...")
- At least 2 people asking "when can I use it?"
- Zero comments saying "X already does this perfectly" (that would mean you need to look harder at competitors)

A red light looks like:
- "Just use mcp-audit" with no complaints about it
- "MCP is already secure by design" (means people don't feel the pain yet)
- Under 10 upvotes after 24 hours
