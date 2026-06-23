# MCPAudit Research Directory

Active research that extends the engine beyond what existing scanners do.
Each subdirectory is one research thread: background, implementation, tests.

---

## Research 1 — Unicode Steganography Detection
**Directory:** `unicode_steganography/`  
**Engine checks added:** PI-005, SC-006  
**Status:** Complete — integrated into main engine

### Why this was chosen over other options

The engine has 41 checks as of 2026-06-23. After auditing every check, there is a specific
blind spot: **actual decoded Unicode characters in config values are never scanned**.

- PI-004 catches `\uXXXX` as a *literal escape sequence* in text (6 chars: backslash, u, 4 hex digits).
- SH-004 catches non-ASCII Unicode *letters* (category "L") in server *names*.
- **Nothing** catches zero-width characters (category "Cf") or bidi override characters in args,
  env values, or package names.

An attacker can embed U+200B (Zero Width Space) throughout an injection payload in an arg string.
In Claude Desktop's approval dialog, these characters render as nothing — the arg looks empty or
harmless. The LLM processes the full decoded string including the invisible content.

The Trojan Source vulnerability (CVE-2021-42574) demonstrated that bidi override characters
(U+202E RTL Override) can make text *appear* to say one thing in a UI while actually saying
another when processed by a parser. The same technique applies to MCP tool descriptions and args.

No competing scanner (mcp-audit, tooltrust, McpSafetyScanner) implements this check.

**Research finding:** Two distinct check IDs cover the full attack surface:
- PI-005: invisible/zero-width/bidi Unicode in args and env values
- SC-006: non-ASCII characters in package names (homoglyph package spoofing via args)

---

## Research 2 — Cross-Server Capability Chain Analysis
**Directory:** `cross_server_chains/`  
**Engine checks added:** CHAIN-001, CHAIN-002, CHAIN-003  
**Status:** In progress (next loop iteration)

### Why this was chosen over other options

Every existing MCP security check (this engine included) analyzes servers in isolation.
But MCP configs typically list 5–15 servers simultaneously. A sophisticated attacker does not
need a single server to be dangerous — they need two servers whose capabilities *compose*
into something dangerous.

Classic example:
- Server A: filesystem MCP with write access to `/tmp`
- Server B: shell execution MCP that can run scripts

Neither server alone is flagged as critical. Together they form a complete remote code execution
chain: A writes a script, B executes it. The attacker controls both via prompt injection.

Academic basis: arxiv.org/pdf/2507.06250 "We Urgently Need Privilege Management in MCP"
identifies capability over-privilege but does not model inter-server composition.

No existing scanner performs cross-server graph analysis. This is a genuine research contribution.

---

## Why these 2 and not others

Other research candidates considered and deprioritized:

| Candidate | Why deprioritized |
|---|---|
| Live MCP registry API correlation | Adds network latency; SC-003 + SH-001 cover the static case already |
| WASM/Pyodide client-side scanning | Frontend architecture concern, not a new detection capability |
| LLM-powered semantic description analysis | Requires Stage 4 (Claude API integration); not a static engine addition |
| gVisor/Firecracker dynamic sandbox | Runtime infrastructure, not a check-level research item |
| Levenshtein distance typosquatting | SC-002 already has targeted regex; fuzzy matching adds false positives |

Unicode steganography and cross-server chains were chosen because:
1. They are completely undetected by the current engine (genuine gap)
2. They are implementable as static checks (no network, no LLM, no runtime)
3. No competing tool does them
4. They map to documented real-world attack techniques
