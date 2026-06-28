# MCPAudit Check Reference

All 51+ check IDs, their severity, OWASP category, CWE, and what they detect.
Used by the website results UI for labels and the CLI for text output.

## Secrets — SEC (secrets.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| SEC-001 | CRITICAL | MCP01 | CWE-798 | AWS Access Key ID (`AKIA...`) in env/args/headers |
| SEC-002 | CRITICAL | MCP01 | CWE-798 | GitHub/GitLab tokens (`ghp_`, `glpat-`) |
| SEC-003 | CRITICAL | MCP01 | CWE-798 | DB connection strings with embedded credentials (postgres://, mysql://, mongodb://) |
| SEC-004 | HIGH | MCP01 | CWE-798 | API keys: OpenAI (`sk-`), Anthropic (`sk-ant-`), Stripe, Slack, HuggingFace, etc. |
| SEC-005 | HIGH | MCP01 | CWE-312 | JWT tokens or SSH private keys |
| SEC-006 | MEDIUM | MCP04 | CWE-1104 | Unpinned npm package (`@latest` or no version) — rug pull risk |
| SEC-007 | CRITICAL | MCP01 | CWE-918 | Cloud IMDS endpoint (169.254.169.254) — IAM credential theft |
| SEC-008 | HIGH | MCP01 | CWE-312 | Credentials embedded in the `url:` field of an HTTP MCP server |

Checks env vars, HTTP headers, command args, and the `url:` field.
Ignores placeholder values (`${VAR}`, `<your-key>`, `xxx`).

---

## Supply Chain — SC (supply_chain.py + osv_lookup.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| SC-001 | CRITICAL | MCP04 | CWE-829 | Known malicious/compromised package (from curated blocklist) |
| SC-002 | HIGH | MCP04 | CWE-829 | Typosquatting pattern in package name (misspelled `@modelcontextprotocol`, leet-speak, etc.) |
| SC-003 | MEDIUM | MCP04 | CWE-1104 | Unverified npm scope (not in trusted scope list like @anthropic, @microsoft, etc.) |
| SC-004 | varies | MCP04 | CWE-1035 | Live OSV.dev CVE lookup — flags packages with known CVEs |
| SC-005 | HIGH | MCP04 | CWE-829 | Direct VCS ref dependency (`github:user/repo`, `bitbucket:user/repo`, `gitlab:user/repo`) — bypasses npm registry entirely: no integrity hash, no audit trail, maintainer can force-push and silently change what runs next invocation. |
| SC-008 | HIGH | MCP04 | CWE-494 | VCS URL install (`git+https://`, `git+ssh://`, `git+http://`) or tarball URL (`https://...tar.gz`, `https://...zip`) as package argument — bypasses registry integrity checks same as SC-005 but via URL syntax rather than shorthand. |
| SC-006 | HIGH | MCP04 | CWE-1007 | Unicode homoglyph characters in package name (visual spoofing) |
| SC-007 | HIGH | MCP04 | CWE-829 | Custom registry/index-url override (Birsan-style dependency confusion) |

---

## Privilege Escalation — PE (privilege.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| PE-001 | HIGH | MCP02 | CWE-732 | Filesystem server with over-broad path (`/Users`, `/`, `C:\`, etc.) |
| PE-002 | HIGH | MCP05 | CWE-77 | Shell execution keyword in args (`--shell`, `/bin/bash`, `--eval`, etc.) |
| PE-003 | HIGH | MCP02 | CWE-250 | Admin/root credential env var (`SUDO_PASSWORD`, `ROOT_TOKEN`, `ADMIN_KEY`) |
| PE-004 | MEDIUM | MCP10 | CWE-732 | Database connection without explicit read-only flag |
| PE-005 | CRITICAL | MCP05 | CWE-250 | Docker container with dangerous flags: `--privileged`, `--cap-add=all`, `--network=host`, `--pid=host`, or sensitive volume mount (`-v /etc:/...`) |
| PE-006 | CRITICAL | MCP02 | CWE-250 | Server command is `sudo`, `su`, `doas`, `pkexec`, or `runas` |
| PE-007 | CRITICAL | MCP02 | CWE-284 | Permission bypass flag: `--dangerously-skip-permissions` or similar |
| PE-008 | HIGH | MCP02 | CWE-22 | Path traversal sequence (`..`) in server args |
| PE-009 | HIGH | MCP02 | CWE-250 | Docker `--cap-add` with dangerous capability: `SYS_ADMIN`, `SYS_PTRACE`, `NET_ADMIN`, `DAC_OVERRIDE`, `SYS_MODULE`, etc. |

---

## Shadow Servers — SH (shadow.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| SH-001 | INFO | MCP09 | CWE-829 | Package not in MCPAudit's verified allowlist (informational — not necessarily malicious) |
| SH-002 | HIGH | MCP07 | CWE-319 | HTTP MCP server (non-localhost) without TLS |
| SH-003 | LOW | MCP09 | CWE-346 | Localhost URL backed by remotely-fetched npm package (unpinned remote execution) |
| SH-004 | HIGH | MCP03 | CWE-1007 | Unicode homoglyph in server NAME (Tool Name Spoofing — Adversa AI Top 25 #12) |
| SH-005 | HIGH | MCP09 | CWE-284 | Auto-discovery env var (`MCP_AUTO_DISCOVERY=true`) enabling silent plugin loading |
| SH-006 | MEDIUM | MCP07 | CWE-306 | HTTP/SSE transport server with no authentication env vars, headers, or URL params |

---

## Code Execution — EX (code_execution.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| EX-001 | CRITICAL | MCP05 | CWE-78 | Inline code execution patterns in args: `python -c`, `node -e`, `eval()`, `exec()`, `subprocess.call()`, `os.system()`, `child_process`, `Runtime.getRuntime().exec()` |
| EX-002 | HIGH | MCP05 | CWE-78 | Command substitution / shell injection syntax in args: `$()`, backticks, `{{}}` template injection, process substitution `<()`, chained shell commands (`;rm`, `;curl`), pipe-to-interpreter |
| EX-003 | CRITICAL | MCP05 | CWE-116 | Three obfuscated execution patterns: (a) PowerShell `-EncodedCommand`/`-ec` flag followed by Base64 payload; (b) `curl`/`wget` piped to `bash`/`sh`/`python`; (c) `exec(base64.b64decode(...))` Python b64 decode-and-execute. All three decoded and previewed in finding. |

---

## Tool Poisoning / Prompt Injection — PI, DX (tool_poisoning.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| PI-001 | HIGH | MCP03 | CWE-77 | Prompt injection keywords in args OR env vars: "ignore previous instructions", "override system prompt", "you are now", "developer mode", "DAN mode", LLM control tokens (`[INST]`, `<<SYS>>`, `<system>`), etc. |
| PI-002 | MEDIUM | MCP06 | CWE-400 | Excessively long combined args (>2000 chars total) — may be hiding injected instructions or obfuscated payloads within what appears to be normal configuration. |
| PI-003 | HIGH/MEDIUM | MCP03 | CWE-693 | Horizontal-scroll injection: single arg >300 chars on one line with no newlines. Content past the viewport is hidden in Claude Desktop / Cursor approval dialogs. Severity HIGH if injection keywords also present, MEDIUM otherwise. |
| PI-004 | HIGH | MCP03 | CWE-116 | Obfuscation via escape sequences in args: 4+ consecutive `\uXXXX` unicode escapes or `\xXX` hex escapes. Classic payload obfuscation — `Ignore` decodes to "Ignore" but looks like gibberish in UI. |
| PI-005 | HIGH/MEDIUM | MCP03 | CWE-116 | Invisible/zero-width/bidi-override Unicode steganography in args, env vars, OR server name. Detects Zero Width Space, ZWNJ, ZWJ, Soft Hyphen, Mongolian Vowel Separator, RTL Override (Trojan Source CVE-2021-42574), etc. Severity HIGH if bidi override present. |
| DX-001 | HIGH | MCP03 | CWE-200 | Data exfiltration patterns in args OR env var values: "send data to", "POST to https://", webhook/callback URL references, "steal/harvest credentials", BCC/blind-copy rules, email forwarding rules (Postmark Sep 2025 incident). |

---

## Audit & Telemetry — AT (scanner.py + audit.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| AT-001 | MEDIUM | MCP08 | CWE-1104 | Zero version pinning across the entire config — ALL servers have unpinned packages (systemic rug pull / supply chain risk). Fires only when no server has any pinned package. |
| AT-002 | LOW | MCP08 | CWE-16 | Transport ambiguity: server has BOTH `command` AND `url` fields declared. An MCP server uses one transport (stdio or HTTP/SSE), not both; this combination suggests misconfiguration or obfuscation. |
| AT-003 | INFO | MCP08 | CWE-16 | Remote server URL without explicit `transport` declaration — MCP client must guess the protocol, which can lead to unexpected behavior. Exempt if `transport: sse/http/streamable-http/ws` is set. |
| AT-004 | HIGH | MCP08 | CWE-668 | Server bound to all network interfaces (`0.0.0.0` or `[::]` in URL) — exposes MCP tools to the entire local network. NeighborJack pattern: any device on same WiFi can invoke tools without auth. |
| AT-005 | INFO | MCP08 | — | Excessive server count (10+ servers) — large unreviewed attack surface; each server adds risk. |
| AT-006 | MEDIUM | MCP04 | CWE-1104 | Docker image without pinned tag (`:latest`, no tag, or floating alias like `:stable`) — image may change without notice between invocations. |

---

## Lifecycle — LF (lifecycle.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| LF-001 | MEDIUM | MCP04 | CWE-912 | `npx -y <package>` without `--ignore-scripts` — npm will execute `preinstall`/`install`/`postinstall` scripts automatically on install. Static flag check: does not inspect the package itself, but flags the configuration that allows lifecycle scripts to run. Only fires when both `-y`/`--yes` flag is present AND `--ignore-scripts` is absent. |

---

## Config Level — CL, EC (config_level.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| CL-001 | HIGH | MCP02 | CWE-441 | Confused deputy: single server combining broad filesystem access AND shell execution (or secrets AND shell). Neither permission is dangerous in isolation; together they enable silent file exfiltration. |
| CL-002 | MEDIUM | MCP03 | CWE-290 | Duplicate server package: two servers run the exact same `command` + package, which may indicate a tool-shadowing attack where a malicious server intercepts calls from the legitimate one. |
| CL-003 | HIGH | MCP07 | CWE-295 | Security feature explicitly disabled via env var: `NODE_TLS_REJECT_UNAUTHORIZED=0`, `DISABLE_AUTH=true`, `SKIP_TLS_VERIFY=true`, `SSL_VERIFY=false`, etc. |
| CL-004 | CRITICAL/HIGH/MEDIUM | MCP07 | CWE-284 | `autoApprove` / `alwaysAllow` bypasses per-tool user confirmation. Wildcard (`*` or `true`) → critical. Partial list (≥5 tools) → high. Partial list (<5 tools) → medium. |
| EC-001 | MEDIUM | MCP01 | CWE-532 | Debug logging enabled (`LOG_LEVEL=debug`, `VERBOSE=true`) AND hardcoded secrets present in the same server — debug logs often capture env vars and HTTP headers in plaintext. |

---

## Cross-Server Chain Analysis — CHAIN (chain_analysis.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| CHAIN-001 | HIGH | MCP02 | CWE-732 | Filesystem server + code execution server in same config (combined breakout risk) |
| CHAIN-002 | CRITICAL | MCP02 | CWE-200 | Credential-access server + HTTP/network server (exfiltration chain) |
| CHAIN-003 | HIGH | MCP02 | CWE-732 | Shadow server + privileged server (stealth + impact chain) |

---

## OWASP MCP Top 10 Category Reference

| Category | Name | Checks that cover it |
|----------|------|----------------------|
| MCP01 | Token Mismanagement & Secret Exposure | SEC-001–008, EC-001 |
| MCP02 | Privilege Escalation via Scope Creep | PE-001–009, CL-001, CHAIN-001–003 |
| MCP03 | Tool Poisoning | PI-001–005, SH-004, DX-001, CL-002 |
| MCP04 | Supply Chain Attacks | SC-001–007, SEC-006, AT-001, AT-006, LF-001 |
| MCP05 | Command Injection & Execution | PE-002, PE-005, EX-001–003 |
| MCP06 | Prompt Injection via Contextual Payloads | PI-002 |
| MCP07 | Insufficient Authentication | SH-002, SH-006, CL-003, CL-004 |
| MCP08 | Lack of Audit and Telemetry | AT-001–006 |
| MCP09 | Shadow MCP Servers | SH-001, SH-003, SH-005, SC-001–002 |
| MCP10 | Context Injection & Over-Sharing | PE-004 |
