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
| SC-005 | MEDIUM | MCP04 | CWE-829 | `uv run --with <package>` installs arbitrary PyPI package at runtime |
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
| EX-001 | HIGH | MCP05 | CWE-506 | base64-encoded command in args (obfuscated code execution) |
| EX-002 | HIGH | MCP05 | CWE-78 | PowerShell encoded command (`-EncodedCommand` or `-enc`) |
| EX-003 | HIGH | MCP05 | CWE-78 | `curl | bash` or `wget | sh` pipe pattern in args |

---

## Tool Poisoning / Prompt Injection — PI, DX (tool_poisoning.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| PI-001 | HIGH | MCP03 | CWE-77 | Prompt injection patterns in args (role override, ignore-previous-instructions, etc.) |
| PI-002 | HIGH | MCP06 | CWE-116 | Invisible/zero-width Unicode characters in args (steganographic injection) |
| PI-003 | HIGH | MCP06 | CWE-116 | Horizontal scroll exploit (very long lines hiding malicious instructions) |
| PI-004 | HIGH | MCP03 | CWE-918 | Exfiltration webhook URL pattern in args |
| PI-005 | HIGH | MCP03 | CWE-77 | Tool override pattern (attempts to redefine trusted tool behavior) |
| DX-001 | HIGH | MCP06 | CWE-116 | Data exfiltration pattern in env var values |

---

## Audit & Telemetry — AT (scanner.py + audit.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| AT-001 | MEDIUM | MCP08 | CWE-1104 | Zero version pinning across the entire config (systemic rug pull risk) |
| AT-002 | INFO | MCP08 | — | No logging configured on any server |
| AT-003 | INFO | MCP08 | — | Telemetry explicitly disabled |
| AT-004 | INFO | MCP08 | — | Missing audit trail markers (no `--log-level`, `--audit`, etc.) |
| AT-005 | INFO | MCP08 | — | Excessive server count (10+ servers — large unreviewed attack surface) |
| AT-006 | MEDIUM | MCP04 | CWE-1104 | Docker image without pinned tag (`:latest`, no tag, or floating alias like `:stable`) |

---

## Lifecycle — LF (lifecycle.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| LF-001 | HIGH | MCP04 | CWE-829 | Dangerous lifecycle script (`postinstall`, `preinstall`) in fetched package |

---

## Config Level — CL, EC (config_level.py)

| ID | Severity | OWASP | CWE | What it detects |
|----|----------|-------|-----|-----------------|
| CL-001 | MEDIUM | MCP03 | CWE-1104 | Duplicate server names in config (tool name collision) |
| CL-002 | INFO | MCP02 | — | Server with neither command nor URL (likely misconfigured) |
| CL-003 | HIGH | MCP02 | CWE-284 | Cross-server scope escalation (server A has access server B's secrets) |
| EC-001 | HIGH | MCP07 | CWE-284 | Security feature explicitly disabled (TLS bypass, auth disable flags) |

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
| MCP01 | Token Mismanagement & Secret Exposure | SEC-001–008 |
| MCP02 | Privilege Escalation via Scope Creep | PE-001–009, CL-003, CHAIN-001–003 |
| MCP03 | Tool Poisoning | PI-001–005, SH-004, DX-001 |
| MCP04 | Supply Chain Attacks | SC-001–007, SEC-006, AT-001, AT-006, LF-001 |
| MCP05 | Command Injection & Execution | PE-002, PE-005, EX-001–003 |
| MCP06 | Prompt Injection via Contextual Payloads | PI-002–003, DX-001 |
| MCP07 | Insufficient Authentication | SH-002, SH-006, EC-001 |
| MCP08 | Lack of Audit and Telemetry | AT-001–006 |
| MCP09 | Shadow MCP Servers | SH-001, SH-003, SH-005, SC-001–002 |
| MCP10 | Context Injection & Over-Sharing | PE-004 |
