# Research 2: Cross-Server Capability Chain Analysis

**Status:** In progress — implementation scheduled for next loop iteration.

## Problem Statement

All 43 existing checks in the MCPAudit engine analyze servers in isolation.
A config with 10 servers is treated as 10 independent scan targets.
This misses an entire class of vulnerabilities that emerge from *server composition*.

Two individually benign servers can form a dangerous capability chain when their
permissions and tool sets are composed together. No existing MCP scanner does
cross-server graph analysis.

## Attack Scenario: Write-Execute Chain

```json
{
  "mcpServers": {
    "docs": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-filesystem", "/tmp"]
    },
    "shell": {
      "command": "npx",
      "args": ["mcp-server-shell"]
    }
  }
}
```

Individual assessment:
- `docs`: filesystem MCP, medium risk (write access to /tmp)
- `shell`: shell execution MCP, high risk (PE-002)

Composed assessment:
- CHAIN-001: `docs` can write a script to `/tmp`, then `shell` can execute it.
  This is a complete arbitrary code execution chain. Neither server needs to be
  "malicious" for this to be exploitable via prompt injection.

## Attack Scenario: Secrets-Exfiltration Chain

```json
{
  "mcpServers": {
    "vault": {
      "command": "npx",
      "args": ["@hashicorp/mcp-vault"],
      "env": {"VAULT_TOKEN": "hvs.CAESIBfp..."}
    },
    "fetch": {
      "command": "npx",
      "args": ["@modelcontextprotocol/server-fetch"]
    }
  }
}
```

Individual assessment:
- `vault`: secret management MCP with credentials (SEC findings)
- `fetch`: HTTP fetch MCP, no findings

Composed assessment:
- CHAIN-002: An attacker's prompt injection in any tool response can instruct the LLM
  to (1) read secrets from vault, (2) POST them to an attacker URL via fetch.
  The chain is: secrets-reader + http-exfiltrator → credential exfiltration.

## Attack Scenario: Amplified Filesystem Blast Radius

```json
{
  "mcpServers": {
    "fs1": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/home"]},
    "fs2": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/etc"]},
    "fs3": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/"]}
  }
}
```

Individual assessment:
- Each filesystem server gets a PE-001 (broad path) finding
- Standard per-server findings

Composed assessment:
- CHAIN-003: Three overlapping filesystem writers. A ransomware-style prompt injection
  can instruct the LLM to chain all three servers to encrypt the entire system.
  The total blast radius is the union of all accessible paths.

## Planned Implementation

### Check IDs

| ID | Name | Trigger | Severity |
|---|---|---|---|
| CHAIN-001 | Write+Execute gadget pair | filesystem-write server + shell/exec server present | HIGH |
| CHAIN-002 | Secrets+Exfiltration chain | secret-holding server + HTTP-fetch server present | HIGH |
| CHAIN-003 | Overlapping filesystem amplification | 3+ filesystem servers or total path set includes / | MEDIUM |

### Architecture

New file: `apps/api/engine/checks/chain_analysis.py`

```python
def check_cross_server_chains(config: MCPConfig, per_server: dict[str, list[Finding]]) -> list[Finding]:
    """
    Cross-server capability chain analysis.
    Called from scanner.py after per-server checks complete.
    Takes per_server findings dict to use existing analysis results.
    """
    ...
```

Called from `scanner.py` alongside `check_config_level`:
```python
all_findings.extend(check_cross_server_chains(config, per_server))
```

### Capability Classification

Each server will be classified into capability buckets:
- `filesystem_writer`: has filesystem MCP with writable path
- `shell_executor`: has PE-002 (shell execution) finding or command=`bash`/`sh`
- `secret_holder`: has CRITICAL/HIGH secrets findings
- `http_outbound`: has fetch/HTTP server, or SH-002 (non-TLS URL)
- `code_runner`: has EX-001, EX-002, EX-003 findings

### Graph Analysis

Build a directed capability graph:
- Node = server
- Edge = capability composition (writer → executor = RCE chain)

Detect dangerous subgraphs using the patterns above.

## Academic Basis

- arxiv.org/pdf/2507.06250 "We Urgently Need Privilege Management in MCP"
  Identifies per-server over-privilege but does not model inter-server composition.
  This research extends that work to multi-server configs.

- "Privilege Separation" (Saltzer & Schroeder, 1975) — the foundational principle
  that each component should have only the minimum permissions it needs. When multiple
  MCP servers each have "minimum permissions" but their composition exceeds what any
  single server needs, this is a violation of the principle at the system level.

## Why No Existing Scanner Does This

Static per-server analysis is straightforward — scan one server, emit findings.
Cross-server analysis requires:
1. Understanding the semantics of each server's capabilities
2. Building a composition graph
3. Detecting dangerous subgraphs

This is harder to implement and requires reasoning about what combinations are dangerous.
The capability classification approach makes it tractable: classify first, compose second.
