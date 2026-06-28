# mcpaudit GitHub Action

Scan MCP server configs for security vulnerabilities in CI. Implements all 54 checks across the OWASP MCP Top 10. **Runs 100% offline — your config never leaves your runner.**

## Quick Start

```yaml
# .github/workflows/security.yml
name: MCP Security

on:
  push:
    paths:
      - '**/claude_desktop_config.json'
      - '**/.cursor/mcp.json'
      - '.github/workflows/security.yml'
  pull_request:
    paths:
      - '**/claude_desktop_config.json'
      - '**/.cursor/mcp.json'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: MCPAudit Security Scan
        uses: abhijitdalal26/MCP-Audit/.github/actions/mcpaudit@master
        with:
          config-path: claude_desktop_config.json
          fail-on: critical
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `config-path` | `claude_desktop_config.json` | Path to MCP config file |
| `fail-on` | `critical` | Minimum severity to fail CI: `critical` / `high` / `medium` / `low` / `info` / `none` |
| `format` | `text` | Output format: `text` / `json` / `sarif` / `bom` |
| `sarif-output` | `mcpaudit.sarif` | SARIF file path (only when `format: sarif`) |
| `upload-sarif` | `false` | Upload to GitHub Security tab (requires `format: sarif` + `security-events: write`) |
| `no-network` | `false` | Skip OSV.dev CVE lookup (fully air-gapped mode) |
| `version` | `latest` | Pin a specific mcpaudit release tag |
| `verify-checksum` | `true` | Verify SHA-256 checksum of downloaded binary |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of security findings |
| `risk-grade` | Risk grade: A / B / C / D / F |
| `sarif-file` | Path to SARIF output (when `format: sarif`) |

## Examples

### Gate PRs on critical findings

```yaml
- uses: abhijitdalal26/MCP-Audit/.github/actions/mcpaudit@master
  with:
    config-path: claude_desktop_config.json
    fail-on: critical    # block merges with critical findings
```

### Upload to GitHub Security tab

```yaml
jobs:
  scan:
    permissions:
      security-events: write   # required for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - uses: abhijitdalal26/MCP-Audit/.github/actions/mcpaudit@master
        with:
          format: sarif
          upload-sarif: 'true'
          fail-on: high
```

### Fully air-gapped (no outbound network)

```yaml
- uses: abhijitdalal26/MCP-Audit/.github/actions/mcpaudit@master
  with:
    no-network: 'true'    # skips OSV.dev CVE lookup
    fail-on: medium
```

### Use findings count in later steps

```yaml
- id: audit
  uses: abhijitdalal26/MCP-Audit/.github/actions/mcpaudit@master
  with:
    fail-on: none    # don't fail CI, just report

- name: Comment on PR
  if: steps.audit.outputs.findings-count != '0'
  run: |
    echo "MCPAudit found ${{ steps.audit.outputs.findings-count }} issues (grade ${{ steps.audit.outputs.risk-grade }})"
```

## What Gets Checked

All 54 checks across 10 OWASP MCP Top 10 categories:

| Category | Checks |
|----------|--------|
| MCP01 — Insecure Config | AWS/GH/Stripe/OpenAI key detection, credentials in URLs |
| MCP02 — Privilege Escalation | Broad filesystem paths, sudo, dangerous Docker caps |
| MCP03 — Tool Poisoning | Prompt injection patterns, invisible Unicode, exfiltration |
| MCP04 — Supply Chain | Known malicious packages, typosquats, unpinned versions |
| MCP05 — Code Execution | Inline eval, curl\|bash, PowerShell -EncodedCommand |
| MCP06 — Data Exfiltration | BCC patterns, data-send args in tool descriptions |
| MCP07 — AutoApprove Bypass | Wildcard autoApprove detection |
| MCP08 — Audit Gaps | Missing version pins, wildcard autoApprove, server count |
| MCP09 — Unauthenticated | Remote SSE endpoints without auth headers |
| MCP10 — Permission Bypass | --dangerously-skip-permissions detection |

## Privacy

The scan binary runs entirely on your CI runner. No MCP config data is sent anywhere. The only optional network call is to `api.osv.dev` for CVE lookup (package names only, no credentials). Use `no-network: 'true'` to disable even that.
