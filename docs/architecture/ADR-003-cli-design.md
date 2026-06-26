# ADR-003: CLI Design — Thin HTTP Client in Go

**Date:** 2026-06-27  
**Status:** Decided

## Decision

The CLI (`packages/cli/`) is a thin HTTP client in Go that calls the deployed API.
It does NOT re-implement the security engine in Go.

## Language: Go

- Single static binary — no runtime dependency (unlike Python CLI)
- Fast startup: <50ms vs Python's 500ms+
- Easy cross-compilation: one `GOOS/GOARCH` flag produces binaries for all platforms
- Homebrew-friendly distribution (standard for developer tools)
- `cobra` is the de facto CLI framework in Go (used by kubectl, gh, docker, etc.)

## Architecture: Thin HTTP client

The CLI:
1. Reads the config file (or stdin)
2. POSTs to `POST /scan` (or `/scan/sarif`, `/scan/bom` based on `--format`)
3. Formats and prints the response
4. Exits with appropriate exit code

The Python engine remains the single source of truth for all security logic.
The CLI is a presentation layer, not an engine.

**Consequence:** CLI requires network access. For offline/air-gapped use, users must run
the API themselves (`docker run mcpaudit/api` — planned for Stage 2) and point `--api-url`
at localhost.

## Rejected alternatives

- **Python CLI (click/typer)**: Would require Python runtime. Packaging as a single binary
  (PyInstaller) adds ~50MB to the binary and has reliability issues on some platforms.
- **Go CLI with embedded Python engine**: Possible via cgo + embedded interpreter, but extreme
  complexity for marginal gain. Violates "one engine" principle.
- **Node.js CLI**: No strong reason over Go. Requires Node runtime or bundling.

## Commands

```
mcpaudit scan <file>         # scan a file
mcpaudit scan --stdin        # read from stdin
mcpaudit version             # print version
```

## Flags on `scan`

| Flag | Default | Description |
|------|---------|-------------|
| `--api-url` | `https://api.mcpaudit.app` | API base URL |
| `--format` | `text` | Output: text, json, sarif, bom |
| `--output` | stdout | Write to file |
| `--fail-on` | `critical` | Exit 1 if findings at/above this severity |
| `--no-color` | false | Disable ANSI colors |
| `--timeout` | 30 | HTTP timeout in seconds |

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No findings at/above `--fail-on` threshold (or `--fail-on none`) |
| 1 | Findings found at/above threshold — use for CI blocking |
| 2 | Error: file not found, invalid JSON, API unreachable |

## Output format: `text` (default)

Styled like `npm audit`:
- One finding per block: severity badge, title, server name, check ID, OWASP, CWE
- Remediation on indented line below
- Summary line at bottom: "12 findings: 2 critical, 3 high..."
- ANSI colors matching website severity palette (red/orange/yellow/blue/gray)
- `--no-color` disables all ANSI

## Distribution

1. GitHub Releases (primary): binaries attached to release tag `v*`
2. Homebrew tap (Stage 2): `brew install abhijitdalal26/tap/mcpaudit`
3. npm global package (Stage 3): `npm install -g mcpaudit` (wrapper shell script)

## Directory structure

```
packages/cli/
  go.mod
  go.sum
  main.go               # cobra root init
  cmd/
    root.go             # root command, --api-url --no-color persistent flags
    scan.go             # scan command + all scan-specific flags
    version.go          # version command
  internal/
    client/
      client.go         # ScanConfig(), ScanSARIF(), ScanBOM() — HTTP calls
    output/
      text.go           # colored terminal output
      json.go           # pretty-print raw JSON
  Makefile
```
