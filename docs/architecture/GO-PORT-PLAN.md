# Go Offline Engine — Full Porting Plan

**Goal:** Move the 51 security checks from Python into a Go engine that runs entirely inside the CLI binary. Zero data leaves the user's machine. No network required (except the optional OSV.dev CVE lookup). The Python API stays untouched — it continues to power the web UI.

**Author:** Architecture session, 2026-06-28

---

## 1. Why We're Doing This

The CLI today sends the user's `claude_desktop_config.json` to `https://api.mcpaudit.app` to run checks. That config often contains AWS keys, DB passwords, and API tokens. Sending those to any third-party server is a trust contradiction for a security tool.

Every serious security CLI (Trivy, Grype, Gitleaks, Trufflehog, osv-scanner) runs fully offline. Users of security tooling expect this. Without it, adoption by security-conscious teams is blocked.

---

## 2. What Changes, What Stays

| Component | Before | After |
|---|---|---|
| `apps/api/` (Python) | Powers web UI + is called by CLI | **Unchanged** — still powers web UI |
| `packages/cli/internal/client/` | Used for all scans | Used only when `--api-url` is explicitly set |
| `packages/cli/internal/engine/` | **Does not exist** | New — Go port of all 51 checks |
| CLI default mode | Remote API call | Local engine (zero network) |

The Python files in `apps/api/engine/` are the **source of truth for check logic**. Do not delete or modify them. They serve as the reference implementation during porting.

---

## 3. Architectural Decisions

### 3.1 Mode Detection in the CLI

The `scan` command currently defaults `--api-url` to `https://api.mcpaudit.app`. After porting:

- **Change the default to `""` (empty string)**
- Empty `--api-url` → run local Go engine (new default, offline)
- Non-empty `--api-url` → use existing HTTP client (backward compatible for CI setups that pinned an API URL)
- Add `--no-network` flag to suppress the OSV.dev lookup even in local mode

```
mcpaudit scan config.json                          # offline, local engine
mcpaudit scan config.json --api-url https://...   # remote API (old behavior, still works)
mcpaudit scan config.json --no-network            # offline, skip OSV.dev
```

### 3.2 No New External Go Dependencies

Use Go stdlib only. Existing deps (`cobra`, `fatih/color`) stay. No ORM, no JSON schema lib, no regex lib. The one borderline case is Unicode category lookup for SC-006 — handled with stdlib `unicode` package (see §4.6).

### 3.3 RE2 vs Python Regex (Critical — Read This)

Go's `regexp` package is RE2-based. Python's `re` is PCRE-based. The key incompatibility: **RE2 does not support lookaheads or lookbehinds**.

One confirmed lookahead exists in `supply_chain.py` SC-002:
```python
re.compile(r'@modelcontextprotoc(?!ol/)', re.I)   # ← negative lookahead — INVALID in Go
```

**Rewrite strategy for this pattern:** split into two conditions:
```go
// Match @modelcontextprotoc... but NOT @modelcontextprotocol/
strings.Contains(lower, "@modelcontextprotoc") && !strings.Contains(lower, "@modelcontextprotocol/")
```

Before porting each check file, audit every regex for lookaheads (`(?=`, `(?!`, `(?<=`, `(?<!`). Rewrite any found as Go string logic + multiple regexes.

### 3.4 OSV.dev (SC-004) in Offline Mode

SC-004 calls the OSV.dev API to check packages against the Google CVE database. In local mode:
- Keep the call on by default (it's a read-only query, no config data is sent — only package names and versions)
- Apply a 3-second timeout with graceful degradation (if the call fails, emit an INFO finding noting OSV was unavailable; do not fail the scan)
- `--no-network` flag disables it entirely

### 3.5 SARIF and CycloneDX Generated Locally

Currently `scan.go` hits `/scan/sarif` and `/scan/bom` API endpoints for these formats. In local mode, the Go engine generates them directly. Port `sarif.py` and `cyclonedx.py` to Go.

### 3.6 Unicode Handling (SC-006, SH-004, PI-005)

Python uses `unicodedata.name(char)` and `unicodedata.category(char)`. Go has:
- `unicode.IsLetter(r)`, `unicode.IsSpace(r)` etc. — sufficient for category checks
- No built-in character name lookup

For the finding **detail message** (which reports the Unicode name), use Go's `unicode/utf8` to get the rune and format it as `U+XXXX` with a lookup table for the ~20 known dangerous invisible characters (PI-005's `_INVISIBLE_UNICODE` dict). Full Unicode name DB is not needed.

---

## 4. New Go Package Structure

All engine code lives under `packages/cli/internal/engine/`. No files are moved outside `packages/cli/`.

```
packages/cli/
  internal/
    engine/
      engine.go              ← Public entry point: Scan(json string) (*ScanResult, error)
      scanner.go             ← Orchestrator: calls all check funcs, AT-001/AT-005/AT-006
      sarif.go               ← SARIF 2.1.0 output (ported from apps/api/engine/sarif.py)
      cyclonedx.go           ← CycloneDX 1.6 AI-BOM (ported from apps/api/engine/cyclonedx.py)
      models/
        models.go            ← Finding, ScanResult, ScanSummary, Severity, OWASPCategory
      parser/
        parser.go            ← JSONC stripper + MCPServer struct + parse_config
        parser_test.go
      checks/
        secrets.go           ← SEC-001..008
        secrets_test.go
        supply_chain.go      ← SC-001..003, SC-005..007
        supply_chain_test.go
        osv.go               ← SC-004 (OSV.dev HTTP, graceful fail)
        osv_test.go
        tool_poisoning.go    ← PI-001..005, DX-001
        tool_poisoning_test.go
        privilege.go         ← PE-001..009
        privilege_test.go
        shadow.go            ← SH-001..006
        shadow_test.go
        code_execution.go    ← EX-001..003
        code_execution_test.go
        audit.go             ← AT-002..004
        audit_test.go
        lifecycle.go         ← LF-001
        lifecycle_test.go
        config_level.go      ← CL-001..003, EC-001
        config_level_test.go
        chain_analysis.go    ← CHAIN-001..003
        chain_analysis_test.go
    client/                  ← unchanged (HTTP client for --api-url mode)
    output/                  ← unchanged (text/JSON formatters — already accept ScanResult)
```

---

## 5. Data Models in Go

Port `apps/api/engine/models.py` exactly. Use Go iota for enums where appropriate but keep string values matching Python (e.g., `"critical"`, `"MCP01"`) so JSON output is identical.

```go
// models/models.go

type Severity string
const (
    SeverityCritical Severity = "critical"
    SeverityHigh     Severity = "high"
    SeverityMedium   Severity = "medium"
    SeverityLow      Severity = "low"
    SeverityInfo     Severity = "info"
)

type OWASPCategory string
const (
    MCP01 OWASPCategory = "MCP01"
    // ... MCP02..MCP10
)

type Finding struct {
    CheckID      string        `json:"check_id"`
    Title        string        `json:"title"`
    Detail       string        `json:"detail"`
    Severity     Severity      `json:"severity"`
    OWASP        OWASPCategory `json:"owasp"`
    ServerName   string        `json:"server_name"`
    Remediation  string        `json:"remediation"`
    Engine       string        `json:"engine"`
    AttackTactic string        `json:"attack_tactic,omitempty"`
    CWEID        string        `json:"cwe_id,omitempty"`
}

type ScanSummary struct {
    Total          int      `json:"total"`
    Critical       int      `json:"critical"`
    High           int      `json:"high"`
    Medium         int      `json:"medium"`
    Low            int      `json:"low"`
    Info           int      `json:"info"`
    ServersScanned int      `json:"servers_scanned"`
    OWASPCoverage  []string `json:"owasp_coverage"`
    RiskScore      int      `json:"risk_score"`
    RiskGrade      string   `json:"risk_grade"`
}

type ScanResult struct {
    ScanID     string      `json:"scan_id"`
    ConfigHash string      `json:"config_hash"`
    Findings   []Finding   `json:"findings"`
    Summary    ScanSummary `json:"summary"`
    ScannedAt  string      `json:"scanned_at"`
}
```

---

## 6. Parser in Go

Port `apps/api/engine/parser.py` function-for-function.

```go
// parser/parser.go

type MCPServer struct {
    Name        string
    Command     string
    Args        []string
    Env         map[string]string
    Headers     map[string]string
    URL         string
    Transport   string
    AutoApprove interface{} // bool | string | []string
    Disabled    bool
}

type MCPConfig struct {
    ConfigHash string
    Servers    []MCPServer
}

func ParseConfig(configJSON string) (*MCPConfig, error)
func stripJSONCComments(text string) string      // state machine — same logic as Python
func extractFirstJSONObject(text string) string  // same state machine
```

The JSONC state machine is a direct port — same character-by-character logic, no external parser needed.

---

## 7. Check Function Signatures

Each check file exposes one or two public functions matching the Python pattern:

```go
// Per-server checks (takes one MCPServer):
func CheckSecrets(server *MCPServer) []Finding
func CheckSupplyChain(server *MCPServer) []Finding
func CheckOSV(server *MCPServer, timeout time.Duration) []Finding  // network
func CheckToolPoisoning(server *MCPServer) []Finding
func CheckPrivilege(server *MCPServer) []Finding
func CheckShadow(server *MCPServer) []Finding
func CheckCodeExecution(server *MCPServer) []Finding
func CheckAudit(server *MCPServer) []Finding
func CheckLifecycle(server *MCPServer) []Finding

// Cross-server checks (take full config + per-server findings):
func CheckConfigLevel(config *MCPConfig, perServer map[string][]Finding) []Finding
func CheckCrossServerChains(config *MCPConfig, perServer map[string][]Finding) []Finding
```

---

## 8. Scanner / Orchestrator

Port `apps/api/engine/scanner.py` including AT-001, AT-005, AT-006 which live in the scanner (not in a check file).

```go
// scanner.go

func Scan(config *MCPConfig, opts ScanOptions) *ScanResult {
    // 1. Filter disabled servers
    // 2. Per-server checks (secrets, supply_chain, tool_poisoning, privilege,
    //    shadow, code_execution, audit, lifecycle, osv)
    // 3. Config-level checks (config_level, chain_analysis)
    // 4. Scanner-level checks (AT-001, AT-005, AT-006)
    // 5. Sort findings by severity
    // 6. Summarize + risk score
    // 7. Return ScanResult
}

type ScanOptions struct {
    NoNetwork bool          // --no-network: skip OSV
    OSVTimeout time.Duration
}
```

---

## 9. Public Entry Point

```go
// engine.go — the only thing cmd/scan.go imports from the engine

func Scan(configJSON string, opts Options) (*models.ScanResult, error) {
    cfg, err := parser.ParseConfig(configJSON)
    if err != nil {
        return nil, err
    }
    return scanner.Scan(cfg, opts), nil
}

func ScanToSARIF(configJSON string, opts Options) ([]byte, error)
func ScanToBOM(configJSON string, opts Options) ([]byte, error)
```

---

## 10. Updated `cmd/scan.go` Logic

```go
func runScan(_ *cobra.Command, args []string) error {
    // ... read config (unchanged) ...

    if flagAPIURL != "" {
        // Legacy remote mode — unchanged HTTP client path
        return runRemoteScan(ctx, configJSON, configPath, w)
    }

    // LOCAL ENGINE MODE (default)
    opts := engine.Options{NoNetwork: flagNoNetwork, OSVTimeout: 3 * time.Second}
    
    switch strings.ToLower(flagFormat) {
    case "sarif":
        data, err := engine.ScanToSARIF(configJSON, opts)
        // ...
    case "bom":
        data, err := engine.ScanToBOM(configJSON, opts)
        // ...
    default: // text, json
        result, err := engine.Scan(configJSON, opts)
        // ... output via existing output package ...
    }
}
```

New flags to add:
```go
scanCmd.Flags().StringVar(&flagAPIURL, "api-url", "", "Send to remote API instead of running locally (default: run locally)")
scanCmd.Flags().BoolVar(&flagNoNetwork, "no-network", false, "Skip OSV.dev CVE lookup (fully air-gapped mode)")
```

---

## 11. Check-by-Check Porting Notes

### SEC (secrets.go)
- `_VALUE_PATTERNS` → `var valuePatterns = []struct{checkID, title string; re *regexp.Regexp; severity Severity}{...}`
- `_SENSITIVE_VAR_NAMES` → same pattern
- `_PLACEHOLDER_RE` → compile once at package init
- `mask()` helper — direct port
- All regex patterns are RE2-compatible ✓

### SC (supply_chain.go)
- `KNOWN_MALICIOUS` → `var knownMalicious = map[string]bool{...}`
- `KNOWN_MALICIOUS_BY_RUNTIME` → `map[string]map[string]bool`
- `_TYPOSQUAT_PATTERNS` → **AUDIT REQUIRED**: `(?!ol/)` negative lookahead must be rewritten as:
  ```go
  strings.Contains(lower, "@modelcontextprotoc") && !strings.Contains(lower, "@modelcontextprotocol/")
  ```
- `_TRUSTED_SCOPES` → `map[string]bool`
- SC-006 Unicode check: iterate runes with `for i, r := range pkg { if r > 127 { ... } }`; format as `U+%04X`
- `_extract_packages` → `extractPackages(s *MCPServer) []pkgEntry` where `pkgEntry = {name, runtime string}`

### SC-004 (osv.go)
OSV.dev API format (unchanged from Python):
```json
POST https://api.osv.dev/v1/query
{"package": {"name": "pkg-name", "ecosystem": "npm"}, "version": "1.2.3"}
```
Use `net/http` with 3-second timeout. On any error (network, timeout, non-200), append an INFO finding saying OSV was unavailable and return — never propagate the error to the scan caller.

### PI (tool_poisoning.go)
- Port all `_INJECTION_PATTERNS`, `_EXFILTRATION_PATTERNS`, `_EXFILTRATION_ENV_PATTERNS`
- `_INVISIBLE_UNICODE` dict → `var invisibleUnicode = map[rune]string{'​': "Zero Width Space", ...}`
- `_BIDI_OVERRIDE_UNICODE` → same pattern
- All patterns should be RE2-compatible — audit before porting

### PE (privilege.go)
- `_BROAD_PATHS`, `_WIN_DRIVE_ROOT_RE` → direct port
- `_DOCKER_DANGER_FLAGS` → `map[string]string`
- `_DOCKER_SENSITIVE_MOUNT_PATHS` → `[]string`
- `_ELEVATED_CMD_BASENAMES` → `map[string]bool`
- `_DOCKER_DANGEROUS_CAPS` → `map[string]string`
- `_is_node_like_command` → `isNodeLikeCommand(cmd string) bool`
- `_is_broad_path` → `isBroadPath(arg, broad string) bool`
- All patterns RE2-compatible ✓

### SH (shadow.go)
- `_KNOWN_GOOD_SCOPES`, `_KNOWN_GOOD_PACKAGES` → `map[string]bool`
- `unicodedata.category(char)` for SH-004: use `unicode.IsLetter(r) && r > 127`
- Check SH-006 regex patterns for lookaheads — audit required

### EX (code_execution.go)
- Port `_SHELL_INJECTION_PATTERNS`, `_CURL_PIPE_RE`, `_POWERSHELL_ENCODED_RE`
- All should be RE2-compatible — audit

### AT (audit.go)
- Port `_KNOWN_AUDIT_TOOLS`, `_LOG_LEVEL_RE` etc.
- Straightforward — no complex patterns

### LF (lifecycle.go)
- Small file — direct port
- `_LIFECYCLE_HOOKS` list → `[]string`

### CL (config_level.go)
- `_SECURITY_DISABLE_PATTERNS` → `[]struct{keyRE, valRE *regexp.Regexp; description string; severity Severity; cwe string}`
- Cross-server logic (`_check_confused_deputy`, `_check_duplicate_servers`) → direct port
- Receives `map[string][]Finding` from scanner — same as Python

### CHAIN (chain_analysis.go)
- Cross-server analysis — takes full config
- Port capability inference helpers first, then chain detection

---

## 12. Output Formatters

### sarif.go
Port `apps/api/engine/sarif.py`. SARIF 2.1.0 is pure JSON — use Go structs with `encoding/json`. Key struct:
```go
type SARIFLog struct {
    Schema  string    `json:"$schema"`
    Version string    `json:"version"`
    Runs    []SARIFRun `json:"runs"`
}
```
No external dependency. The Python output is the spec — match it field-for-field.

### cyclonedx.go
Port `apps/api/engine/cyclonedx.py`. CycloneDX 1.6 outputs XML. Use `encoding/xml` (stdlib). Match field names exactly.

---

## 13. Testing Strategy

**Rule:** Every existing Python test case gets a Go equivalent. The Go tests are table-driven.

For each `checks/foo.go`, create `checks/foo_test.go` with:
```go
func TestCheckFoo(t *testing.T) {
    tests := []struct {
        name     string
        server   MCPServer
        wantIDs  []string  // check_ids expected in findings
        wantNone bool
    }{
        // Port each Python test case here
    }
    for _, tc := range tests {
        t.Run(tc.name, func(t *testing.T) { ... })
    }
}
```

Port ALL 313 existing Python test cases. Target: 313/313 Go tests passing before merge.

Also add integration test: `cmd/scan_test.go` — call `runScan` in local mode with a real fixture file, assert non-empty findings.

---

## 14. Work Order (Sequential — Each Phase Builds on the Prior)

### Phase A: Foundation (do first, everything depends on this)
1. `internal/engine/models/models.go` — all types, constants, severity weights
2. `internal/engine/parser/parser.go` + `parser_test.go` — JSONC parser + MCPServer
3. `internal/engine/checks/checks.go` — package-level shared helpers (mask, cmdBasename, etc.)

### Phase B: Per-Server Checks (can be done in any order within this phase)
4. `checks/secrets.go` + `secrets_test.go`
5. `checks/supply_chain.go` + `supply_chain_test.go`
6. `checks/osv.go` + `osv_test.go`
7. `checks/tool_poisoning.go` + `tool_poisoning_test.go`
8. `checks/privilege.go` + `privilege_test.go`
9. `checks/shadow.go` + `shadow_test.go`
10. `checks/code_execution.go` + `code_execution_test.go`
11. `checks/audit.go` + `audit_test.go`
12. `checks/lifecycle.go` + `lifecycle_test.go`

### Phase C: Cross-Server Checks (depend on per-server check signatures)
13. `checks/config_level.go` + `config_level_test.go`
14. `checks/chain_analysis.go` + `chain_analysis_test.go`

### Phase D: Orchestrator + Output
15. `internal/engine/scanner.go` — orchestrates all checks, AT-001/AT-005/AT-006
16. `internal/engine/sarif.go` + sarif test
17. `internal/engine/cyclonedx.go` + cyclonedx test
18. `internal/engine/engine.go` — public `Scan()`, `ScanToSARIF()`, `ScanToBOM()`

### Phase E: CLI Wiring
19. Update `cmd/scan.go` — mode detection, new flags, local engine path
20. Update `cmd/scan_test.go` — integration test for local mode
21. Update `Makefile` — ensure `go test ./...` covers all new packages

### Phase F: Validation
22. Run `go test ./...` — all tests pass
23. Run `go build -o bin/mcpaudit.exe .` — binary builds clean
24. Manual smoke test: `./bin/mcpaudit.exe scan <real-config.json>` — findings match Python API output

---

## 15. Files That Must NOT Be Changed

- `apps/api/` — entire Python codebase stays as-is
- `apps/web/` — Next.js frontend stays as-is
- `packages/cli/internal/client/` — HTTP client stays (used by `--api-url` mode)
- `packages/cli/internal/output/` — output formatters stay (already accept ScanResult-shaped data)

---

## 16. Definition of Done

- [ ] `go test ./...` passes (all phases A–E complete)
- [ ] `mcpaudit scan <file>` runs with zero network calls by default
- [ ] `mcpaudit scan <file> --format sarif` produces valid SARIF 2.1.0 locally
- [ ] `mcpaudit scan <file> --format bom` produces valid CycloneDX 1.6 locally
- [ ] `mcpaudit scan <file> --api-url https://api.mcpaudit.app` still works (backward compat)
- [ ] `--no-network` flag suppresses OSV.dev call
- [ ] Binary size stays under 20 MB
- [ ] Cross-compile targets work: `GOOS=linux GOARCH=amd64`, `GOOS=darwin GOARCH=arm64`, `GOOS=windows GOARCH=amd64`
- [ ] CLAUDE.md updated to reflect new CLI default behavior
