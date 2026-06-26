"use client"

import { useState, useMemo } from "react"

// ─── Demo config ────────────────────────────────────────────────────────────
const EXAMPLE_CONFIG = `{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users"],
      "env": {
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
      }
    },
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_abc123def456ghi789jkl012mno345pqrstu"
      }
    },
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": {
        "DATABASE_URL": "postgresql://admin:s3cr3t@prod.db.example.com/mydb"
      }
    }
  }
}`

// ─── Severity styling ────────────────────────────────────────────────────────
const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border border-red-500/30",
  high:     "bg-orange-500/20 text-orange-300 border border-orange-500/30",
  medium:   "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30",
  low:      "bg-blue-500/20 text-blue-300 border border-blue-500/30",
  info:     "bg-gray-500/20 text-gray-400 border border-gray-500/30",
}

const SEVERITY_LEFT: Record<string, string> = {
  critical: "border-l-red-500",
  high:     "border-l-orange-500",
  medium:   "border-l-yellow-500",
  low:      "border-l-blue-500",
  info:     "border-l-gray-600",
}

const SEVERITY_BAR: Record<string, string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
  info:     "bg-gray-600",
}

const GRADE_COLOR: Record<string, string> = {
  A: "text-green-400",
  B: "text-emerald-400",
  C: "text-yellow-400",
  D: "text-orange-400",
  F: "text-red-400",
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const
type SeverityKey = (typeof SEVERITIES)[number]

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

// ─── OWASP ──────────────────────────────────────────────────────────────────
const OWASP_ALL = [
  "MCP01","MCP02","MCP03","MCP04","MCP05",
  "MCP06","MCP07","MCP08","MCP09","MCP10",
]

const OWASP_SHORT: Record<string, string> = {
  MCP01: "Secret Exposure",
  MCP02: "Privilege Escalation",
  MCP03: "Tool Poisoning",
  MCP04: "Supply Chain",
  MCP05: "Code Execution",
  MCP06: "Prompt Injection",
  MCP07: "No Authentication",
  MCP08: "No Audit Trail",
  MCP09: "Shadow Servers",
  MCP10: "Over-Sharing",
}

// ─── Types ───────────────────────────────────────────────────────────────────
interface Finding {
  check_id: string
  title: string
  detail: string
  severity: string
  owasp: string
  server_name: string
  remediation: string
  attack_tactic?: string
  cwe_id?: string
}

interface ScanSummary {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  servers_scanned: number
  owasp_coverage: string[]
  risk_score: number
  risk_grade: string
}

interface ScanResult {
  scan_id: string
  config_hash: string
  findings: Finding[]
  summary: ScanSummary
  scanned_at: string
}

// ─── Explainer data ──────────────────────────────────────────────────────────
const CHECK_CATEGORIES = [
  ["Secrets",        "SEC-001–008",       "Hardcoded API keys, AWS credentials, DB passwords, tokens in env vars, headers, and URLs"],
  ["Supply Chain",   "SC-001–007",        "Typosquatting, known malicious packages, registry overrides, OSV.dev live CVE lookup"],
  ["Privilege",      "PE-001–009",        "Broad filesystem paths, Docker escape flags, sudo usage, path traversal, permission bypass"],
  ["Tool Poisoning", "PI-001–005, DX-001","Invisible Unicode, prompt injection in args, exfiltration webhooks, tool override patterns"],
  ["Code Execution", "EX-001–003",        "base64-encoded exec, PowerShell encoded commands, curl|bash pipe patterns"],
  ["Shadow Servers", "SH-001–006",        "Unverified packages, no-auth HTTP, homoglyph server names, auto-discovery env vars"],
  ["Audit",          "AT-001–006",        "Version pinning, Docker image tags, telemetry, excessive server count"],
  ["Lifecycle",      "LF-001",            "Dangerous postinstall/preinstall scripts in fetched packages"],
  ["Config Level",   "CL-001–003, EC-001","Duplicate names, security feature disables, cross-server scope escalation"],
  ["Chain Analysis", "CHAIN-001–003",     "Multi-server attack chains: filesystem + exec, credential + network exfiltration"],
] as const

// ─── Component ───────────────────────────────────────────────────────────────
export default function Home() {
  const [config, setConfig]                   = useState("")
  const [result, setResult]                   = useState<ScanResult | null>(null)
  const [loading, setLoading]                 = useState(false)
  const [error, setError]                     = useState("")
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set())
  const [collapsedServers, setCollapsedServers] = useState<Set<string>>(new Set())

  const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"

  // Live server count preview while typing
  const serverPreview = useMemo(() => {
    if (!config.trim()) return null
    try {
      const d = JSON.parse(config)
      const n = Object.keys(d.mcpServers ?? {}).length
      return n > 0 ? `${n} server${n !== 1 ? "s" : ""} detected` : null
    } catch {
      return null
    }
  }, [config])

  // Group findings by server name, sorted by worst severity
  const groupedFindings = useMemo(() => {
    if (!result) return {} as Record<string, Array<{ finding: Finding; flatIdx: number }>>
    const groups: Record<string, Array<{ finding: Finding; flatIdx: number }>> = {}
    result.findings.forEach((f, i) => {
      groups[f.server_name] ??= []
      groups[f.server_name].push({ finding: f, flatIdx: i })
    })
    return Object.fromEntries(
      Object.entries(groups).sort(([, a], [, b]) => {
        const worst = (items: typeof a) =>
          Math.min(...items.map(({ finding }) => SEVERITY_ORDER[finding.severity] ?? 99))
        return worst(a) - worst(b)
      }),
    )
  }, [result])

  // ── Handlers ───────────────────────────────────────────────────────────────
  const downloadExport = async (endpoint: "sarif" | "bom", filename: string) => {
    if (!config.trim()) return
    try {
      const res = await fetch(`${apiUrl}/scan/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config, config_path: "mcp.json" }),
      })
      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.detail ?? "Export failed")
      }
      const blob = await res.blob()
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement("a")
      a.href = url; a.download = filename; a.click()
      URL.revokeObjectURL(url)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Export failed")
    }
  }

  const runScan = async () => {
    if (!config.trim()) return
    setLoading(true)
    setError("")
    setResult(null)
    setExpandedFindings(new Set())
    setCollapsedServers(new Set())
    try {
      const res  = await fetch(`${apiUrl}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail ?? "Scan failed")
      setResult(data)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Unknown error")
    } finally {
      setLoading(false)
    }
  }

  const toggleFinding = (i: number) =>
    setExpandedFindings(prev => {
      const next = new Set(prev)
      next.has(i) ? next.delete(i) : next.add(i)
      return next
    })

  const toggleServer = (name: string) =>
    setCollapsedServers(prev => {
      const next = new Set(prev)
      next.has(name) ? next.delete(name) : next.add(name)
      return next
    })

  const expandAllFindings = () =>
    setExpandedFindings(new Set(result?.findings.map((_, i) => i) ?? []))

  const collapseAllFindings = () => setExpandedFindings(new Set())

  const clearAll = () => { setConfig(""); setResult(null); setError("") }

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <main className="min-h-screen bg-gray-950 text-gray-100">

      {/* ── Header ── */}
      <header className="border-b border-gray-800 sticky top-0 bg-gray-950/95 backdrop-blur-sm z-10">
        <div className="max-w-4xl mx-auto px-6 py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <span className="font-bold text-lg tracking-tight">MCPAudit</span>
            <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-600 font-mono">v0.1 alpha</span>
          </div>
          <nav className="flex items-center gap-5 text-sm">
            <a href="#cli" className="text-gray-500 hover:text-gray-300 transition-colors">CLI</a>
            <a
              href="https://github.com/abhijitdalal26/MCP-Audit"
              target="_blank"
              rel="noopener noreferrer"
              className="text-gray-500 hover:text-gray-300 transition-colors"
            >
              GitHub ↗
            </a>
          </nav>
        </div>
      </header>

      <div className="max-w-4xl mx-auto px-6 py-12 space-y-10">

        {/* ── Hero ── */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight leading-tight">
            Find security issues in your MCP config
          </h1>
          <p className="mt-3 text-gray-400 leading-relaxed max-w-2xl">
            51 checks across the OWASP MCP Top 10 — secrets, supply chain attacks, privilege
            escalation, prompt injection, and more. Results in under 30 seconds. No account required.
          </p>
        </div>

        {/* ── Input ── */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <label className="text-sm font-medium text-gray-300">
              MCP Config JSON
              {serverPreview && (
                <span className="ml-2 text-xs font-mono font-normal text-gray-600">
                  · {serverPreview}
                </span>
              )}
            </label>
            <button
              onClick={() => setConfig(EXAMPLE_CONFIG)}
              className="text-xs text-gray-600 hover:text-gray-400 transition-colors"
            >
              Load demo config →
            </button>
          </div>
          <textarea
            value={config}
            onChange={e => setConfig(e.target.value)}
            placeholder="Paste your claude_desktop_config.json or .cursor/mcp.json here…"
            rows={10}
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-3 text-sm font-mono text-gray-200 placeholder-gray-700 focus:outline-none focus:ring-1 focus:ring-gray-600 resize-y"
          />
          <div className="flex items-center gap-3">
            <button
              onClick={runScan}
              disabled={!config.trim() || loading}
              className="px-5 py-2 bg-white text-gray-950 text-sm font-semibold rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loading ? "Scanning…" : "Run Security Scan"}
            </button>
            {config && (
              <button
                onClick={clearAll}
                className="text-xs text-gray-600 hover:text-gray-400 transition-colors"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* ── Error ── */}
        {error && (
          <div className="bg-red-950/50 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {/* ── Loading ── */}
        {loading && (
          <div className="space-y-2">
            <p className="text-sm text-gray-500 animate-pulse">Running 51 security checks…</p>
            <div className="h-px bg-gray-800 rounded overflow-hidden">
              <div className="h-full bg-gradient-to-r from-gray-700 to-gray-600 rounded w-1/2 animate-pulse" />
            </div>
          </div>
        )}

        {/* ── Results ── */}
        {result && (
          <div className="space-y-4">

            {/* Risk summary card */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
              <div className="flex items-start justify-between gap-4">

                {/* Grade + counts */}
                <div className="flex items-center gap-5">
                  <div className="text-center shrink-0">
                    <div
                      className={`text-5xl font-black leading-none ${GRADE_COLOR[result.summary.risk_grade] ?? "text-gray-400"}`}
                    >
                      {result.summary.risk_grade}
                    </div>
                    <div className="text-xs text-gray-700 mt-1.5 font-mono tabular-nums">
                      {result.summary.risk_score}/100
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <p className="text-sm font-medium text-gray-300">
                      {result.summary.servers_scanned} server{result.summary.servers_scanned !== 1 ? "s" : ""} scanned
                    </p>
                    {result.summary.total === 0 ? (
                      <p className="text-green-400 text-sm font-medium">
                        ✓ All 51 checks passed — no security issues found
                      </p>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {SEVERITIES.map(s => {
                          const count = result.summary[s as SeverityKey]
                          if (!count) return null
                          return (
                            <span key={s} className={`px-2 py-0.5 rounded-full text-xs font-semibold ${SEVERITY_BADGE[s]}`}>
                              {count} {s}
                            </span>
                          )
                        })}
                      </div>
                    )}
                    <p className="text-xs text-gray-700 font-mono">{result.scan_id.slice(0, 8)}</p>
                  </div>
                </div>

                {/* Export buttons */}
                <div className="flex flex-col gap-1.5 shrink-0">
                  <button
                    onClick={() => downloadExport("sarif", "mcpaudit-results.sarif")}
                    className="text-xs px-2.5 py-1 rounded border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600 transition-colors whitespace-nowrap"
                  >
                    ↓ SARIF
                  </button>
                  <button
                    onClick={() => downloadExport("bom", "mcpaudit-bom.cdx.json")}
                    className="text-xs px-2.5 py-1 rounded border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600 transition-colors whitespace-nowrap"
                  >
                    ↓ AI-BOM
                  </button>
                </div>
              </div>

              {/* Severity bar */}
              {result.summary.total > 0 && (
                <div className="flex h-1.5 rounded-full overflow-hidden gap-px">
                  {SEVERITIES.map(s => {
                    const count = result.summary[s as SeverityKey]
                    if (!count) return null
                    return (
                      <div
                        key={s}
                        style={{ width: `${(count / result.summary.total) * 100}%` }}
                        className={`${SEVERITY_BAR[s]} transition-all`}
                        title={`${count} ${s}`}
                      />
                    )
                  })}
                </div>
              )}
            </div>

            {/* OWASP coverage grid */}
            {result.summary.total > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                <p className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-3">
                  OWASP MCP Top 10 Coverage
                </p>
                <div className="grid grid-cols-5 gap-1.5">
                  {OWASP_ALL.map(cat => {
                    const hit = result.summary.owasp_coverage.includes(cat)
                    return (
                      <div
                        key={cat}
                        className={`rounded-lg p-2 text-center transition-colors ${
                          hit
                            ? "bg-orange-500/10 border border-orange-500/25"
                            : "bg-gray-800/40 border border-gray-800"
                        }`}
                      >
                        <div className={`text-xs font-bold font-mono ${hit ? "text-orange-400" : "text-gray-700"}`}>
                          {cat}
                        </div>
                        <div className={`text-[10px] leading-tight mt-0.5 ${hit ? "text-gray-500" : "text-gray-700"}`}>
                          {OWASP_SHORT[cat]}
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* Findings grouped by server */}
            {result.findings.length > 0 && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium text-gray-300">
                    {result.summary.total} finding{result.summary.total !== 1 ? "s" : ""}
                    <span className="text-gray-700 ml-2 text-xs font-normal font-mono">
                      · {result.config_hash}
                    </span>
                  </p>
                  <div className="flex items-center gap-3 text-xs text-gray-600">
                    <button onClick={expandAllFindings} className="hover:text-gray-400 transition-colors">
                      Expand all
                    </button>
                    <span className="text-gray-800">·</span>
                    <button onClick={collapseAllFindings} className="hover:text-gray-400 transition-colors">
                      Collapse all
                    </button>
                  </div>
                </div>

                {Object.entries(groupedFindings).map(([serverName, items]) => {
                  const worstSeverity = items.reduce<string>((best, { finding }) =>
                    (SEVERITY_ORDER[finding.severity] ?? 99) < (SEVERITY_ORDER[best] ?? 99)
                      ? finding.severity
                      : best,
                    "info",
                  )
                  const isCollapsed = collapsedServers.has(serverName)

                  return (
                    <div key={serverName} className="border border-gray-800 rounded-xl overflow-hidden">

                      {/* Server header */}
                      <button
                        onClick={() => toggleServer(serverName)}
                        className="w-full flex items-center justify-between px-4 py-3 bg-gray-900 hover:bg-gray-800/50 transition-colors"
                      >
                        <div className="flex items-center gap-2.5">
                          <span className="text-sm font-mono font-medium text-gray-200">{serverName}</span>
                          <span className="text-xs px-1.5 py-0.5 rounded bg-gray-800 text-gray-500">
                            {items.length}
                          </span>
                          <span className={`text-xs px-1.5 py-0.5 rounded ${SEVERITY_BADGE[worstSeverity] ?? ""}`}>
                            {worstSeverity}
                          </span>
                        </div>
                        <span className="text-gray-700 text-xs">{isCollapsed ? "▼" : "▲"}</span>
                      </button>

                      {/* Finding cards */}
                      {!isCollapsed && (
                        <div className="divide-y divide-gray-800/50">
                          {items.map(({ finding: f, flatIdx }) => {
                            const isExpanded = expandedFindings.has(flatIdx)
                            return (
                              <div
                                key={flatIdx}
                                className={`border-l-2 ${SEVERITY_LEFT[f.severity] ?? "border-l-gray-700"}`}
                              >
                                <button
                                  onClick={() => toggleFinding(flatIdx)}
                                  className="w-full text-left px-4 py-3 flex items-start gap-3 hover:bg-gray-800/30 transition-colors"
                                >
                                  <span
                                    className={`mt-0.5 shrink-0 px-1.5 py-0.5 rounded text-xs font-bold uppercase ${SEVERITY_BADGE[f.severity] ?? ""}`}
                                  >
                                    {f.severity}
                                  </span>
                                  <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium text-gray-100 leading-snug">
                                      {f.title}
                                    </p>
                                    <p className="mt-0.5 text-xs text-gray-600 font-mono">
                                      {f.check_id}
                                      <span className="mx-1.5 text-gray-800">·</span>
                                      {f.owasp}
                                      {f.cwe_id && (
                                        <>
                                          <span className="mx-1.5 text-gray-800">·</span>
                                          {f.cwe_id}
                                        </>
                                      )}
                                      {f.attack_tactic && (
                                        <>
                                          <span className="mx-1.5 text-gray-800">·</span>
                                          <span className="text-gray-700">ATT&amp;CK: {f.attack_tactic}</span>
                                        </>
                                      )}
                                    </p>
                                  </div>
                                  <span className="text-gray-700 text-xs shrink-0 pt-0.5">
                                    {isExpanded ? "▲" : "▼"}
                                  </span>
                                </button>

                                {isExpanded && (
                                  <div className="px-4 pb-4 pt-2 space-y-3 bg-gray-900/30 border-t border-gray-800/50">
                                    <div>
                                      <p className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-1.5">
                                        Detail
                                      </p>
                                      <p className="text-sm text-gray-300 leading-relaxed">{f.detail}</p>
                                    </div>
                                    <div>
                                      <p className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-1.5">
                                        Remediation
                                      </p>
                                      <p className="text-sm text-gray-400 leading-relaxed">{f.remediation}</p>
                                    </div>
                                  </div>
                                )}
                              </div>
                            )
                          })}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}

        {/* ── Explainer ── */}
        <div className="border-t border-gray-800 pt-10 space-y-6">
          <div>
            <h2 className="text-lg font-semibold text-gray-200">What does MCPAudit check?</h2>
            <p className="mt-1 text-sm text-gray-500">
              51 checks across 11 categories, every finding mapped to the OWASP MCP Top 10.
            </p>
          </div>
          <div className="space-y-0">
            {CHECK_CATEGORIES.map(([category, ids, desc]) => (
              <div
                key={category}
                className="flex gap-4 py-2.5 border-b border-gray-800/40 last:border-0"
              >
                <div className="w-28 shrink-0 text-sm font-medium text-gray-300">{category}</div>
                <div className="w-40 shrink-0 text-xs font-mono text-gray-600 pt-px">{ids}</div>
                <p className="text-sm text-gray-500 leading-snug">{desc}</p>
              </div>
            ))}
          </div>
          <p className="text-xs text-gray-700">
            Output formats: JSON · SARIF 2.1.0 (GitHub Security tab) · CycloneDX 1.6 AI-BOM
          </p>
        </div>

        {/* ── CLI section ── */}
        <div id="cli" className="border-t border-gray-800 pt-10 space-y-5">
          <div>
            <h2 className="text-lg font-semibold text-gray-200">Use from the command line</h2>
            <p className="mt-1 text-sm text-gray-500">
              Single binary, no runtime required. Gate your CI pipeline on critical findings.
            </p>
          </div>
          <div className="space-y-2">
            <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3.5 font-mono text-sm space-y-1.5">
              <p className="text-gray-600"># Scan a config file</p>
              <p className="text-gray-300">mcpaudit scan ~/.claude/claude_desktop_config.json</p>
              <p className="mt-2 text-gray-600"># Output SARIF for the GitHub Security tab</p>
              <p className="text-gray-300">{"mcpaudit scan mcp.json --format sarif > results.sarif"}</p>
              <p className="mt-2 text-gray-600"># Block CI on high or critical findings (exit 1)</p>
              <p className="text-gray-300">mcpaudit scan mcp.json --fail-on high</p>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-lg px-4 py-3.5 font-mono text-sm space-y-1">
              <p className="text-gray-600"># GitHub Actions</p>
              <p className="text-gray-300">- uses: mcpaudit/action@v1</p>
              <p className="text-gray-300 pl-2">with:</p>
              <p className="text-gray-300 pl-4">config-path: .cursor/mcp.json</p>
              <p className="text-gray-300 pl-4">fail-on: high</p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            {(
              [
                ["macOS (Apple Silicon)", "mcpaudit-darwin-arm64"],
                ["macOS (Intel)",         "mcpaudit-darwin-amd64"],
                ["Linux",                 "mcpaudit-linux-amd64"],
                ["Windows",               "mcpaudit-windows-amd64.exe"],
              ] as const
            ).map(([label, filename]) => (
              <a
                key={label}
                href={`https://github.com/abhijitdalal26/MCP-Audit/releases/latest/download/${filename}`}
                className="text-xs px-3 py-1.5 rounded border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-600 transition-colors"
              >
                ↓ {label}
              </a>
            ))}
          </div>
          <p className="text-xs text-gray-700">
            CLI v0.1 · Go binary · MIT License ·{" "}
            <a
              href="https://github.com/abhijitdalal26/MCP-Audit"
              className="hover:text-gray-500 transition-colors"
            >
              Source on GitHub ↗
            </a>
          </p>
        </div>
      </div>

      {/* ── Footer ── */}
      <footer className="border-t border-gray-800 mt-4">
        <div className="max-w-4xl mx-auto px-6 py-5 flex items-center justify-between text-xs text-gray-700">
          <span>MCPAudit · 51 checks · OWASP MCP Top 10</span>
          <div className="flex items-center gap-4">
            <a
              href="https://github.com/abhijitdalal26/MCP-Audit"
              className="hover:text-gray-500 transition-colors"
            >
              GitHub
            </a>
            <span>MIT License</span>
          </div>
        </div>
      </footer>
    </main>
  )
}
