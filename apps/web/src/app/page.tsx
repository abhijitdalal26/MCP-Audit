"use client"

import { useState } from "react"

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

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border border-red-500/30",
  high: "bg-orange-500/20 text-orange-300 border border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-300 border border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-300 border border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border border-gray-500/30",
}

const SEVERITY_LEFT: Record<string, string> = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-blue-500",
  info: "border-l-gray-500",
}

interface Finding {
  check_id: string
  title: string
  detail: string
  severity: string
  owasp: string
  server_name: string
  remediation: string
}

interface ScanResult {
  scan_id: string
  config_hash: string
  findings: Finding[]
  summary: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
    servers_scanned: number
    owasp_coverage: string[]
  }
  scanned_at: string
}

export default function Home() {
  const [config, setConfig] = useState("")
  const [result, setResult] = useState<ScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [expanded, setExpanded] = useState<Set<number>>(new Set())

  const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"

  const runScan = async () => {
    if (!config.trim()) return
    setLoading(true)
    setError("")
    setResult(null)
    setExpanded(new Set())

    try {
      const res = await fetch(`${apiUrl}/scan`, {
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

  const toggle = (i: number) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(i) ? next.delete(i) : next.add(i)
      return next
    })
  }

  return (
    <main className="min-h-screen bg-gray-950 text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center gap-3">
          <span className="font-bold text-lg tracking-tight">MCPAudit</span>
          <span className="text-xs px-2 py-0.5 rounded bg-gray-800 text-gray-500">v0.1 alpha</span>
        </div>
      </header>

      <div className="max-w-4xl mx-auto px-6 py-10 space-y-8">
        {/* Hero */}
        <div>
          <h1 className="text-2xl font-bold tracking-tight">MCP Security Scanner</h1>
          <p className="mt-1.5 text-gray-400">
            Paste your{" "}
            <code className="text-xs bg-gray-800 px-1.5 py-0.5 rounded text-gray-300">
              claude_desktop_config.json
            </code>{" "}
            or{" "}
            <code className="text-xs bg-gray-800 px-1.5 py-0.5 rounded text-gray-300">
              .cursor/mcp.json
            </code>{" "}
            and get a security report in seconds.
          </p>
        </div>

        {/* Input */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label className="text-sm text-gray-400 font-medium">MCP Config JSON</label>
            <button
              onClick={() => setConfig(EXAMPLE_CONFIG)}
              className="text-xs text-gray-600 hover:text-gray-400 transition-colors"
            >
              Load demo config →
            </button>
          </div>
          <textarea
            value={config}
            onChange={(e) => setConfig(e.target.value)}
            placeholder='Paste your MCP config JSON here...'
            rows={10}
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-3 text-sm font-mono text-gray-200 placeholder-gray-700 focus:outline-none focus:ring-1 focus:ring-gray-600 resize-y"
          />
          <div className="flex items-center gap-3">
            <button
              onClick={runScan}
              disabled={!config.trim() || loading}
              className="px-4 py-2 bg-white text-gray-950 text-sm font-semibold rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {loading ? "Scanning…" : "Scan Config"}
            </button>
            {config && (
              <button
                onClick={() => { setConfig(""); setResult(null); setError("") }}
                className="text-xs text-gray-600 hover:text-gray-400 transition-colors"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="bg-red-950/50 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {/* Loading */}
        {loading && (
          <p className="text-sm text-gray-500 animate-pulse">Running security checks…</p>
        )}

        {/* Results */}
        {result && (
          <div className="space-y-5">
            {/* Summary */}
            <div className="bg-gray-900 border border-gray-800 rounded-lg p-5 space-y-3">
              <div className="flex items-center justify-between text-sm">
                <span className="text-gray-300 font-medium">
                  {result.summary.servers_scanned} server{result.summary.servers_scanned !== 1 ? "s" : ""} scanned
                  {result.summary.total > 0 && (
                    <span className="text-gray-600 ml-2">·</span>
                  )}
                  {result.summary.total > 0 && (
                    <span className="text-gray-500 ml-2">
                      {result.summary.total} finding{result.summary.total !== 1 ? "s" : ""}
                    </span>
                  )}
                </span>
                <span className="text-xs font-mono text-gray-700">{result.config_hash}</span>
              </div>

              {result.summary.total === 0 ? (
                <p className="text-green-400 text-sm font-medium">✓ No security issues found</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {(["critical", "high", "medium", "low", "info"] as const).map((s) => {
                    const count = result.summary[s]
                    if (!count) return null
                    return (
                      <span key={s} className={`px-2.5 py-1 rounded-full text-xs font-semibold ${SEVERITY_BADGE[s]}`}>
                        {count} {s}
                      </span>
                    )
                  })}
                </div>
              )}

              {result.summary.owasp_coverage.length > 0 && (
                <p className="text-xs text-gray-700">
                  OWASP MCP categories: {result.summary.owasp_coverage.join(", ")}
                </p>
              )}
            </div>

            {/* Findings */}
            {result.findings.length > 0 && (
              <div className="space-y-2">
                {result.findings.map((f, i) => (
                  <div
                    key={i}
                    className={`bg-gray-900 border border-gray-800 border-l-2 rounded-lg overflow-hidden ${SEVERITY_LEFT[f.severity] ?? "border-l-gray-600"}`}
                  >
                    <button
                      onClick={() => toggle(i)}
                      className="w-full text-left px-4 py-3.5 flex items-start gap-3 hover:bg-gray-800/40 transition-colors"
                    >
                      <span className={`mt-0.5 shrink-0 px-2 py-0.5 rounded text-xs font-bold uppercase ${SEVERITY_BADGE[f.severity] ?? ""}`}>
                        {f.severity}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-gray-100 leading-snug">{f.title}</p>
                        <p className="mt-0.5 text-xs text-gray-600">
                          <span className="font-mono">{f.check_id}</span>
                          <span className="mx-1.5">·</span>
                          <span>{f.owasp}</span>
                          <span className="mx-1.5">·</span>
                          <span className="font-mono text-gray-700">{f.server_name}</span>
                        </p>
                      </div>
                      <span className="text-gray-700 text-xs shrink-0 pt-1">
                        {expanded.has(i) ? "▲" : "▼"}
                      </span>
                    </button>

                    {expanded.has(i) && (
                      <div className="px-4 pb-4 border-t border-gray-800 pt-3 space-y-3">
                        <div>
                          <p className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-1">Detail</p>
                          <p className="text-sm text-gray-300 leading-relaxed">{f.detail}</p>
                        </div>
                        <div>
                          <p className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-1">Remediation</p>
                          <p className="text-sm text-gray-400 leading-relaxed">{f.remediation}</p>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </main>
  )
}
