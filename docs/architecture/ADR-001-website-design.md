# ADR-001: Website Design — Tool-First Single Page

**Date:** 2026-06-27  
**Status:** Decided

## Decision

The website homepage IS the scanner — no separate marketing landing page.
All redesign work stays in `apps/web/src/app/page.tsx`.
No additional routes for MVP (no `/results/[id]`, no `/docs` page).

## Context

MCPAudit targets developers and security engineers who already know what MCP is.
A marketing page between them and the tool adds friction without value at this stage.
Target comparators: observatory.mozilla.org, have i been pwned, virustotal — all put the tool
on the landing page.

## Rejected alternatives

- **Marketing landing + /scan route**: Adds a route, requires navigation, delays the "aha" moment.
  Rejected — Stage 1 is about proving the tool's value, not selling it.
- **Multi-page app with /results/[scan_id]**: Requires scan persistence (database). 
  Rejected — no DB until Stage 2.

## What the page contains (top → bottom)

1. Header: brand + GitHub link + CLI anchor link
2. Hero: one-line tagline + description mentioning check count and OWASP
3. Scan input: textarea + "Run Security Scan" button + "Load demo config" link
4. Results section (conditional, shown after scan):
   - RiskSummaryCard: grade, score, finding counts, scan ID
   - SeverityBreakdown: proportional horizontal bar
   - OWASPCoverageGrid: 10-cell grid, MCP01–MCP10, hit cells colored
   - ExportButtons: SARIF, AI-BOM
   - FindingsGroupedByServer: collapsible per-server sections, expandable finding cards
5. Explainer section: static "what does MCPAudit check" with check category table
6. CLI section: CLI usage examples + download links (anchor: #cli)
7. Footer: version, check count, OWASP reference, GitHub, license

## Style constraints

- Dark theme only: `bg-gray-950` background, `bg-gray-900` cards
- Font: Inter (already in layout.tsx — do not change)
- Severity color palette is fixed (red/orange/yellow/blue/gray) — do not change
- No component file splits for MVP — keep in page.tsx unless it exceeds ~600 lines
- No external UI libraries (no shadcn, radix, etc.) — Tailwind only
