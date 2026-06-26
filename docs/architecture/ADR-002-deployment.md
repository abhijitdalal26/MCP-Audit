# ADR-002: Deployment Strategy — Vercel (web) + Railway (API)

**Date:** 2026-06-27  
**Status:** Decided — deployment deferred until localhost build is verified by owner

## Decision

- **Frontend** (`apps/web`): Deploy to Vercel (auto-deploy from GitHub `master` branch)
- **API** (`apps/api`): Deploy to Railway (Python/FastAPI, single service)
- **Domain**: `mcpaudit.app` → Vercel, `api.mcpaudit.app` → Railway custom domain

## Context

Frontend is Next.js 15 — Vercel is its natural home (zero config, instant deploys, edge CDN).
API is FastAPI Python — needs a persistent server process, not serverless.

Railway was chosen over Render and Fly.io because:
- Nixpacks auto-detects Python and installs from `requirements.txt` without any Dockerfile
- Better DX for small projects: one config file (`railway.toml`)
- $5/month hobby tier is sufficient for scan API traffic at MVP scale
- Easier to add env vars and custom domains compared to Fly.io

## Configuration files created

- `apps/api/railway.toml` — Railway build + start config
- `apps/api/Procfile` — fallback for other platforms (Render, Heroku)
- `apps/api/requirements.txt` — production-only deps (no pytest)
- `apps/web/.env.example` — documents NEXT_PUBLIC_API_URL for contributors

## CORS

`apps/api/main.py` `allow_origins` must include:
```python
"https://mcpaudit.app",
"https://www.mcpaudit.app",
```
`http://localhost:3000` and `http://localhost:3001` stay for local dev.

## Environment variables

| Var | Set in | Value |
|-----|--------|-------|
| `NEXT_PUBLIC_API_URL` | Vercel dashboard | `https://api.mcpaudit.app` |
| `PORT` | Railway (auto-injected) | varies |

## Stage 2 additions (not now)

- Supabase `DATABASE_URL` in Railway env
- Clerk `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY` in Vercel env
- Redis for rate limiting (Railway addon)

## Rejected alternatives

- **Single Vercel deployment with API Routes**: FastAPI is Python, not Node.js. Vercel
  Python runtime is serverless with cold starts — bad for a scan tool with 3s OSV timeout.
- **Fly.io for API**: Good option but requires a Dockerfile and more config. Railway's Nixpacks
  auto-detection is simpler for MVP.
- **Single server (VPS)**: Too much ops overhead for Stage 1. Managed platforms first.
