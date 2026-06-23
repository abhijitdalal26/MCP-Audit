from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional

from engine.parser import parse_config
from engine.scanner import scan
from engine.models import ScanResult
from engine.sarif import to_sarif

app = FastAPI(
    title="MCPAudit API",
    description="MCP server configuration security scanner",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://mcpaudit.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    config: str
    config_path: Optional[str] = "mcp.json"


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": "0.1.0"}


@app.post("/scan", response_model=ScanResult)
def run_scan(req: ScanRequest) -> ScanResult:
    try:
        config = parse_config(req.config)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    if not config.servers:
        raise HTTPException(
            status_code=422,
            detail="No MCP servers found. Ensure your JSON has a 'mcpServers' key with at least one entry.",
        )

    return scan(config)


@app.post("/scan/sarif")
def run_scan_sarif(req: ScanRequest) -> JSONResponse:
    """Return scan findings in SARIF 2.1.0 format for GitHub Security tab integration."""
    try:
        config = parse_config(req.config)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    if not config.servers:
        raise HTTPException(
            status_code=422,
            detail="No MCP servers found.",
        )

    result = scan(config)
    sarif_doc = to_sarif(result, config_path=req.config_path or "mcp.json")

    return JSONResponse(
        content=sarif_doc,
        media_type="application/sarif+json",
        headers={"Content-Disposition": "attachment; filename=mcpaudit-results.sarif"},
    )
