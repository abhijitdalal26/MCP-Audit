from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from engine.parser import parse_config
from engine.scanner import scan
from engine.models import ScanResult

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
