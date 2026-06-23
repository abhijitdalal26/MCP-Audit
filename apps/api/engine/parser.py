import json
import hashlib
from pydantic import BaseModel
from typing import Optional


class MCPServer(BaseModel):
    name: str
    command: Optional[str] = None
    args: list[str] = []
    env: dict[str, str] = {}
    url: Optional[str] = None
    transport: Optional[str] = None


class MCPConfig(BaseModel):
    config_hash: str
    servers: list[MCPServer]


def parse_config(config_json: str) -> MCPConfig:
    try:
        data = json.loads(config_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")

    if not isinstance(data, dict):
        raise ValueError("Config must be a JSON object")

    config_hash = hashlib.sha256(config_json.encode()).hexdigest()[:16]

    raw_servers = data.get("mcpServers", {})
    if not isinstance(raw_servers, dict):
        raise ValueError("'mcpServers' must be an object")

    servers: list[MCPServer] = []
    for name, server_data in raw_servers.items():
        if not isinstance(server_data, dict):
            continue
        servers.append(MCPServer(
            name=name,
            command=server_data.get("command"),
            args=[str(a) for a in server_data.get("args", [])],
            env={k: str(v) for k, v in server_data.get("env", {}).items()},
            url=server_data.get("url"),
            transport=server_data.get("transport"),
        ))

    return MCPConfig(config_hash=config_hash, servers=servers)
