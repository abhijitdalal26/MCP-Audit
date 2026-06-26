"""Shared fixtures for the MCPAudit test suite."""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.parser import MCPServer, MCPConfig


def make_server(
    name: str = "test-server",
    command: str = "npx",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    url: str | None = None,
    headers: dict[str, str] | None = None,
    auto_approve: object = None,
    disabled: bool = False,
) -> MCPServer:
    return MCPServer(
        name=name,
        command=command,
        args=args or [],
        env=env or {},
        headers=headers or {},
        url=url,
        auto_approve=auto_approve,
        disabled=disabled,
    )


def make_config(servers: list[MCPServer]) -> MCPConfig:
    return MCPConfig(config_hash="test1234", servers=servers)
