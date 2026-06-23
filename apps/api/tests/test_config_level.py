"""Tests for config_level checks: CL-001, CL-002, EC-001."""
import json
import pytest
from tests.conftest import make_server, make_config
from engine.checks.config_level import check_config_level, _has_broad_filesystem, _has_shell_execution
from engine.parser import parse_config
from engine.scanner import scan
from engine.models import Severity, Finding, OWASPCategory


def _run_config_level(config_json: str) -> list[Finding]:
    from engine.checks import (
        check_secrets, check_supply_chain, check_tool_poisoning,
        check_privilege, check_shadow, check_code_execution, check_audit, check_lifecycle
    )
    config = parse_config(config_json)
    per_server: dict = {}
    for server in config.servers:
        sf = []
        sf.extend(check_secrets(server))
        sf.extend(check_privilege(server))
        sf.extend(check_shell := check_code_execution(server))
        per_server[server.name] = sf
    return check_config_level(config, per_server)


class TestConfusedDeputy:
    def test_broad_path_plus_shell_detected(self):
        config_json = json.dumps({
            "mcpServers": {
                "dangerous": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users", "--shell"],
                }
            }
        })
        findings = _run_config_level(config_json)
        assert any(f.check_id == "CL-001" for f in findings)
        cl1 = [f for f in findings if f.check_id == "CL-001"]
        assert cl1[0].severity == Severity.HIGH

    def test_specific_path_plus_shell_not_confused_deputy(self):
        config_json = json.dumps({
            "mcpServers": {
                "ok": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects/myapp", "--shell"],
                }
            }
        })
        findings = _run_config_level(config_json)
        # /Users/me/projects/myapp is not broad enough for CL-001
        cl1 = [f for f in findings if f.check_id == "CL-001"]
        assert len(cl1) == 0

    def test_broad_path_no_shell_not_confused_deputy(self):
        config_json = json.dumps({
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users"],
                }
            }
        })
        findings = _run_config_level(config_json)
        cl1 = [f for f in findings if f.check_id == "CL-001"]
        assert len(cl1) == 0  # no shell = no confused deputy


class TestServerDuplication:
    def test_duplicate_server_flagged(self):
        config_json = json.dumps({
            "mcpServers": {
                "fs-a": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                },
                "fs-b": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                },
            }
        })
        config = parse_config(config_json)
        findings = check_config_level(config, {})
        assert any(f.check_id == "CL-002" for f in findings)

    def test_different_packages_not_flagged(self):
        config_json = json.dumps({
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                },
                "gh": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                },
            }
        })
        config = parse_config(config_json)
        findings = check_config_level(config, {})
        assert not any(f.check_id == "CL-002" for f in findings)


class TestDebugLoggingExposure:
    def test_debug_plus_secrets_flagged(self):
        config_json = json.dumps({
            "mcpServers": {
                "server": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {
                        "GITHUB_TOKEN": "ghp_EXAMPLEfaketoken0000000000000000000000",
                        "DEBUG": "true",
                    },
                }
            }
        })
        findings = _run_config_level(config_json)
        assert any(f.check_id == "EC-001" for f in findings)

    def test_debug_no_secrets_not_flagged(self):
        config_json = json.dumps({
            "mcpServers": {
                "server": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "env": {"DEBUG": "true"},
                }
            }
        })
        findings = _run_config_level(config_json)
        assert not any(f.check_id == "EC-001" for f in findings)


class TestConfigLevelInFullScan:
    def test_full_scan_catches_confused_deputy(self):
        config_json = json.dumps({
            "mcpServers": {
                "bad": {
                    "command": "npx",
                    "args": [
                        "-y", "@modelcontextprotocol/server-filesystem",
                        "/Users", "--shell", "/bin/bash"
                    ],
                }
            }
        })
        config = parse_config(config_json)
        result = scan(config)
        assert any(f.check_id == "CL-001" for f in result.findings)
