"""Tests for CL-004 (autoApprove), headers parsing, and disabled server skipping."""
import json
import pytest
from engine.parser import parse_config
from engine.scanner import scan
from engine.checks.config_level import check_config_level
from engine.checks.secrets import check_secrets
from engine.checks.shadow import check_shadow
from engine.models import Severity
from tests.conftest import make_server


class TestAutoApproveParsing:
    def test_parses_wildcard_auto_approve(self):
        config = parse_config(json.dumps({
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "autoApprove": "*",
                }
            }
        }))
        assert config.servers[0].auto_approve == "*"

    def test_parses_always_allow_alias(self):
        config = parse_config(json.dumps({
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "alwaysAllow": ["read_file", "list_dir"],
                }
            }
        }))
        assert config.servers[0].auto_approve == ["read_file", "list_dir"]

    def test_parses_headers(self):
        config = parse_config(json.dumps({
            "mcpServers": {
                "remote": {
                    "url": "https://api.example.com/mcp",
                    "headers": {"Authorization": "Bearer sk-test-token-1234567890"},
                }
            }
        }))
        assert "Authorization" in config.servers[0].headers

    def test_parses_disabled(self):
        config = parse_config(json.dumps({
            "mcpServers": {
                "off": {
                    "command": "npx",
                    "args": ["-y", "evil-package"],
                    "disabled": True,
                }
            }
        }))
        assert config.servers[0].disabled is True


class TestCL004AutoApprove:
    def test_wildcard_auto_approve_critical(self):
        config = parse_config(json.dumps({
            "mcpServers": {
                "danger": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "autoApprove": "*",
                }
            }
        }))
        findings = check_config_level(config, {})
        cl4 = [f for f in findings if f.check_id == "CL-004"]
        assert len(cl4) == 1
        assert cl4[0].severity == Severity.CRITICAL

    def test_partial_auto_approve_list(self):
        config = parse_config(json.dumps({
            "mcpServers": {
                "partial": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "autoApprove": ["read_file", "write_file"],
                }
            }
        }))
        findings = check_config_level(config, {})
        assert any(f.check_id == "CL-004" and f.severity == Severity.MEDIUM for f in findings)

    def test_disabled_server_skips_cl004(self):
        config = parse_config(json.dumps({
            "mcpServers": {
                "off": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "autoApprove": "*",
                    "disabled": True,
                }
            }
        }))
        findings = check_config_level(config, {})
        assert not any(f.check_id == "CL-004" for f in findings)


class TestHeadersSecrets:
    def test_secret_in_authorization_header(self):
        server = make_server(
            command=None,
            args=[],
            url="https://api.example.com/mcp",
        )
        server.headers = {"Authorization": "Bearer ghp_abc123def456ghi789jkl012mno345pqrstu"}
        findings = check_secrets(server)
        assert any(f.check_id == "SEC-002" for f in findings)


class TestDisabledServerSkipping:
    def test_disabled_server_not_scanned(self):
        config = parse_config(json.dumps({
            "mcpServers": {
                "off": {
                    "command": "npx",
                    "args": ["-y", "totally-unknown-evil-package"],
                    "disabled": True,
                },
                "on": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
                },
            }
        }))
        result = scan(config)
        assert result.summary.servers_scanned == 1
        assert not any(f.server_name == "off" for f in result.findings)


class TestSH001Severity:
    def test_unknown_package_is_info(self):
        server = make_server(args=["-y", "my-random-mcp-server"])
        findings = check_shadow(server)
        sh1 = [f for f in findings if f.check_id == "SH-001"]
        assert len(sh1) == 1
        assert sh1[0].severity == Severity.INFO
