"""Tests for lifecycle check, risk scoring, and CycloneDX BOM output."""
import json
import pytest
from tests.conftest import make_server, make_config
from engine.checks.lifecycle import check_lifecycle
from engine.parser import parse_config
from engine.scanner import scan
from engine.cyclonedx import to_cyclonedx
from engine.models import Severity


class TestLifecycleCheck:
    def test_npx_without_ignore_scripts_flagged(self):
        server = make_server(
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem"],
        )
        findings = check_lifecycle(server)
        assert any(f.check_id == "LF-001" for f in findings)

    def test_npx_with_ignore_scripts_not_flagged(self):
        server = make_server(
            command="npx",
            args=["-y", "--ignore-scripts", "@modelcontextprotocol/server-filesystem"],
        )
        findings = check_lifecycle(server)
        assert not any(f.check_id == "LF-001" for f in findings)

    def test_non_npm_command_not_flagged(self):
        # uvx / python commands don't have npm lifecycle scripts
        server = make_server(command="uvx", args=["-y", "some-python-mcp"])
        findings = check_lifecycle(server)
        assert not any(f.check_id == "LF-001" for f in findings)

    def test_npm_without_y_not_flagged(self):
        # Without -y there's a manual confirmation step anyway
        server = make_server(command="npx", args=["@modelcontextprotocol/server-filesystem"])
        findings = check_lifecycle(server)
        assert not any(f.check_id == "LF-001" for f in findings)

    def test_lf001_attack_tactic_is_execution(self):
        server = make_server(command="npx", args=["-y", "random-package"])
        findings = check_lifecycle(server)
        lf1 = [f for f in findings if f.check_id == "LF-001"]
        assert len(lf1) > 0
        assert lf1[0].attack_tactic == "execution"


class TestRiskScoring:
    def test_clean_config_gets_grade_a(self):
        config_json = json.dumps({
            "mcpServers": {
                "fs": {
                    "command": "npx",
                    "args": ["-y", "--ignore-scripts", "@modelcontextprotocol/server-filesystem@1.0.0", "/home/user/projects"],
                }
            }
        })
        config = parse_config(config_json)
        result = scan(config)
        # No secrets, no critical issues, clean path
        assert result.summary.risk_score < 40
        assert result.summary.risk_grade in ("A", "B")

    def test_critical_findings_increase_score(self):
        config_json = json.dumps({
            "mcpServers": {
                "bad": {
                    "command": "npx",
                    "args": ["-y", "mcp-server-free"],
                    "env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
                }
            }
        })
        config = parse_config(config_json)
        result = scan(config)
        assert result.summary.risk_score >= 40
        assert result.summary.risk_grade in ("C", "D", "F")

    def test_extreme_findings_get_grade_f(self):
        config_json = json.dumps({
            "mcpServers": {
                "nightmare": {
                    "command": "npx",
                    "args": ["-y", "mcp-server-free", "/"],
                    "env": {
                        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                        "GITHUB_TOKEN": "ghp_abc123def456ghi789jkl012mno345pqrstu",
                        "DB": "postgresql://admin:s3cr3t@prod.example.com/db",
                    },
                }
            }
        })
        config = parse_config(config_json)
        result = scan(config)
        assert result.summary.risk_score >= 60
        assert result.summary.risk_grade in ("D", "F")

    def test_risk_score_bounded_0_to_100(self):
        config_json = json.dumps({
            "mcpServers": {s: {
                "command": "npx",
                "args": ["-y", "mcp-server-free"],
                "env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
            } for s in ["s1", "s2", "s3", "s4", "s5"]}
        })
        config = parse_config(config_json)
        result = scan(config)
        assert 0 <= result.summary.risk_score <= 100


class TestCycloneDXBOM:
    def _make_result_and_config(self):
        config_json = json.dumps({
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/home/user"],
                },
                "bad-server": {
                    "command": "npx",
                    "args": ["-y", "mcp-server-free"],
                    "env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
                },
            }
        })
        config = parse_config(config_json)
        result = scan(config)
        return result, config

    def test_cyclonedx_format(self):
        result, config = self._make_result_and_config()
        bom = to_cyclonedx(result, config)
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.6"

    def test_components_match_servers(self):
        result, config = self._make_result_and_config()
        bom = to_cyclonedx(result, config)
        assert len(bom["components"]) == 2

    def test_vulnerabilities_match_findings(self):
        result, config = self._make_result_and_config()
        bom = to_cyclonedx(result, config)
        assert len(bom["vulnerabilities"]) == len(result.findings)

    def test_pinned_package_has_version(self):
        result, config = self._make_result_and_config()
        bom = to_cyclonedx(result, config)
        fs = next(c for c in bom["components"] if "filesystem" in c.get("name", ""))
        assert fs.get("version") == "1.0.0"

    def test_unpinned_package_marked(self):
        result, config = self._make_result_and_config()
        bom = to_cyclonedx(result, config)
        bad = next(c for c in bom["components"] if c.get("bom-ref") == "mcp-server:bad-server")
        assert bad.get("version") == "unpinned"
