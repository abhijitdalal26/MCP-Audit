"""Tests for shadow.py (SH-001) and audit.py (AT-002/003) and SARIF formatter."""
import json
import pytest
from tests.conftest import make_server, make_config
from engine.checks.shadow import check_shadow
from engine.checks.audit import check_audit
from engine.parser import parse_config
from engine.scanner import scan
from engine.sarif import to_sarif
from engine.models import Severity


class TestShadowSH001:
    def test_unknown_package_flagged(self):
        server = make_server(args=["-y", "my-random-mcp-server"])
        findings = check_shadow(server)
        assert any(f.check_id == "SH-001" for f in findings)
        sh1 = [f for f in findings if f.check_id == "SH-001"]
        assert sh1[0].severity == Severity.MEDIUM

    def test_official_package_not_flagged(self):
        server = make_server(args=["-y", "@modelcontextprotocol/server-filesystem@1.0.0"])
        findings = check_shadow(server)
        assert not any(f.check_id == "SH-001" for f in findings)

    def test_known_scope_not_flagged(self):
        server = make_server(args=["-y", "@modelcontextprotocol/server-git"])
        findings = check_shadow(server)
        assert not any(f.check_id == "SH-001" for f in findings)

    def test_attack_tactic_set_on_sh001(self):
        server = make_server(args=["-y", "unknown-package"])
        findings = check_shadow(server)
        sh1 = [f for f in findings if f.check_id == "SH-001"]
        assert len(sh1) > 0
        assert sh1[0].attack_tactic == "initial-access"


class TestAuditChecks:
    def test_transport_ambiguity_flagged(self):
        # Both command and url present with no explicit transport
        server = make_server(
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem"],
            url="http://localhost:3000/mcp",
        )
        findings = check_audit(server)
        assert any(f.check_id == "AT-002" for f in findings)

    def test_remote_url_without_transport_flagged(self):
        server = make_server(
            command=None,
            args=[],
            url="https://api.example.com/mcp",
        )
        findings = check_audit(server)
        assert any(f.check_id == "AT-003" for f in findings)

    def test_explicit_sse_transport_not_flagged(self):
        from engine.parser import MCPServer
        server = MCPServer(
            name="test",
            command=None,
            args=[],
            url="https://api.example.com/mcp",
            transport="sse",
        )
        findings = check_audit(server)
        assert not any(f.check_id == "AT-003" for f in findings)

    def test_clean_stdio_server_no_findings(self):
        server = make_server(
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
            url=None,
        )
        findings = check_audit(server)
        assert len(findings) == 0


class TestSarifOutput:
    def _make_result(self):
        config_json = json.dumps({
            "mcpServers": {
                "bad-server": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"],
                    "env": {"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
                }
            }
        })
        config = parse_config(config_json)
        return scan(config)

    def test_sarif_structure(self):
        result = self._make_result()
        sarif = to_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "MCPAudit"
        assert len(run["results"]) == len(result.findings)

    def test_sarif_rules_match_findings(self):
        result = self._make_result()
        sarif = to_sarif(result)
        rule_ids = {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        result_rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        assert rule_ids == result_rule_ids

    def test_sarif_fingerprints_unique(self):
        result = self._make_result()
        sarif = to_sarif(result)
        fingerprints = [r["fingerprints"]["mcpAudit/v1"] for r in sarif["runs"][0]["results"]]
        assert len(fingerprints) == len(set(fingerprints))

    def test_sarif_critical_maps_to_error(self):
        result = self._make_result()
        sarif = to_sarif(result)
        # AWS key should be SEC-001 with CRITICAL severity → SARIF "error"
        sec001 = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "SEC-001"]
        assert len(sec001) > 0
        assert sec001[0]["level"] == "error"
