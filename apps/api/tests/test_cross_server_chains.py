"""
Tests for cross-server capability chain analysis: CHAIN-001, CHAIN-002, CHAIN-003.
Research 2: see research/cross_server_chains/RESEARCH.md for background.
"""

import pytest
from tests.conftest import make_server, make_config
from engine.checks.chain_analysis import check_cross_server_chains, _classify_capabilities
from engine.checks.privilege import check_privilege
from engine.checks.secrets import check_secrets
from engine.scanner import scan
from engine.parser import MCPServer
from engine.models import Severity, OWASPCategory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_chains(servers, extra_findings=None):
    """
    Run check_cross_server_chains with the given MCPServer list.
    extra_findings: dict[server_name → list[Finding]] for injecting simulated findings.
    """
    config = make_config(servers)
    per_server = {s.name: [] for s in servers}
    if extra_findings:
        for name, findings in extra_findings.items():
            per_server[name] = findings
    return check_cross_server_chains(config, per_server)


def _findings_with_real_checks(servers):
    """
    Run a real scan (with actual per-server checks) and return CHAIN findings.
    Slower but exercises the full integration path.
    """
    config = make_config(servers)
    result = scan(config)
    return [f for f in result.findings if f.check_id.startswith("CHAIN-")]


# ---------------------------------------------------------------------------
# Capability Classification Unit Tests
# ---------------------------------------------------------------------------

class TestClassifyCapabilities:
    """_classify_capabilities: map one server to its capability buckets."""

    def test_filesystem_server_is_writer(self):
        server = make_server(
            command="npx",
            args=["@modelcontextprotocol/server-filesystem", "/home/user"],
        )
        caps = _classify_capabilities(server, [])
        assert "filesystem_writer" in caps

    def test_shell_command_server_is_executor(self):
        server = make_server(command="bash", args=["-c", "mcp"])
        caps = _classify_capabilities(server, [])
        assert "shell_executor" in caps

    def test_powershell_command_is_executor(self):
        server = make_server(command="powershell", args=["-File", "server.ps1"])
        caps = _classify_capabilities(server, [])
        assert "shell_executor" in caps

    def test_docker_command_is_executor(self):
        server = make_server(command="docker", args=["run", "my-mcp-image"])
        caps = _classify_capabilities(server, [])
        assert "shell_executor" in caps

    def test_terminal_package_is_executor(self):
        server = make_server(command="npx", args=["mcp-server-terminal"])
        caps = _classify_capabilities(server, [])
        assert "shell_executor" in caps

    def test_fetch_server_is_http_outbound(self):
        server = make_server(command="npx", args=["@modelcontextprotocol/server-fetch"])
        caps = _classify_capabilities(server, [])
        assert "http_outbound" in caps

    def test_external_url_server_is_http_outbound(self):
        server = make_server(url="https://api.example.com/mcp")
        caps = _classify_capabilities(server, [])
        assert "http_outbound" in caps

    def test_localhost_url_is_not_http_outbound(self):
        server = make_server(url="http://localhost:3000")
        caps = _classify_capabilities(server, [])
        assert "http_outbound" not in caps

    def test_server_with_aws_key_is_secret_holder(self):
        from engine.models import Finding, Severity, OWASPCategory
        fake_sec_finding = Finding(
            check_id="SEC-001",
            title="AWS credentials",
            detail="",
            severity=Severity.CRITICAL,
            owasp=OWASPCategory.MCP01,
            server_name="test",
            remediation="",
        )
        server = make_server(env={"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"})
        caps = _classify_capabilities(server, [fake_sec_finding])
        assert "secret_holder" in caps

    def test_clean_server_has_no_capabilities(self):
        server = make_server(command="npx", args=["some-other-package"])
        caps = _classify_capabilities(server, [])
        # Not filesystem, not shell, not secret, not http
        assert "filesystem_writer" not in caps
        assert "shell_executor" not in caps
        assert "secret_holder" not in caps
        assert "http_outbound" not in caps

    def test_pe001_finding_marks_as_filesystem_writer(self):
        from engine.models import Finding, Severity, OWASPCategory
        pe001 = Finding(
            check_id="PE-001",
            title="Broad filesystem path",
            detail="",
            severity=Severity.HIGH,
            owasp=OWASPCategory.MCP02,
            server_name="test",
            remediation="",
        )
        server = make_server(command="npx", args=["some-custom-mcp"])
        caps = _classify_capabilities(server, [pe001])
        assert "filesystem_writer" in caps

    def test_pe002_finding_marks_as_shell_executor(self):
        from engine.models import Finding, Severity, OWASPCategory
        pe002 = Finding(
            check_id="PE-002",
            title="Shell execution",
            detail="",
            severity=Severity.HIGH,
            owasp=OWASPCategory.MCP02,
            server_name="test",
            remediation="",
        )
        server = make_server(command="npx", args=["some-custom-mcp"])
        caps = _classify_capabilities(server, [pe002])
        assert "shell_executor" in caps


# ---------------------------------------------------------------------------
# CHAIN-001: Write + Execute Gadget Pair
# ---------------------------------------------------------------------------

class TestCHAIN001WriteExecute:
    """CHAIN-001: filesystem writer + shell executor on different servers."""

    def test_filesystem_plus_terminal_triggers_chain001(self):
        servers = [
            make_server(
                name="docs",
                command="npx",
                args=["@modelcontextprotocol/server-filesystem", "/tmp"],
            ),
            make_server(
                name="shell",
                command="npx",
                args=["mcp-server-terminal"],
            ),
        ]
        findings = _run_chains(servers)
        chain1 = [f for f in findings if f.check_id == "CHAIN-001"]
        assert len(chain1) == 1

    def test_chain001_severity_is_high(self):
        servers = [
            make_server(name="fs", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/home"]),
            make_server(name="exec", command="bash", args=["-c", "mcp"]),
        ]
        findings = _run_chains(servers)
        chain1 = [f for f in findings if f.check_id == "CHAIN-001"]
        assert chain1[0].severity == Severity.HIGH

    def test_chain001_owasp_mcp02(self):
        servers = [
            make_server(name="fs", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/home"]),
            make_server(name="exec", command="bash", args=["-c", "mcp"]),
        ]
        findings = _run_chains(servers)
        chain1 = [f for f in findings if f.check_id == "CHAIN-001"]
        assert chain1[0].owasp == OWASPCategory.MCP02

    def test_chain001_names_both_servers_in_title(self):
        servers = [
            make_server(name="my-filesystem", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/tmp"]),
            make_server(name="my-terminal", command="npx",
                        args=["mcp-server-terminal"]),
        ]
        findings = _run_chains(servers)
        chain1 = [f for f in findings if f.check_id == "CHAIN-001"]
        assert "my-filesystem" in chain1[0].title
        assert "my-terminal" in chain1[0].title

    def test_no_chain001_with_only_filesystem_server(self):
        servers = [
            make_server(name="fs1", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/tmp"]),
            make_server(name="fs2", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/home"]),
        ]
        findings = _run_chains(servers)
        assert not any(f.check_id == "CHAIN-001" for f in findings)

    def test_no_chain001_with_only_executor(self):
        servers = [
            make_server(name="t1", command="bash", args=[]),
            make_server(name="t2", command="bash", args=[]),
        ]
        findings = _run_chains(servers)
        assert not any(f.check_id == "CHAIN-001" for f in findings)

    def test_no_chain001_when_same_server_has_both(self):
        # If one server has both capabilities, PE-001+PE-002 already cover it.
        # CHAIN-001 should only fire for DIFFERENT servers.
        server = make_server(
            name="super-server",
            command="npx",
            args=["@modelcontextprotocol/server-filesystem", "/home", "--exec"],
        )
        findings = _run_chains([server, make_server(name="other")])
        # With only 2 servers and both capabilities on one, no cross-server chain
        # (only super-server has filesystem_writer; no other server has shell_executor)
        chain1 = [f for f in findings if f.check_id == "CHAIN-001"]
        assert len(chain1) == 0

    def test_chain001_fires_with_single_server_config(self):
        # Single server → no chain possible
        servers = [
            make_server(name="fs", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/home"]),
        ]
        findings = _run_chains(servers)
        assert not any(f.check_id == "CHAIN-001" for f in findings)

    def test_chain001_attack_tactic_is_execution(self):
        servers = [
            make_server(name="fs", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/tmp"]),
            make_server(name="exec", command="bash", args=[]),
        ]
        findings = _run_chains(servers)
        chain1 = [f for f in findings if f.check_id == "CHAIN-001"]
        assert chain1[0].attack_tactic == "execution"

    def test_chain001_cwe_250(self):
        servers = [
            make_server(name="fs", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/tmp"]),
            make_server(name="exec", command="bash", args=[]),
        ]
        findings = _run_chains(servers)
        chain1 = [f for f in findings if f.check_id == "CHAIN-001"]
        assert chain1[0].cwe_id == "CWE-250"


# ---------------------------------------------------------------------------
# CHAIN-002: Secrets + HTTP Exfiltration Chain
# ---------------------------------------------------------------------------

class TestCHAIN002CredentialExfiltration:
    """CHAIN-002: secret_holder + http_outbound on different servers."""

    def test_secrets_plus_fetch_triggers_chain002(self):
        from engine.models import Finding, Severity, OWASPCategory as OC
        # Simulate a SEC-001 finding on the vault server
        sec_finding = Finding(
            check_id="SEC-001", title="AWS key", detail="",
            severity=Severity.CRITICAL, owasp=OC.MCP01,
            server_name="vault", remediation="",
        )
        servers = [
            make_server(name="vault", env={"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"}),
            make_server(name="fetcher", command="npx",
                        args=["@modelcontextprotocol/server-fetch"]),
        ]
        findings = _run_chains(servers, extra_findings={"vault": [sec_finding]})
        chain2 = [f for f in findings if f.check_id == "CHAIN-002"]
        assert len(chain2) == 1

    def test_chain002_severity_is_high(self):
        from engine.models import Finding, Severity as Sev, OWASPCategory as OC
        sec = Finding(check_id="SEC-002", title="GH PAT", detail="",
                      severity=Sev.CRITICAL, owasp=OC.MCP01,
                      server_name="creds", remediation="")
        servers = [
            make_server(name="creds"),
            make_server(name="http", command="npx", args=["@modelcontextprotocol/server-fetch"]),
        ]
        findings = _run_chains(servers, extra_findings={"creds": [sec]})
        chain2 = [f for f in findings if f.check_id == "CHAIN-002"]
        assert chain2[0].severity == Severity.HIGH

    def test_chain002_owasp_mcp01(self):
        from engine.models import Finding, Severity as Sev, OWASPCategory as OC
        sec = Finding(check_id="SEC-001", title="t", detail="",
                      severity=Sev.CRITICAL, owasp=OC.MCP01,
                      server_name="s", remediation="")
        servers = [
            make_server(name="s"),
            make_server(name="http", command="npx", args=["@modelcontextprotocol/server-fetch"]),
        ]
        findings = _run_chains(servers, extra_findings={"s": [sec]})
        chain2 = [f for f in findings if f.check_id == "CHAIN-002"]
        assert chain2[0].owasp == OWASPCategory.MCP01

    def test_no_chain002_without_http_server(self):
        from engine.models import Finding, Severity as Sev, OWASPCategory as OC
        sec = Finding(check_id="SEC-001", title="t", detail="",
                      severity=Sev.CRITICAL, owasp=OC.MCP01,
                      server_name="vault", remediation="")
        servers = [
            make_server(name="vault"),
            make_server(name="other", command="npx", args=["mcp-server-docs"]),
        ]
        findings = _run_chains(servers, extra_findings={"vault": [sec]})
        assert not any(f.check_id == "CHAIN-002" for f in findings)

    def test_no_chain002_without_secret_server(self):
        servers = [
            make_server(name="clean"),
            make_server(name="http", command="npx", args=["@modelcontextprotocol/server-fetch"]),
        ]
        findings = _run_chains(servers)
        assert not any(f.check_id == "CHAIN-002" for f in findings)

    def test_chain002_no_fire_when_same_server(self):
        # Both capabilities on the same server → no cross-server chain
        from engine.models import Finding, Severity as Sev, OWASPCategory as OC
        sec = Finding(check_id="SEC-001", title="t", detail="",
                      severity=Sev.CRITICAL, owasp=OC.MCP01,
                      server_name="combo", remediation="")
        servers = [
            make_server(name="combo", command="npx",
                        args=["@modelcontextprotocol/server-fetch"]),
            make_server(name="clean"),
        ]
        findings = _run_chains(servers, extra_findings={"combo": [sec]})
        # combo has both secret_holder and http_outbound → would fire on itself
        # but CHAIN-002 requires DIFFERENT servers, so no finding
        chain2 = [f for f in findings if f.check_id == "CHAIN-002"]
        assert len(chain2) == 0

    def test_chain002_names_both_servers_in_title(self):
        from engine.models import Finding, Severity as Sev, OWASPCategory as OC
        sec = Finding(check_id="SEC-001", title="t", detail="",
                      severity=Sev.CRITICAL, owasp=OC.MCP01,
                      server_name="my-vault", remediation="")
        servers = [
            make_server(name="my-vault"),
            make_server(name="my-fetcher", command="npx",
                        args=["@modelcontextprotocol/server-fetch"]),
        ]
        findings = _run_chains(servers, extra_findings={"my-vault": [sec]})
        chain2 = [f for f in findings if f.check_id == "CHAIN-002"]
        assert "my-vault" in chain2[0].title
        assert "my-fetcher" in chain2[0].title

    def test_chain002_attack_tactic_exfiltration(self):
        from engine.models import Finding, Severity as Sev, OWASPCategory as OC
        sec = Finding(check_id="SEC-001", title="t", detail="",
                      severity=Sev.CRITICAL, owasp=OC.MCP01,
                      server_name="s", remediation="")
        servers = [
            make_server(name="s"),
            make_server(name="http", command="npx", args=["@modelcontextprotocol/server-fetch"]),
        ]
        findings = _run_chains(servers, extra_findings={"s": [sec]})
        chain2 = [f for f in findings if f.check_id == "CHAIN-002"]
        assert chain2[0].attack_tactic == "exfiltration"

    def test_chain002_external_url_server_as_http_outbound(self):
        from engine.models import Finding, Severity as Sev, OWASPCategory as OC
        sec = Finding(check_id="SEC-003", title="t", detail="",
                      severity=Sev.CRITICAL, owasp=OC.MCP01,
                      server_name="db", remediation="")
        servers = [
            make_server(name="db"),
            make_server(name="api-proxy", url="https://api.attacker.com/mcp"),
        ]
        findings = _run_chains(servers, extra_findings={"db": [sec]})
        chain2 = [f for f in findings if f.check_id == "CHAIN-002"]
        assert len(chain2) == 1


# ---------------------------------------------------------------------------
# CHAIN-003: Amplified Filesystem Blast Radius
# ---------------------------------------------------------------------------

class TestCHAIN003AmplifiedFilesystem:
    """CHAIN-003: 3+ filesystem servers in the same config."""

    def test_three_filesystem_servers_trigger_chain003(self):
        servers = [
            make_server(name="fs-home", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/home"]),
            make_server(name="fs-docs", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/tmp"]),
            make_server(name="fs-work", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/work"]),
        ]
        findings = _run_chains(servers)
        chain3 = [f for f in findings if f.check_id == "CHAIN-003"]
        assert len(chain3) == 1

    def test_two_filesystem_servers_do_not_trigger_chain003(self):
        servers = [
            make_server(name="fs1", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/home"]),
            make_server(name="fs2", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/tmp"]),
        ]
        findings = _run_chains(servers)
        assert not any(f.check_id == "CHAIN-003" for f in findings)

    def test_chain003_severity_is_medium(self):
        servers = [
            make_server(name=f"fs-{i}", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", f"/path{i}"])
            for i in range(3)
        ]
        findings = _run_chains(servers)
        chain3 = [f for f in findings if f.check_id == "CHAIN-003"]
        assert chain3[0].severity == Severity.MEDIUM

    def test_chain003_owasp_mcp02(self):
        servers = [
            make_server(name=f"fs-{i}", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", f"/path{i}"])
            for i in range(3)
        ]
        findings = _run_chains(servers)
        chain3 = [f for f in findings if f.check_id == "CHAIN-003"]
        assert chain3[0].owasp == OWASPCategory.MCP02

    def test_chain003_title_includes_server_count(self):
        servers = [
            make_server(name=f"fs-{i}", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", f"/path{i}"])
            for i in range(4)
        ]
        findings = _run_chains(servers)
        chain3 = [f for f in findings if f.check_id == "CHAIN-003"]
        assert "4" in chain3[0].title

    def test_chain003_attack_tactic_impact(self):
        servers = [
            make_server(name=f"fs-{i}", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", f"/path{i}"])
            for i in range(3)
        ]
        findings = _run_chains(servers)
        chain3 = [f for f in findings if f.check_id == "CHAIN-003"]
        assert chain3[0].attack_tactic == "impact"

    def test_chain003_cwe_732(self):
        servers = [
            make_server(name=f"fs-{i}", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", f"/path{i}"])
            for i in range(3)
        ]
        findings = _run_chains(servers)
        chain3 = [f for f in findings if f.check_id == "CHAIN-003"]
        assert chain3[0].cwe_id == "CWE-732"

    def test_chain003_and_chain001_can_coexist(self):
        # 3+ filesystem servers + a shell executor = CHAIN-001 AND CHAIN-003
        servers = [
            make_server(name=f"fs-{i}", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", f"/path{i}"])
            for i in range(3)
        ] + [make_server(name="shell", command="bash", args=[])]
        findings = _run_chains(servers)
        assert any(f.check_id == "CHAIN-001" for f in findings)
        assert any(f.check_id == "CHAIN-003" for f in findings)


# ---------------------------------------------------------------------------
# Integration: Full Scanner Chain Detection
# ---------------------------------------------------------------------------

class TestChainIntegration:
    """Verify chain checks fire correctly through the full scan() pipeline."""

    def test_full_scan_detects_chain001(self):
        servers = [
            make_server(name="files", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/home/user"]),
            make_server(name="term", command="bash", args=["-c", "mcp"]),
        ]
        chain = _findings_with_real_checks(servers)
        assert any(f.check_id == "CHAIN-001" for f in chain)

    def test_full_scan_detects_chain003(self):
        servers = [
            make_server(name=f"fs-{i}", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", f"/path{i}"])
            for i in range(3)
        ]
        chain = _findings_with_real_checks(servers)
        assert any(f.check_id == "CHAIN-003" for f in chain)

    def test_clean_config_no_chain_findings(self):
        servers = [
            make_server(name="github", command="npx",
                        args=["@modelcontextprotocol/server-github@1.0.0"]),
            make_server(name="sqlite", command="npx",
                        args=["@modelcontextprotocol/server-sqlite@1.0.0", "/tmp/db.sqlite"]),
        ]
        chain = _findings_with_real_checks(servers)
        assert chain == []

    def test_single_server_no_chain_findings(self):
        servers = [
            make_server(name="fs", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/home"]),
        ]
        chain = _findings_with_real_checks(servers)
        assert chain == []

    def test_chain_findings_appear_in_scan_result(self):
        servers = [
            make_server(name="files", command="npx",
                        args=["@modelcontextprotocol/server-filesystem", "/home/user"]),
            make_server(name="term", command="bash", args=[]),
        ]
        config = make_config(servers)
        result = scan(config)
        chain_ids = [f.check_id for f in result.findings if f.check_id.startswith("CHAIN-")]
        assert "CHAIN-001" in chain_ids
