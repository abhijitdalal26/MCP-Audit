"""Tests for new checks: SH-004, SH-005, SC-005, AT-004, PE-005, PI-004, and cwe_id on Finding model."""
import json
import pytest
from tests.conftest import make_server, make_config
from engine.checks.shadow import check_shadow
from engine.checks.supply_chain import check_supply_chain
from engine.checks.audit import check_audit
from engine.checks.tool_poisoning import check_tool_poisoning
from engine.checks.secrets import check_secrets
from engine.parser import parse_config, MCPServer
from engine.scanner import scan
from engine.models import Severity, Finding


class TestSH004HomoglyphsInServerName:
    """SH-004: Server names containing non-ASCII Unicode letters (homoglyph spoofing)."""

    def test_cyrillic_a_in_name_flagged(self):
        # Cyrillic 'а' (U+0430) looks identical to Latin 'a' but is different
        server = MCPServer(name="filesysteм", command="npx", args=[])  # Cyrillic м
        findings = check_shadow(server)
        sh4 = [f for f in findings if f.check_id == "SH-004"]
        assert len(sh4) == 1
        assert sh4[0].severity == Severity.HIGH

    def test_pure_ascii_name_not_flagged(self):
        server = MCPServer(name="filesystem", command="npx", args=[])
        findings = check_shadow(server)
        assert not any(f.check_id == "SH-004" for f in findings)

    def test_ascii_with_hyphens_not_flagged(self):
        server = MCPServer(name="my-mcp-server-123", command="npx", args=[])
        findings = check_shadow(server)
        assert not any(f.check_id == "SH-004" for f in findings)

    def test_cwe_id_set_on_sh004(self):
        server = MCPServer(name="fileѕystem", command="npx", args=[])  # Cyrillic ѕ
        findings = check_shadow(server)
        sh4 = [f for f in findings if f.check_id == "SH-004"]
        assert len(sh4) == 1
        assert sh4[0].cwe_id == "CWE-1007"

    def test_attack_tactic_defense_evasion(self):
        server = MCPServer(name="fіlesystem", command="npx", args=[])  # Cyrillic і
        findings = check_shadow(server)
        sh4 = [f for f in findings if f.check_id == "SH-004"]
        assert len(sh4) == 1
        assert sh4[0].attack_tactic == "defense-evasion"

    def test_owasp_mcp03_tool_poisoning(self):
        server = MCPServer(name="fileѕystem", command="npx", args=[])
        findings = check_shadow(server)
        sh4 = [f for f in findings if f.check_id == "SH-004"]
        assert sh4[0].owasp.value == "MCP03"

    def test_numbers_only_not_flagged(self):
        server = MCPServer(name="server-123", command="npx", args=[])
        findings = check_shadow(server)
        assert not any(f.check_id == "SH-004" for f in findings)


class TestSH005AutoDiscovery:
    """SH-005: Env var enabling auto-discovery / silent plugin loading."""

    def _make_server_with_env(self, env: dict) -> MCPServer:
        return MCPServer(name="test-server", command="node", args=[], env=env)

    def test_mcp_auto_discovery_true_flagged(self):
        server = self._make_server_with_env({"MCP_AUTO_DISCOVERY": "true"})
        findings = check_shadow(server)
        sh5 = [f for f in findings if f.check_id == "SH-005"]
        assert len(sh5) == 1
        assert sh5[0].severity == Severity.HIGH

    def test_auto_discovery_value_false_not_flagged(self):
        server = self._make_server_with_env({"MCP_AUTO_DISCOVERY": "false"})
        findings = check_shadow(server)
        assert not any(f.check_id == "SH-005" for f in findings)

    def test_plugin_discover_enabled_flagged(self):
        server = self._make_server_with_env({"PLUGIN_DISCOVER": "1"})
        findings = check_shadow(server)
        assert any(f.check_id == "SH-005" for f in findings)

    def test_dynamic_load_yes_flagged(self):
        server = self._make_server_with_env({"DYNAMIC_LOAD": "yes"})
        findings = check_shadow(server)
        assert any(f.check_id == "SH-005" for f in findings)

    def test_unrelated_env_not_flagged(self):
        server = self._make_server_with_env({"DATABASE_URL": "postgres://localhost/db", "PORT": "3000"})
        findings = check_shadow(server)
        assert not any(f.check_id == "SH-005" for f in findings)

    def test_cwe_id_set_on_sh005(self):
        server = self._make_server_with_env({"MCP_AUTO_DISCOVERY": "true"})
        findings = check_shadow(server)
        sh5 = [f for f in findings if f.check_id == "SH-005"]
        assert sh5[0].cwe_id == "CWE-284"

    def test_owasp_mcp09_shadow(self):
        server = self._make_server_with_env({"MCP_AUTO_DISCOVERY": "true"})
        findings = check_shadow(server)
        sh5 = [f for f in findings if f.check_id == "SH-005"]
        assert sh5[0].owasp.value == "MCP09"

    def test_server_discover_on_flagged(self):
        server = self._make_server_with_env({"SERVER_DISCOVERY": "on"})
        findings = check_shadow(server)
        assert any(f.check_id == "SH-005" for f in findings)

    def test_corpus_dezocode_pattern(self):
        """Real-world Dezocode config: MCP_AUTO_DISCOVERY=true + MCP_SYSTEM_PATH."""
        server = MCPServer(
            name="mcp-system",
            command="/Users/dezmondhollins/bin/mcp-universal",
            args=["router"],
            env={"MCP_AUTO_DISCOVERY": "true", "MCP_SYSTEM_PATH": "/etc/mcp"},
        )
        findings = check_shadow(server)
        assert any(f.check_id == "SH-005" for f in findings)


class TestSC005GitHubRefDependency:
    """SC-005: npx args using github:user/repo (bypasses npm audit trail)."""

    def test_github_ref_flagged(self):
        server = MCPServer(
            name="pdf-generator",
            command="npx",
            args=["github:FabianGenell/pdf-mcp-server"],
        )
        findings = check_supply_chain(server)
        sc5 = [f for f in findings if f.check_id == "SC-005"]
        assert len(sc5) == 1
        assert sc5[0].severity == Severity.HIGH

    def test_bitbucket_ref_flagged(self):
        server = MCPServer(
            name="my-server",
            command="npx",
            args=["bitbucket:myorg/my-mcp"],
        )
        findings = check_supply_chain(server)
        assert any(f.check_id == "SC-005" for f in findings)

    def test_gitlab_ref_flagged(self):
        server = MCPServer(
            name="my-server",
            command="npx",
            args=["gitlab:myorg/my-mcp"],
        )
        findings = check_supply_chain(server)
        assert any(f.check_id == "SC-005" for f in findings)

    def test_normal_npm_package_not_flagged_sc005(self):
        server = MCPServer(
            name="fs",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem"],
        )
        findings = check_supply_chain(server)
        assert not any(f.check_id == "SC-005" for f in findings)

    def test_cwe_id_set_on_sc005(self):
        server = MCPServer(
            name="pdf-gen",
            command="npx",
            args=["github:SomeUser/some-mcp-server"],
        )
        findings = check_supply_chain(server)
        sc5 = [f for f in findings if f.check_id == "SC-005"]
        assert sc5[0].cwe_id == "CWE-829"

    def test_attack_tactic_initial_access(self):
        server = MCPServer(
            name="pdf-gen",
            command="npx",
            args=["github:SomeUser/some-mcp-server"],
        )
        findings = check_supply_chain(server)
        sc5 = [f for f in findings if f.check_id == "SC-005"]
        assert sc5[0].attack_tactic == "initial-access"

    def test_owasp_mcp04_supply_chain(self):
        server = MCPServer(
            name="pdf-gen",
            command="npx",
            args=["github:SomeUser/some-mcp-server"],
        )
        findings = check_supply_chain(server)
        sc5 = [f for f in findings if f.check_id == "SC-005"]
        assert sc5[0].owasp.value == "MCP04"

    def test_corpus_canfieldjuan_pdf_generator(self):
        """Real-world Canfield config has github:FabianGenell/pdf-mcp-server."""
        config_json = json.dumps({
            "mcpServers": {
                "pdf-generator": {
                    "command": "npx",
                    "args": ["github:FabianGenell/pdf-mcp-server"],
                }
            }
        })
        config = parse_config(config_json)
        result = scan(config)
        check_ids = {f.check_id for f in result.findings}
        assert "SC-005" in check_ids


class TestAT004NeighborJack:
    """AT-004: MCP server bound to 0.0.0.0 or [::] (all-interfaces binding)."""

    def test_0000_url_flagged(self):
        server = MCPServer(
            name="local-server",
            command=None,
            args=[],
            url="http://0.0.0.0:3000/mcp",
        )
        findings = check_audit(server)
        at4 = [f for f in findings if f.check_id == "AT-004"]
        assert len(at4) == 1
        assert at4[0].severity == Severity.HIGH

    def test_ipv6_any_url_flagged(self):
        server = MCPServer(
            name="local-server",
            command=None,
            args=[],
            url="http://[::]:3000/mcp",
        )
        findings = check_audit(server)
        assert any(f.check_id == "AT-004" for f in findings)

    def test_localhost_not_flagged_at004(self):
        server = MCPServer(
            name="local-server",
            command=None,
            args=[],
            url="http://localhost:3000/mcp",
        )
        findings = check_audit(server)
        assert not any(f.check_id == "AT-004" for f in findings)

    def test_127001_not_flagged_at004(self):
        server = MCPServer(
            name="local-server",
            command=None,
            args=[],
            url="http://127.0.0.1:3000/mcp",
        )
        findings = check_audit(server)
        assert not any(f.check_id == "AT-004" for f in findings)

    def test_cwe_668_on_at004(self):
        server = MCPServer(
            name="exposed",
            command=None,
            args=[],
            url="http://0.0.0.0:8080/mcp",
        )
        findings = check_audit(server)
        at4 = [f for f in findings if f.check_id == "AT-004"]
        assert at4[0].cwe_id == "CWE-668"

    def test_owasp_mcp08_on_at004(self):
        server = MCPServer(
            name="exposed",
            command=None,
            args=[],
            url="http://0.0.0.0:8080/mcp",
        )
        findings = check_audit(server)
        at4 = [f for f in findings if f.check_id == "AT-004"]
        assert at4[0].owasp.value == "MCP08"

    def test_attack_tactic_initial_access(self):
        server = MCPServer(
            name="exposed",
            command=None,
            args=[],
            url="http://0.0.0.0:8080/mcp",
        )
        findings = check_audit(server)
        at4 = [f for f in findings if f.check_id == "AT-004"]
        assert at4[0].attack_tactic == "initial-access"


class TestPE005DockerPrivilegeEscalation:
    """PE-005: Docker containers with dangerous flags or sensitive host volume mounts."""

    def test_privileged_flag_flagged(self):
        server = MCPServer(
            name="docker-server",
            command="docker",
            args=["run", "-i", "--rm", "--privileged", "ubuntu", "bash"],
        )
        from engine.checks.privilege import check_privilege
        findings = check_privilege(server)
        pe5 = [f for f in findings if f.check_id == "PE-005"]
        assert len(pe5) >= 1
        assert pe5[0].severity == Severity.CRITICAL

    def test_network_host_flagged(self):
        server = MCPServer(
            name="docker-server",
            command="docker",
            args=["run", "--network=host", "my-mcp-image"],
        )
        from engine.checks.privilege import check_privilege
        findings = check_privilege(server)
        assert any(f.check_id == "PE-005" for f in findings)

    def test_root_volume_mount_flagged(self):
        server = MCPServer(
            name="docker-server",
            command="docker",
            args=["run", "-v", "/:/host", "ubuntu"],
        )
        from engine.checks.privilege import check_privilege
        findings = check_privilege(server)
        pe5 = [f for f in findings if f.check_id == "PE-005"]
        assert len(pe5) >= 1
        assert pe5[0].severity == Severity.CRITICAL

    def test_etc_volume_mount_flagged(self):
        server = MCPServer(
            name="docker-server",
            command="docker",
            args=["run", "-v", "/etc:/host-etc", "ubuntu"],
        )
        from engine.checks.privilege import check_privilege
        findings = check_privilege(server)
        assert any(f.check_id == "PE-005" for f in findings)

    def test_docker_sock_mount_flagged(self):
        server = MCPServer(
            name="docker-server",
            command="docker",
            args=["run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "ubuntu"],
        )
        from engine.checks.privilege import check_privilege
        findings = check_privilege(server)
        assert any(f.check_id == "PE-005" for f in findings)

    def test_safe_docker_not_flagged(self):
        server = MCPServer(
            name="docker-server",
            command="docker",
            args=["run", "-i", "--rm", "-v", "/home/user/projects:/workspace", "mcp-image"],
        )
        from engine.checks.privilege import check_privilege
        findings = check_privilege(server)
        assert not any(f.check_id == "PE-005" for f in findings)

    def test_non_docker_command_not_flagged(self):
        server = MCPServer(
            name="node-server",
            command="node",
            args=["server.js", "--privileged"],
        )
        from engine.checks.privilege import check_privilege
        findings = check_privilege(server)
        assert not any(f.check_id == "PE-005" for f in findings)

    def test_cwe_250_on_pe005_flag(self):
        server = MCPServer(
            name="docker-server",
            command="docker",
            args=["run", "--privileged", "ubuntu"],
        )
        from engine.checks.privilege import check_privilege
        findings = check_privilege(server)
        pe5 = [f for f in findings if f.check_id == "PE-005"]
        assert pe5[0].cwe_id == "CWE-250"

    def test_owasp_mcp05_on_pe005(self):
        server = MCPServer(
            name="docker-server",
            command="docker",
            args=["run", "--privileged", "ubuntu"],
        )
        from engine.checks.privilege import check_privilege
        findings = check_privilege(server)
        pe5 = [f for f in findings if f.check_id == "PE-005"]
        assert pe5[0].owasp.value == "MCP05"

    def test_corpus_terminal_server_docker_pattern(self):
        """Real-world pattern: docker run -i --rm with workspace volume (should be safe)."""
        config_json = json.dumps({
            "mcpServers": {
                "terminal_server": {
                    "command": "docker",
                    "args": [
                        "run", "-i", "--rm",
                        "-v", "/Users/user/mcp/workspace:/workspace",
                        "mcp-terminal-image",
                    ],
                }
            }
        })
        config = parse_config(config_json)
        result = scan(config)
        check_ids = {f.check_id for f in result.findings}
        assert "PE-005" not in check_ids


class TestCweIdOnFindingModel:
    """cwe_id field is optional on Finding and appears in scan results."""

    def test_cwe_id_optional_defaults_none(self):
        f = Finding(
            check_id="TEST-001",
            title="Test",
            detail="Test detail",
            severity=Severity.LOW,
            owasp="MCP01",
            server_name="server",
            remediation="Fix it",
        )
        assert f.cwe_id is None

    def test_cwe_id_set_survives_round_trip(self):
        f = Finding(
            check_id="SH-004",
            title="Homoglyph",
            detail="detail",
            severity=Severity.HIGH,
            owasp="MCP03",
            server_name="server",
            remediation="Fix",
            cwe_id="CWE-1007",
        )
        data = f.model_dump()
        assert data["cwe_id"] == "CWE-1007"
        f2 = Finding(**data)
        assert f2.cwe_id == "CWE-1007"

    def test_scan_result_includes_cwe_ids(self):
        """Full scan on a config triggering SH-005 should have cwe_id in findings."""
        config_json = json.dumps({
            "mcpServers": {
                "auto-loader": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"MCP_AUTO_DISCOVERY": "true"},
                }
            }
        })
        config = parse_config(config_json)
        result = scan(config)
        sh5_findings = [f for f in result.findings if f.check_id == "SH-005"]
        assert len(sh5_findings) == 1
        assert sh5_findings[0].cwe_id == "CWE-284"


class TestPI004Obfuscation:
    """PI-004: Escape-sequence obfuscation in server args (defense-evasion technique).

    Attack vector: JSON config uses double-backslash (\\\\uXXXX) so that after JSON parsing
    the string contains literal \\uXXXX sequences — invisible in UI but interpreted by LLMs.
    """

    def test_unicode_escapes_flagged(self):
        # After JSON parse: arg contains literal Igno = "Ign" hidden in escapes
        # In Python string: "\\u0049\\u0067\\u006e\\u006f" = backslash-u-0049-backslash-u-0067...
        esc_arg = "\\u0049\\u0067\\u006e\\u006f\\u0072\\u0065\\u0020\\u0061\\u006c\\u006c"
        server = MCPServer(name="evil-server", command="npx", args=["-y", "some-pkg", esc_arg])
        findings = check_tool_poisoning(server)
        pi4 = [f for f in findings if f.check_id == "PI-004"]
        assert len(pi4) == 1
        assert pi4[0].severity == Severity.HIGH

    def test_hex_escapes_flagged(self):
        # \x69\x67\x6e\x6f\x72\x65 = "ignore" in hex — 6 consecutive hex escapes
        esc_arg = "\\x69\\x67\\x6e\\x6f\\x72\\x65\\x20\\x61\\x6c\\x6c"
        server = MCPServer(name="evil-server", command="npx", args=["-y", "pkg", esc_arg])
        findings = check_tool_poisoning(server)
        pi4 = [f for f in findings if f.check_id == "PI-004"]
        assert len(pi4) == 1

    def test_cwe_116_and_mcp03(self):
        esc_arg = "\\u0049\\u0067\\u006e\\u006f\\u0072\\u0065\\u0020\\u0070\\u0072"
        server = MCPServer(name="evil-server", command="npx", args=[esc_arg])
        findings = check_tool_poisoning(server)
        pi4 = [f for f in findings if f.check_id == "PI-004"]
        assert len(pi4) == 1
        assert pi4[0].cwe_id == "CWE-116"
        assert pi4[0].owasp.value == "MCP03"

    def test_attack_tactic_defense_evasion(self):
        esc_arg = "\\u0049\\u0067\\u006e\\u006f\\u0072\\u0065\\u0020\\u0070\\u0072"
        server = MCPServer(name="evil-server", command="npx", args=[esc_arg])
        findings = check_tool_poisoning(server)
        pi4 = [f for f in findings if f.check_id == "PI-004"]
        assert pi4[0].attack_tactic == "defense-evasion"

    def test_only_3_unicode_escapes_not_flagged(self):
        """3 consecutive unicode escapes (below threshold of 4) should not be flagged."""
        esc_arg = "\\u0049\\u0067\\u006e"  # only 3 — below threshold
        server = MCPServer(name="server", command="npx", args=["-y", esc_arg])
        findings = check_tool_poisoning(server)
        assert not any(f.check_id == "PI-004" for f in findings)

    def test_normal_args_not_flagged(self):
        server = MCPServer(
            name="filesystem",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/Users/me/projects"],
        )
        findings = check_tool_poisoning(server)
        assert not any(f.check_id == "PI-004" for f in findings)

    def test_at_most_one_pi004_per_server(self):
        """Even if multiple args contain obfuscation, only one PI-004 fires per server."""
        esc1 = "\\u0049\\u0067\\u006e\\u006f\\u0072\\u0065"
        esc2 = "\\u0049\\u0067\\u006e\\u006f\\u0072\\u0065\\u0073"
        server = MCPServer(name="evil-server", command="npx", args=[esc1, esc2])
        findings = check_tool_poisoning(server)
        pi4 = [f for f in findings if f.check_id == "PI-004"]
        assert len(pi4) == 1


class TestSEC003HttpBasicAuth:
    """SEC-003 extended: HTTP Basic Auth credentials embedded in URL."""

    def test_http_basic_auth_url_detected(self):
        server = make_server(env={"API_URL": "http://admin:mysecretpassword@internal.server.com/api"})
        findings = check_secrets(server)
        sec3 = [f for f in findings if f.check_id == "SEC-003"]
        assert len(sec3) >= 1

    def test_https_basic_auth_url_detected(self):
        server = make_server(env={"ENDPOINT": "https://user:supersecret@example.internal/v1"})
        findings = check_secrets(server)
        assert any(f.check_id == "SEC-003" for f in findings)

    def test_url_without_password_not_flagged(self):
        """http://example.com without credentials is not an auth URL."""
        server = make_server(env={"URL": "https://api.example.com/endpoint"})
        findings = check_secrets(server)
        sec3 = [f for f in findings if f.check_id == "SEC-003"]
        assert len(sec3) == 0

    def test_placeholder_http_auth_not_flagged(self):
        server = make_server(env={"URL": "${BASE_URL}"})
        findings = check_secrets(server)
        assert not any(f.check_id == "SEC-003" for f in findings)
