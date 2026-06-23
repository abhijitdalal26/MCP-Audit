"""Property-based tests using Hypothesis.

These generate thousands of structurally valid but randomly-valued MCP configs
and assert invariants that must hold for ALL inputs — the engine must never
crash, output must always be bounded, and output must be deterministic.

Run with: pytest tests/test_property.py -v
To see examples: pytest tests/test_property.py --hypothesis-show-statistics
"""
import json
import pytest
from hypothesis import given, settings, HealthCheck, assume
from hypothesis import strategies as st

from engine.parser import MCPConfig, MCPServer, parse_config
from engine.scanner import scan
from engine.sarif import to_sarif
from engine.cyclonedx import to_cyclonedx

# ── Hypothesis strategies for MCP configs ─────────────────────────────────────

_PRINTABLE = st.characters(whitelist_categories=["L", "N", "P", "S"])

_server_name = st.text(
    min_size=1, max_size=40,
    alphabet=st.characters(whitelist_categories=["L", "N"], whitelist_characters=["-", "_"])
)

_safe_text = st.text(min_size=0, max_size=150, alphabet=_PRINTABLE)

_command = st.one_of(
    st.none(),
    st.sampled_from(["npx", "node", "python3", "uvx", "uv", "docker", "npx.cmd"]),
    _safe_text,
)

_arg = st.one_of(
    st.sampled_from([
        "-y", "--ignore-scripts", "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-github", "/Users", "/tmp", "F:/",
        "run", "--directory", "--shell", "/bin/bash",
        "mcp-server-free", "@randomscope/some-mcp-server",
    ]),
    _safe_text,
)

_env_key = st.text(
    min_size=1, max_size=30,
    alphabet=st.characters(whitelist_categories=["L", "N"], whitelist_characters=["_"])
)

_env_value = _safe_text

_server_strategy = st.fixed_dictionaries({
    "command": _command,
    "args": st.lists(_arg, max_size=8),
    "env": st.dictionaries(_env_key, _env_value, max_size=5),
    "url": st.one_of(st.none(), st.sampled_from([
        None, "http://localhost:3000/mcp", "https://api.example.com/mcp",
        "http://api.evil.com/mcp", "ws://localhost:8080",
    ])),
})


def _make_config(servers_dict: dict) -> MCPConfig:
    return MCPConfig(
        config_hash="prop-test",
        servers=[
            MCPServer(
                name=name,
                command=data["command"],
                args=data["args"],
                env=data["env"],
                url=data["url"],
            )
            for name, data in servers_dict.items()
        ]
    )


# ── Invariant tests ───────────────────────────────────────────────────────────

class TestPropertyInvariants:

    @given(
        servers=st.dictionaries(_server_name, _server_strategy, min_size=1, max_size=6)
    )
    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_scan_never_crashes(self, servers):
        """Engine must never raise an exception for any valid MCPConfig."""
        config = _make_config(servers)
        result = scan(config)  # must not raise
        assert result is not None

    @given(
        servers=st.dictionaries(_server_name, _server_strategy, min_size=1, max_size=6)
    )
    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_risk_score_always_bounded(self, servers):
        """Risk score must always be in [0, 100]."""
        config = _make_config(servers)
        result = scan(config)
        assert 0 <= result.summary.risk_score <= 100, (
            f"risk_score={result.summary.risk_score} out of bounds"
        )

    @given(
        servers=st.dictionaries(_server_name, _server_strategy, min_size=1, max_size=6)
    )
    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_risk_grade_always_valid(self, servers):
        """Risk grade must always be one of A, B, C, D, F."""
        config = _make_config(servers)
        result = scan(config)
        assert result.summary.risk_grade in ("A", "B", "C", "D", "F"), (
            f"Invalid grade: {result.summary.risk_grade}"
        )

    @given(
        servers=st.dictionaries(_server_name, _server_strategy, min_size=1, max_size=6)
    )
    @settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_finding_counts_consistent(self, servers):
        """summary.total must equal len(findings)."""
        config = _make_config(servers)
        result = scan(config)
        counted = (
            result.summary.critical + result.summary.high +
            result.summary.medium + result.summary.low + result.summary.info
        )
        assert result.summary.total == len(result.findings), (
            f"total={result.summary.total} != len(findings)={len(result.findings)}"
        )
        assert result.summary.total == counted, (
            f"sum of severities {counted} != total {result.summary.total}"
        )

    @given(
        servers=st.dictionaries(_server_name, _server_strategy, min_size=1, max_size=6)
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_sarif_output_never_crashes(self, servers):
        """SARIF serialization must not crash."""
        config = _make_config(servers)
        result = scan(config)
        sarif = to_sarif(result)
        assert sarif["version"] == "2.1.0"

    @given(
        servers=st.dictionaries(_server_name, _server_strategy, min_size=1, max_size=6)
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_cyclonedx_output_never_crashes(self, servers):
        """CycloneDX serialization must not crash."""
        config = _make_config(servers)
        result = scan(config)
        bom = to_cyclonedx(result, config)
        assert bom["bomFormat"] == "CycloneDX"

    @given(
        servers=st.dictionaries(_server_name, _server_strategy, min_size=1, max_size=4)
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_findings_have_valid_check_ids(self, servers):
        """Every finding must have a non-empty check_id and a valid severity."""
        from engine.models import Severity
        config = _make_config(servers)
        result = scan(config)
        for f in result.findings:
            assert f.check_id, "Finding has empty check_id"
            assert f.severity in Severity, f"Invalid severity: {f.severity}"
            assert f.server_name, "Finding has empty server_name"
            assert f.owasp, "Finding has empty owasp category"


class TestPropertyParserRobustness:

    @given(st.text(max_size=500))
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
    def test_parser_never_crashes_on_arbitrary_input(self, text):
        """Parser must either succeed or raise ValueError — never an unhandled exception."""
        try:
            parse_config(text)
        except ValueError:
            pass  # expected for invalid input
        except Exception as e:
            pytest.fail(f"Unexpected exception type {type(e).__name__}: {e}")

    @given(
        servers=st.dictionaries(
            # Restrict key chars: JSON keys can contain any unicode but we
            # want predictable round-trip behaviour, so avoid control chars
            st.text(min_size=1, max_size=20, alphabet=st.characters(
                whitelist_categories=["L", "N"], whitelist_characters=["-", "_", " "]
            )),
            st.fixed_dictionaries({
                "command": st.text(max_size=50),
                "args": st.lists(st.text(max_size=50), max_size=5),
            }),
            min_size=0,
            max_size=5,
        )
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_json_roundtrip_parse(self, servers):
        """Config serialized as JSON must parse to same server count."""
        config_dict = {"mcpServers": servers}
        config_json = json.dumps(config_dict)
        config = parse_config(config_json)
        assert len(config.servers) == len(servers)

    def test_parser_handles_jsonc_comments(self):
        """JSONC with // comments must parse cleanly."""
        jsonc = """
        // This is a comment
        {
            // Another comment
            "mcpServers": {
                "test": {
                    "command": "npx", // inline comment
                    "args": ["-y", "some-package"]
                }
            }
        }
        """
        config = parse_config(jsonc)
        assert len(config.servers) == 1
        assert config.servers[0].name == "test"

    def test_parser_handles_multi_object_jsonc(self):
        """JSONC with two JSON objects (like terminal_server) extracts first object."""
        jsonc = """
        // First config
        { "mcpServers": { "a": { "command": "npx", "args": [] } } }
        // Second config
        { "mcpServers": { "b": { "command": "node", "args": [] } } }
        """
        config = parse_config(jsonc)
        assert len(config.servers) == 1
        assert config.servers[0].name == "a"

    def test_parser_ignores_extra_top_level_keys(self):
        """Configs with extra keys like 'darkMode', 'mcp_system_integration' must parse ok."""
        config_json = json.dumps({
            "darkMode": "light",
            "scale": 0,
            "mcpServers": {"fs": {"command": "npx", "args": []}},
            "mcp_system_integration": {"enabled": True},
        })
        config = parse_config(config_json)
        assert len(config.servers) == 1
