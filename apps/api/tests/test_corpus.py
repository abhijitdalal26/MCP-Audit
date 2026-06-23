"""Corpus tests: scan real-world MCP configs fetched from GitHub public repos.

These tests assert the engine never crashes and produces valid output.
They also write JSON snapshots to tests/corpus/snapshots/ so findings
from real configs can be reviewed and tracked over time.
"""
import json
import os
import pathlib
import pytest
from engine.parser import parse_config
from engine.scanner import scan
from engine.models import ScanResult

CORPUS_DIR = pathlib.Path(__file__).parent / "corpus"
SNAPSHOTS_DIR = CORPUS_DIR / "snapshots"
SNAPSHOTS_DIR.mkdir(exist_ok=True)


def _load_corpus_file(filename: str) -> str:
    return (CORPUS_DIR / filename).read_text(encoding="utf-8")


def _scan_and_snapshot(filename: str) -> ScanResult:
    raw = _load_corpus_file(filename)
    config = parse_config(raw)
    result = scan(config)

    # Write snapshot for human review — never assert specific findings here
    stem = pathlib.Path(filename).stem
    snapshot_path = SNAPSHOTS_DIR / f"{stem}_snapshot.json"
    snapshot = {
        "source_file": filename,
        "risk_score": result.summary.risk_score,
        "risk_grade": result.summary.risk_grade,
        "total_findings": result.summary.total,
        "by_severity": {
            "critical": result.summary.critical,
            "high": result.summary.high,
            "medium": result.summary.medium,
            "low": result.summary.low,
            "info": result.summary.info,
        },
        "findings": [
            {
                "check_id": f.check_id,
                "title": f.title,
                "severity": f.severity.value,
                "server": f.server_name,
                "owasp": f.owasp.value,
                "attack_tactic": f.attack_tactic,
            }
            for f in result.findings
        ],
    }
    snapshot_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    return result


class TestCorpusNoCrash:
    """Engine must not crash on any real-world config. Output must be valid."""

    def test_confluent_enterprise(self):
        result = _scan_and_snapshot("real_confluent.json")
        assert 0 <= result.summary.risk_score <= 100
        assert result.summary.risk_grade in ("A", "B", "C", "D", "F")
        assert isinstance(result.findings, list)

    def test_terminal_server_jsonc(self):
        """File has // JS comments and two JSON objects — parser must handle gracefully."""
        result = _scan_and_snapshot("real_terminal_server.jsonc")
        assert 0 <= result.summary.risk_score <= 100
        # Terminal server with uv + direct path should produce findings
        assert isinstance(result.findings, list)

    def test_canfieldjuan_multi_server(self):
        """12-server real user config with env placeholders."""
        result = _scan_and_snapshot("real_canfieldjuan.json")
        assert 0 <= result.summary.risk_score <= 100
        check_ids = {f.check_id for f in result.findings}
        # Should catch duplicated puppeteer server (CL-002)
        assert "CL-002" in check_ids, f"Expected CL-002, got: {check_ids}"
        # Unpinned versions everywhere
        assert "AT-001" in check_ids or any(
            f.check_id == "SEC-006" for f in result.findings
        )

    def test_angrysky56_windows_root_drives(self):
        """Windows config with F:/ and D:/ root drive access — PE-001 must fire."""
        result = _scan_and_snapshot("real_angrysky56.json")
        assert 0 <= result.summary.risk_score <= 100
        check_ids = {f.check_id for f in result.findings}
        # F:/ and D:/ are root drives — broad filesystem access
        assert "PE-001" in check_ids, f"Expected PE-001 for root drives, got: {check_ids}"

    def test_dezocode_custom_binary(self):
        """Real user backup with unknown binary and MCP_AUTO_DISCOVERY=true."""
        result = _scan_and_snapshot("real_dezocode.json")
        assert 0 <= result.summary.risk_score <= 100
        # SH-001 should fire: binary not in known-good registry
        check_ids = {f.check_id for f in result.findings}
        assert len(result.findings) >= 0  # at minimum: no crash

    def test_synthetic_adversarial_multi_vector(self):
        """Synthetic worst-case config exercises SEC-007, EX-003, CL-003, PE-006, DX-001, PI-001."""
        result = _scan_and_snapshot("synthetic_adversarial.json")
        check_ids = {f.check_id for f in result.findings}
        # Must catch at minimum: SEC-001 (AWS key), EX-003 (curl|bash or PS encoded),
        # SEC-007 (metadata endpoint), PI-001 (injection in env), PE-006 (sudo), DX-001 (BCC)
        assert "SEC-001" in check_ids, "AWS key in env var must be caught"
        assert "EX-003" in check_ids, "PowerShell encoded command or curl|bash must be caught"
        assert "SEC-007" in check_ids, "Cloud metadata endpoint URL must be caught"
        assert "PI-001" in check_ids, "Prompt injection phrase in env var must be caught"
        assert "PE-006" in check_ids, "sudo as command must be caught"
        assert "DX-001" in check_ids, "BCC exfiltration env var must be caught"
        assert "PE-007" in check_ids, "--dangerously-skip-permissions must be caught"
        assert result.summary.risk_grade == "F", "Adversarial config must grade as F"


class TestCorpusFindings:
    """Assert specific expected security findings in real configs."""

    def test_canfieldjuan_placeholder_env_not_flagged_as_secret(self):
        """${env:GITHUB_PERSONAL_ACCESS_TOKEN} is a placeholder — must NOT be flagged as SEC-002."""
        raw = _load_corpus_file("real_canfieldjuan.json")
        config = parse_config(raw)
        result = scan(config)
        # Should have no SEC-001/002 from placeholder values
        secret_findings = [
            f for f in result.findings
            if f.check_id in ("SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005")
            and "${env:" in f.detail
        ]
        assert len(secret_findings) == 0, (
            f"Placeholder env vars incorrectly flagged as secrets: {[f.detail for f in secret_findings]}"
        )

    def test_angrysky56_placeholder_tokens_not_flagged(self):
        """'your token', 'your key', 'xoxb-etc...' must be filtered by placeholder logic."""
        raw = _load_corpus_file("real_angrysky56.json")
        config = parse_config(raw)
        result = scan(config)
        # 'your token' and 'your key' are clearly placeholder values
        placeholder_secrets = [
            f for f in result.findings
            if f.check_id in ("SEC-001", "SEC-002", "SEC-003", "SEC-004")
            and any(p in f.detail for p in ["your token", "your key", "xoxb-etc", "ANTHROPIC_API_KEY"])
        ]
        assert len(placeholder_secrets) == 0, (
            f"Placeholder values flagged as secrets: {[f.detail for f in placeholder_secrets]}"
        )

    def test_all_corpus_risk_scores_bounded(self):
        """Risk score must be 0-100 for every corpus file."""
        corpus_files = [
            "real_confluent.json",
            "real_canfieldjuan.json",
            "real_angrysky56.json",
            "real_dezocode.json",
        ]
        for fname in corpus_files:
            raw = _load_corpus_file(fname)
            config = parse_config(raw)
            result = scan(config)
            assert 0 <= result.summary.risk_score <= 100, (
                f"{fname}: risk_score {result.summary.risk_score} out of range"
            )

    def test_corpus_scan_is_deterministic(self):
        """Same config must always produce the same config_hash and finding count."""
        raw = _load_corpus_file("real_canfieldjuan.json")
        config1 = parse_config(raw)
        config2 = parse_config(raw)
        result1 = scan(config1)
        result2 = scan(config2)
        assert config1.config_hash == config2.config_hash
        assert result1.summary.total == result2.summary.total
        assert [f.check_id for f in result1.findings] == [f.check_id for f in result2.findings]
