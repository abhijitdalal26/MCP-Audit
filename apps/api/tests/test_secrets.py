"""Tests for engine/checks/secrets.py"""
import pytest
from tests.conftest import make_server
from engine.checks.secrets import check_secrets
from engine.models import Severity


class TestValuePatterns:
    def test_aws_key_detected(self):
        server = make_server(env={"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"})
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-001" in ids

    def test_github_pat_detected(self):
        server = make_server(env={"TOKEN": "ghp_EXAMPLEfaketoken0000000000000000000000"})
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-002" in ids
        crit = [f for f in findings if f.check_id == "SEC-002"]
        assert crit[0].severity == Severity.CRITICAL

    def test_postgres_url_detected(self):
        server = make_server(env={"DB": "postgresql://admin:s3cr3t@prod.example.com/db"})
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-003" in ids

    def test_openai_key_detected(self):
        server = make_server(env={"KEY": "sk-proj-EXAMPLEfaketoken000000000000000000000000000000"})
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-004" in ids

    def test_slack_bot_token_detected(self):
        server = make_server(env={"SLACK": "xoxb-EXAMPLEONLY-EXAMPLEONLY-EXAMPLEONLYabcdefghi"})
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-004" in ids

    def test_huggingface_token_detected(self):
        server = make_server(env={"HF": "hf_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"})
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-004" in ids

    def test_firebase_key_detected(self):
        server = make_server(env={"KEY": "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz123456789"})
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-004" in ids

    def test_ssh_private_key_detected(self):
        server = make_server(env={"KEY": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA"})
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-005" in ids
        crits = [f for f in findings if f.check_id == "SEC-005"]
        assert crits[0].severity == Severity.CRITICAL

    def test_placeholder_not_flagged(self):
        server = make_server(env={"API_KEY": "${MY_API_KEY}"})
        findings = check_secrets(server)
        # Placeholder should not produce a value-pattern finding
        val_findings = [f for f in findings if "hardcoded in" in f.title]
        assert len(val_findings) == 0

    def test_empty_env_no_findings(self):
        server = make_server(env={})
        findings = check_secrets(server)
        assert len(findings) == 0


class TestSensitiveVarNames:
    def test_aws_var_name_flagged(self):
        server = make_server(env={"AWS_SECRET_ACCESS_KEY": "somesecretvalue123"})
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-001" in ids

    def test_jwt_secret_var_name_flagged(self):
        server = make_server(env={"JWT_SECRET": "mysupersecretvalue"})
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-005" in ids


class TestUnpinnedVersions:
    def test_unpinned_package_flagged(self):
        server = make_server(args=["-y", "@modelcontextprotocol/server-filesystem"])
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-006" in ids

    def test_pinned_package_not_flagged(self):
        server = make_server(args=["-y", "@modelcontextprotocol/server-filesystem@1.0.0"])
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-006" not in ids
