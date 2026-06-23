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

    def test_latest_tag_flagged_as_unpinned(self):
        """@latest is a dist-tag, not a version pin — rug pull risk."""
        server = make_server(args=["-y", "@modelcontextprotocol/server-filesystem@latest"])
        findings = check_secrets(server)
        ids = [f.check_id for f in findings]
        assert "SEC-006" in ids

    def test_next_tag_flagged_as_unpinned(self):
        server = make_server(args=["-y", "some-package@next"])
        findings = check_secrets(server)
        assert any(f.check_id == "SEC-006" for f in findings)

    def test_beta_tag_flagged_as_unpinned(self):
        server = make_server(args=["-y", "some-package@beta"])
        findings = check_secrets(server)
        assert any(f.check_id == "SEC-006" for f in findings)

    def test_exact_semver_not_flagged(self):
        server = make_server(args=["-y", "some-package@2.3.1"])
        findings = check_secrets(server)
        assert not any(f.check_id == "SEC-006" for f in findings)


class TestCloudMetadataEndpoint:
    """SEC-007: Cloud instance metadata endpoints in env vars (SSRF credential theft vector)."""

    def test_aws_imds_endpoint_flagged(self):
        server = make_server(env={"BACKEND_URL": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"})
        findings = check_secrets(server)
        assert any(f.check_id == "SEC-007" for f in findings)

    def test_ecs_imds_endpoint_flagged(self):
        server = make_server(env={"METADATA_URL": "http://169.254.170.2/v2/credentials/abc123"})
        findings = check_secrets(server)
        assert any(f.check_id == "SEC-007" for f in findings)

    def test_gcp_metadata_flagged(self):
        server = make_server(env={"AUTH_URL": "http://metadata.google.internal/computeMetadata/v1/"})
        findings = check_secrets(server)
        assert any(f.check_id == "SEC-007" for f in findings)

    def test_severity_is_critical(self):
        server = make_server(env={"URL": "http://169.254.169.254/latest/"})
        findings = check_secrets(server)
        sec7 = [f for f in findings if f.check_id == "SEC-007"]
        assert len(sec7) >= 1
        assert sec7[0].severity == Severity.CRITICAL

    def test_normal_url_not_flagged(self):
        server = make_server(env={"API_URL": "https://api.example.com/v1/data"})
        findings = check_secrets(server)
        assert not any(f.check_id == "SEC-007" for f in findings)


class TestSecretsInArgs:
    """Secrets passed as CLI arg values (not env vars) are also detected."""

    def test_aws_key_in_args_detected(self):
        server = make_server(
            command="npx",
            args=["-y", "some-server", "AKIAIOSFODNN7EXAMPLE"],
        )
        findings = check_secrets(server)
        assert any(f.check_id == "SEC-001" for f in findings)

    def test_github_pat_in_args_detected(self):
        server = make_server(
            command="npx",
            args=["-y", "some-server", "--token", "ghp_EXAMPLEfaketoken0000000000000000000000"],
        )
        findings = check_secrets(server)
        # The flag name "--token" is skipped (starts with -), but the value arg is checked
        assert any(f.check_id == "SEC-002" for f in findings)

    def test_openai_key_in_args_detected(self):
        server = make_server(
            command="node",
            args=["server.js", "--api-key", "sk-proj-EXAMPLEfaketoken000000000000000000000000000000"],
        )
        findings = check_secrets(server)
        assert any(f.check_id == "SEC-004" for f in findings)

    def test_flag_names_not_flagged(self):
        """--api-key itself (the flag name) should not trigger a finding."""
        server = make_server(
            command="node",
            args=["server.js", "--api-key"],
        )
        findings = check_secrets(server)
        # No secret value, so no finding
        sec_findings = [f for f in findings if f.check_id.startswith("SEC-00")]
        assert not any(f.check_id in ("SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005") for f in sec_findings)

    def test_placeholder_arg_not_flagged(self):
        server = make_server(
            command="node",
            args=["server.js", "${MY_API_KEY}"],
        )
        findings = check_secrets(server)
        assert not any(f.check_id in ("SEC-001", "SEC-002", "SEC-004") for f in findings)

    def test_cwe_798_on_arg_secret(self):
        """CWE-798: hardcoded credentials — applies to args just as to env vars."""
        server = make_server(
            command="npx",
            args=["some-server", "AKIAIOSFODNN7EXAMPLE"],
        )
        findings = check_secrets(server)
        sec001 = [f for f in findings if f.check_id == "SEC-001"]
        assert len(sec001) >= 1
        assert sec001[0].cwe_id == "CWE-798"
