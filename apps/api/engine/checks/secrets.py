import re
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

# (check_id, human title, compiled regex, severity)
_VALUE_PATTERNS: list[tuple[str, str, re.Pattern, Severity]] = [
    ("SEC-001", "AWS Access Key ID",
     re.compile(r'AKIA[0-9A-Z]{16}'), Severity.CRITICAL),
    ("SEC-002", "GitHub Personal Access Token",
     re.compile(r'ghp_[A-Za-z0-9]{36,}'), Severity.CRITICAL),
    ("SEC-002", "GitHub OAuth Token",
     re.compile(r'gho_[A-Za-z0-9]{36,}'), Severity.CRITICAL),
    ("SEC-002", "GitHub App Token",
     re.compile(r'ghs_[A-Za-z0-9]{36,}'), Severity.CRITICAL),
    ("SEC-002", "GitLab Personal Access Token",
     re.compile(r'glpat-[A-Za-z0-9_-]{20,}'), Severity.CRITICAL),
    ("SEC-003", "PostgreSQL connection string with credentials",
     re.compile(r'postgres(?:ql)?://[^:@\s]+:[^@\s]+@'), Severity.CRITICAL),
    ("SEC-003", "MySQL connection string with credentials",
     re.compile(r'mysql://[^:@\s]+:[^@\s]+@'), Severity.CRITICAL),
    ("SEC-003", "MongoDB connection string with credentials",
     re.compile(r'mongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@'), Severity.CRITICAL),
    ("SEC-004", "OpenAI API key",
     re.compile(r'sk-(?:proj-)?[A-Za-z0-9_-]{40,}'), Severity.HIGH),
    ("SEC-004", "Anthropic API key",
     re.compile(r'sk-ant-[A-Za-z0-9_-]{32,}'), Severity.HIGH),
    ("SEC-004", "Stripe live secret key",
     re.compile(r'sk_live_[A-Za-z0-9]{24,}'), Severity.HIGH),
    ("SEC-004", "Stripe live publishable key",
     re.compile(r'pk_live_[A-Za-z0-9]{24,}'), Severity.HIGH),
    ("SEC-005", "JWT token (encoded)",
     re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), Severity.HIGH),
]

# Env var names that suggest sensitive content (checked regardless of value pattern)
_SENSITIVE_VAR_NAMES: list[tuple[str, re.Pattern, Severity]] = [
    ("SEC-001", re.compile(r'(?i)^(aws_access_key_id|aws_secret_access_key|aws_session_token)$'), Severity.CRITICAL),
    ("SEC-003", re.compile(r'(?i)(database_url|db_password|postgres_password|mysql_password|db_url|connection_string)'), Severity.CRITICAL),
    ("SEC-003", re.compile(r'(?i)(admin_password|root_password|sudo_password)'), Severity.CRITICAL),
    ("SEC-005", re.compile(r'(?i)(jwt_secret|signing_key|jwt_signing|secret_key|signing_secret)'), Severity.HIGH),
    ("SEC-004", re.compile(r'(?i)^(openai_api_key|anthropic_api_key|stripe_secret_key|stripe_sk)$'), Severity.HIGH),
]

_PLACEHOLDER_RE = re.compile(
    r'^\s*(\$\{[^}]+\}|<[^>]+>|your[-_\s].+|xxx+|placeholder|changeme|todo|example)\s*$',
    re.I,
)


def _mask(val: str) -> str:
    if len(val) <= 8:
        return "***"
    return val[:4] + "..." + val[-4:]


def check_secrets(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()

    for env_key, env_val in server.env.items():
        if not env_val or _PLACEHOLDER_RE.match(env_val):
            continue

        # Match value against known secret patterns
        for check_id, title, pattern, severity in _VALUE_PATTERNS:
            dedup = f"{check_id}:{server.name}:{env_key}:val"
            if dedup in seen:
                continue
            if pattern.search(env_val):
                seen.add(dedup)
                findings.append(Finding(
                    check_id=check_id,
                    title=f"{title} hardcoded in `{env_key}`",
                    detail=(
                        f"Server `{server.name}` has what appears to be a {title.lower()} "
                        f"hardcoded in environment variable `{env_key}` (value: `{_mask(env_val)}`). "
                        "Credentials in MCP config files are readable by anyone with file system access "
                        "and are often synced to cloud backup or version control."
                    ),
                    severity=severity,
                    owasp=OWASPCategory.MCP01,
                    server_name=server.name,
                    remediation=(
                        f"Remove the hardcoded value from `{env_key}`. "
                        "Reference a secrets manager (e.g. 1Password CLI, AWS Secrets Manager, Vault) "
                        "or set the variable in your shell profile and reference it with `$ENV_VAR` syntax "
                        "so the plaintext never appears in the config file."
                    ),
                    engine="custom",
                ))
                break

        # Flag by suspicious var name even if value pattern doesn't match
        dedup_name = f"name:{server.name}:{env_key}"
        if dedup_name not in seen:
            for check_id, pattern_re, severity in _SENSITIVE_VAR_NAMES:
                if pattern_re.search(env_key):
                    seen.add(dedup_name)
                    findings.append(Finding(
                        check_id=check_id,
                        title=f"Sensitive env var `{env_key}` with hardcoded value",
                        detail=(
                            f"Server `{server.name}` sets `{env_key}`, which by name indicates "
                            "it holds a secret credential. Hardcoding secrets in MCP configs risks "
                            "accidental exposure in backups, logs, or version control."
                        ),
                        severity=severity,
                        owasp=OWASPCategory.MCP01,
                        server_name=server.name,
                        remediation=(
                            f"Ensure `{env_key}` is not stored in plaintext in the config. "
                            "Use environment variable substitution or a secrets management tool."
                        ),
                        engine="custom",
                    ))
                    break

    # SEC-006: Unpinned package versions (rug pull risk)
    for arg in server.args:
        if _is_package_arg(arg) and not _is_pinned(arg):
            findings.append(Finding(
                check_id="SEC-006",
                title=f"Unpinned package version: `{arg}`",
                detail=(
                    f"Server `{server.name}` installs `{arg}` without a pinned version. "
                    "Unpinned packages are vulnerable to rug pull attacks where a malicious "
                    "update silently replaces the package after you've reviewed it."
                ),
                severity=Severity.MEDIUM,
                owasp=OWASPCategory.MCP04,
                server_name=server.name,
                remediation=(
                    f"Pin the package to an exact version, e.g. `{arg}@x.y.z`. "
                    "Check the latest stable version on npmjs.com and commit that exact version string."
                ),
                engine="custom",
            ))

    return findings


def _is_package_arg(arg: str) -> bool:
    if arg.startswith("-"):
        return False
    return arg.startswith("@") or ("/" not in arg and not arg.startswith("/"))


def _is_pinned(arg: str) -> bool:
    if arg.startswith("@"):
        # @scope/pkg@version has 2+ '@' chars
        return arg.count("@") >= 2
    return "@" in arg
