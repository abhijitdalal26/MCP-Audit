import re
from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer

# CWE ID per check — applied to all Finding() calls
_CHECK_CWE: dict[str, str] = {
    "SEC-001": "CWE-798",   # Use of Hard-Coded Credentials
    "SEC-002": "CWE-798",   # Use of Hard-Coded Credentials
    "SEC-003": "CWE-798",   # Use of Hard-Coded Credentials (DB connection strings)
    "SEC-004": "CWE-798",   # Use of Hard-Coded Credentials (API keys)
    "SEC-005": "CWE-312",   # Cleartext Storage of Sensitive Information (JWT/SSH keys)
    "SEC-006": "CWE-1104",  # Use of Unmaintained Third Party Components (unpinned)
    "SEC-007": "CWE-918",   # Server-Side Request Forgery (cloud metadata endpoint)
    "SEC-008": "CWE-312",   # Cleartext Storage of Sensitive Information (credentials in URL)
}

# (check_id, human title, compiled regex, severity)
_VALUE_PATTERNS: list[tuple[str, str, re.Pattern, Severity]] = [
    # SEC-001: AWS
    ("SEC-001", "AWS Access Key ID",
     re.compile(r'AKIA[0-9A-Z]{16}'), Severity.CRITICAL),
    # SEC-002: VCS tokens
    ("SEC-002", "GitHub Personal Access Token",
     re.compile(r'ghp_[A-Za-z0-9]{36,}'), Severity.CRITICAL),
    ("SEC-002", "GitHub OAuth Token",
     re.compile(r'gho_[A-Za-z0-9]{36,}'), Severity.CRITICAL),
    ("SEC-002", "GitHub App Token",
     re.compile(r'ghs_[A-Za-z0-9]{36,}'), Severity.CRITICAL),
    ("SEC-002", "GitHub Fine-Grained PAT",
     re.compile(r'github_pat_[A-Za-z0-9_]{82,}'), Severity.CRITICAL),
    ("SEC-002", "GitLab Personal Access Token",
     re.compile(r'glpat-[A-Za-z0-9_-]{20,}'), Severity.CRITICAL),
    # SEC-003: Database connection strings
    ("SEC-003", "PostgreSQL connection string with credentials",
     re.compile(r'postgres(?:ql)?://[^:@\s]+:[^@\s]+@'), Severity.CRITICAL),
    ("SEC-003", "MySQL connection string with credentials",
     re.compile(r'mysql://[^:@\s]+:[^@\s]+@'), Severity.CRITICAL),
    ("SEC-003", "MongoDB connection string with credentials",
     re.compile(r'mongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@'), Severity.CRITICAL),
    ("SEC-003", "Redis connection string with credentials",
     re.compile(r'redis://:[^@\s]+@'), Severity.HIGH),
    ("SEC-003", "HTTP Basic Auth credentials embedded in URL",
     re.compile(r'https?://[^:@\s]{1,64}:[^@\s]{3,}@[a-zA-Z0-9]'), Severity.HIGH),
    # SEC-007: Cloud instance metadata service endpoint
    # If an MCP server fetches this URL, it gets cloud IAM credentials (AWS/GCP/Azure).
    # Presence in env vars suggests either a misconfigured server or intentional credential theft.
    ("SEC-007", "Cloud instance metadata endpoint (IMDS) URL",
     re.compile(r'169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal', re.I), Severity.CRITICAL),
    # SEC-004: API keys
    ("SEC-004", "OpenAI API key",
     re.compile(r'sk-(?:proj-)?[A-Za-z0-9_-]{40,}'), Severity.HIGH),
    ("SEC-004", "Anthropic API key",
     re.compile(r'sk-ant-[A-Za-z0-9_-]{32,}'), Severity.HIGH),
    ("SEC-004", "Stripe live secret key",
     re.compile(r'sk_live_[A-Za-z0-9]{24,}'), Severity.HIGH),
    ("SEC-004", "Stripe live publishable key",
     re.compile(r'pk_live_[A-Za-z0-9]{24,}'), Severity.HIGH),
    ("SEC-004", "Slack bot token",
     re.compile(r'xoxb-[0-9A-Za-z-]{40,}'), Severity.HIGH),
    ("SEC-004", "Slack OAuth token",
     re.compile(r'xoxp-[0-9A-Za-z-]{40,}'), Severity.HIGH),
    ("SEC-004", "Slack app-level token",
     re.compile(r'xapp-[0-9A-Za-z-]{80,}'), Severity.HIGH),
    ("SEC-004", "npm access token",
     re.compile(r'npm_[A-Za-z0-9]{36,}'), Severity.HIGH),
    ("SEC-004", "Hugging Face access token",
     re.compile(r'hf_[A-Za-z0-9]{36,}'), Severity.HIGH),
    ("SEC-004", "Replicate API token",
     re.compile(r'r8_[A-Za-z0-9]{40,}'), Severity.HIGH),
    ("SEC-004", "Firebase / GCP API key",
     re.compile(r'AIza[0-9A-Za-z_-]{35}'), Severity.HIGH),
    ("SEC-004", "Twilio Account SID",
     re.compile(r'AC[a-zA-Z0-9]{32}'), Severity.HIGH),
    ("SEC-004", "SendGrid API key",
     re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'), Severity.HIGH),
    ("SEC-004", "Shopify shared secret / access token",
     re.compile(r'shp(?:ss|at|ca)_[a-fA-F0-9]{32}'), Severity.HIGH),
    # SEC-005: JWT and signing keys
    ("SEC-005", "JWT token (encoded)",
     re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), Severity.HIGH),
    ("SEC-005", "SSH private key",
     re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'), Severity.CRITICAL),
]

# Env var names that suggest sensitive content (checked regardless of value pattern)
_SENSITIVE_VAR_NAMES: list[tuple[str, re.Pattern, Severity]] = [
    ("SEC-001", re.compile(r'(?i)^(aws_access_key_id|aws_secret_access_key|aws_session_token)$'), Severity.CRITICAL),
    ("SEC-003", re.compile(r'(?i)(database_url|db_password|postgres_password|mysql_password|db_url|connection_string)'), Severity.CRITICAL),
    ("SEC-003", re.compile(r'(?i)(admin_password|root_password|sudo_password)'), Severity.CRITICAL),
    ("SEC-005", re.compile(r'(?i)(jwt_secret|signing_key|jwt_signing|secret_key|signing_secret)'), Severity.HIGH),
    ("SEC-004", re.compile(r'(?i)^(openai_api_key|anthropic_api_key|stripe_secret_key|stripe_sk)$'), Severity.HIGH),
    ("SEC-004", re.compile(r'(?i)^(slack_bot_token|slack_token|slack_oauth_token|slack_signing_secret)$'), Severity.HIGH),
    ("SEC-004", re.compile(r'(?i)^(npm_token|npm_auth_token)$'), Severity.HIGH),
    ("SEC-004", re.compile(r'(?i)^(hf_token|hugging_face_hub_token|huggingface_token)$'), Severity.HIGH),
    ("SEC-004", re.compile(r'(?i)^(replicate_api_token|replicate_api_key)$'), Severity.HIGH),
    ("SEC-004", re.compile(r'(?i)^(firebase_api_key|firebase_service_account)$'), Severity.HIGH),
    ("SEC-004", re.compile(r'(?i)^(twilio_auth_token|twilio_account_sid)$'), Severity.HIGH),
    ("SEC-004", re.compile(r'(?i)^(sendgrid_api_key)$'), Severity.HIGH),
    ("SEC-004", re.compile(r'(?i)^(shopify_access_token|shopify_api_secret)$'), Severity.HIGH),
]

_PLACEHOLDER_RE = re.compile(
    r'^\s*(\$\{[^}]+\}|<[^>]+>|your[-_\s].+|xxx+|placeholder|changeme|todo|example|insert[-_]here|replace[-_]me)\s*$',
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
                    cwe_id=_CHECK_CWE.get(check_id),
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
                        cwe_id=_CHECK_CWE.get(check_id),
                    ))
                    break

    # Scan args for embedded secrets (--api-key sk-abc123 pattern)
    # Some servers accept credentials as CLI flags, which is equally dangerous
    for i, arg in enumerate(server.args):
        if not arg or arg.startswith("-") or _PLACEHOLDER_RE.match(arg):
            continue
        for check_id, title, pattern, severity in _VALUE_PATTERNS:
            dedup = f"{check_id}:{server.name}:arg:{i}:val"
            if dedup in seen:
                continue
            if pattern.search(arg):
                seen.add(dedup)
                findings.append(Finding(
                    check_id=check_id,
                    title=f"{title} hardcoded in command args",
                    detail=(
                        f"Server `{server.name}` has what appears to be a {title.lower()} "
                        f"hardcoded directly in the command args (arg #{i+1}: `{_mask(arg)}`). "
                        "Credentials passed as command-line arguments appear in process listings, "
                        "shell history, and are readable by anyone with file system access to the config."
                    ),
                    severity=severity,
                    owasp=OWASPCategory.MCP01,
                    server_name=server.name,
                    remediation=(
                        f"Move the {title.lower()} to an environment variable instead. "
                        "Replace the inline value with an env var reference (e.g., `$API_KEY`) "
                        "so the plaintext never appears in the config or process table."
                    ),
                    engine="custom",
                    cwe_id=_CHECK_CWE.get(check_id, "CWE-214"),
                ))
                break

    # SEC-008: Credentials embedded in the server `url:` field
    # The url: field is used by HTTP/SSE MCP servers. If credentials are embedded
    # in the URL (e.g., https://user:pass@api.example.com/mcp) or added as query params,
    # those creds appear in access logs, proxy logs, browser history, and any system
    # that records the config file. No other check currently covers the url: field.
    if server.url and not _PLACEHOLDER_RE.match(server.url):
        for check_id, title, pattern, severity in _VALUE_PATTERNS:
            dedup = f"SEC-008:{server.name}:url:{check_id}"
            if dedup not in seen and pattern.search(server.url):
                seen.add(dedup)
                findings.append(Finding(
                    check_id="SEC-008",
                    title=f"{title} embedded in server URL",
                    detail=(
                        f"Server `{server.name}` has what appears to be a {title.lower()} "
                        f"embedded directly in its `url` field (`{_mask(server.url)}`). "
                        "Credentials in URLs are recorded by web servers, proxies, and load balancers; "
                        "appear in browser history if the URL is opened; and are visible to anyone "
                        "who reads the MCP config file. MCP configs are frequently synced via "
                        "cloud backup (iCloud, Google Drive) or accidentally committed to git."
                    ),
                    severity=severity,
                    owasp=OWASPCategory.MCP01,
                    server_name=server.name,
                    remediation=(
                        "Move the credential out of the URL and into a dedicated environment variable. "
                        "Most API providers accept tokens via a header (e.g., `Authorization: Bearer $TOKEN`) "
                        "rather than requiring them in the URL. "
                        "Reference the variable with `$ENV_VAR` syntax so the plaintext never appears "
                        "in the config file."
                    ),
                    engine="custom",
                    cwe_id="CWE-312",
                ))
                break  # One SEC-008 per server

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
                cwe_id="CWE-1104",
            ))

    return findings


_DIST_TAG_RE = re.compile(r'^(latest|next|beta|alpha|canary|rc|nightly|stable|dev|edge|experimental)$', re.I)
_SEMVER_START_RE = re.compile(r'^\d+\.')


def _is_package_arg(arg: str) -> bool:
    if arg.startswith("-"):
        return False
    return arg.startswith("@") or ("/" not in arg and not arg.startswith("/") and not arg.startswith("C:\\"))


def _extract_version_tag(arg: str) -> str | None:
    """Return the version/tag string in package@version, or None if no version."""
    if arg.startswith("@"):
        parts = arg.split("@")
        return parts[2] if len(parts) >= 3 and parts[2] else None
    return arg.split("@")[1] if "@" in arg else None


def _is_pinned(arg: str) -> bool:
    """True only if the package is pinned to a specific semver (not a dist-tag like @latest)."""
    version = _extract_version_tag(arg)
    if version is None:
        return False
    if _DIST_TAG_RE.match(version):
        return False  # @latest, @next, @beta etc. are NOT pinned
    return bool(_SEMVER_START_RE.match(version))  # must start with digits (semver)
