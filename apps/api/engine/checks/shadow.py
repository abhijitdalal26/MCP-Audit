from ..models import Finding, Severity, OWASPCategory
from ..parser import MCPServer


def check_shadow(server: MCPServer) -> list[Finding]:
    findings: list[Finding] = []

    # SH-002: HTTP server without TLS
    if server.url:
        if server.url.startswith("http://") and "localhost" not in server.url and "127.0.0.1" not in server.url:
            findings.append(Finding(
                check_id="SH-002",
                title=f"MCP server using unencrypted HTTP: `{server.url}`",
                detail=(
                    f"Server `{server.name}` connects to `{server.url}` over plain HTTP. "
                    "Unencrypted connections expose all MCP tool calls, responses, and any "
                    "credentials passed to network interception (man-in-the-middle attacks)."
                ),
                severity=Severity.HIGH,
                owasp=OWASPCategory.MCP07,
                server_name=server.name,
                remediation=(
                    f"Replace `{server.url}` with an HTTPS equivalent. "
                    "If the server operator does not support HTTPS, do not use it in production."
                ),
                engine="custom",
            ))

    # SH-003: Localhost URL paired with remotely-fetched npm package
    if server.url and ("localhost" in server.url or "127.0.0.1" in server.url):
        package = _get_npm_package(server)
        if package and not _is_local_path(server.command or ""):
            findings.append(Finding(
                check_id="SH-003",
                title=f"Localhost server backed by remote package `{package}`",
                detail=(
                    f"Server `{server.name}` exposes a localhost URL (`{server.url}`) "
                    f"but fetches `{package}` from npm on every run. "
                    "A malicious npm update could silently change what code runs on your local machine."
                ),
                severity=Severity.LOW,
                owasp=OWASPCategory.MCP09,
                server_name=server.name,
                remediation=(
                    f"Pin `{package}` to an exact version and verify its integrity hash, "
                    "or install it locally and reference the binary directly so it is not re-fetched each run."
                ),
                engine="custom",
            ))

    return findings


def _get_npm_package(server: MCPServer) -> str | None:
    if server.command in ("npx", "npm"):
        for arg in server.args:
            if not arg.startswith("-"):
                return arg
    return None


def _is_local_path(command: str) -> bool:
    return "/" in command or "\\" in command
