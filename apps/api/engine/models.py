from pydantic import BaseModel
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(str, Enum):
    MCP01 = "MCP01"  # Token Mismanagement & Secret Exposure
    MCP02 = "MCP02"  # Privilege Escalation via Scope Creep
    MCP03 = "MCP03"  # Tool Poisoning
    MCP04 = "MCP04"  # Supply Chain Attacks
    MCP05 = "MCP05"  # Command Injection & Execution
    MCP06 = "MCP06"  # Prompt Injection via Contextual Payloads
    MCP07 = "MCP07"  # Insufficient Authentication
    MCP08 = "MCP08"  # Lack of Audit and Telemetry
    MCP09 = "MCP09"  # Shadow MCP Servers
    MCP10 = "MCP10"  # Context Injection & Over-Sharing


OWASP_NAMES: dict[str, str] = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Supply Chain Attacks",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Prompt Injection via Contextual Payloads",
    "MCP07": "Insufficient Authentication",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

# MITRE ATT&CK tactic tags — used for enterprise reporting
ATTACK_TACTICS = {
    "initial-access": "Initial Access",
    "credential-access": "Credential Access",
    "privilege-escalation": "Privilege Escalation",
    "execution": "Execution",
    "persistence": "Persistence",
    "defense-evasion": "Defense Evasion",
    "collection": "Collection",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


class Finding(BaseModel):
    check_id: str
    title: str
    detail: str
    severity: Severity
    owasp: OWASPCategory
    server_name: str
    remediation: str
    engine: str = "custom"
    # Optional ATT&CK tactic for enterprise report correlation
    attack_tactic: Optional[str] = None


class ScanSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    servers_scanned: int
    owasp_coverage: list[str]


class ScanResult(BaseModel):
    scan_id: str
    config_hash: str
    findings: list[Finding]
    summary: ScanSummary
    scanned_at: str
