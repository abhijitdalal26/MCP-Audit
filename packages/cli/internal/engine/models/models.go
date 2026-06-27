package models

// Severity levels — string values must match Python API output exactly.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// SeverityRank maps severity to sort order (lower = more severe).
var SeverityRank = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

// SeverityScoreWeights maps severity to risk score contribution (0–100 cap).
var SeverityScoreWeights = map[Severity]int{
	SeverityCritical: 25,
	SeverityHigh:     10,
	SeverityMedium:   4,
	SeverityLow:      1,
	SeverityInfo:     0,
}

// OWASPCategory represents one of the OWASP MCP Top 10 categories.
type OWASPCategory string

const (
	MCP01 OWASPCategory = "MCP01" // Token Mismanagement & Secret Exposure
	MCP02 OWASPCategory = "MCP02" // Privilege Escalation via Scope Creep
	MCP03 OWASPCategory = "MCP03" // Tool Poisoning
	MCP04 OWASPCategory = "MCP04" // Supply Chain Attacks
	MCP05 OWASPCategory = "MCP05" // Command Injection & Execution
	MCP06 OWASPCategory = "MCP06" // Prompt Injection via Contextual Payloads
	MCP07 OWASPCategory = "MCP07" // Insufficient Authentication
	MCP08 OWASPCategory = "MCP08" // Lack of Audit and Telemetry
	MCP09 OWASPCategory = "MCP09" // Shadow MCP Servers
	MCP10 OWASPCategory = "MCP10" // Context Injection & Over-Sharing
)

var OWASPNames = map[OWASPCategory]string{
	MCP01: "Token Mismanagement & Secret Exposure",
	MCP02: "Privilege Escalation via Scope Creep",
	MCP03: "Tool Poisoning",
	MCP04: "Supply Chain Attacks",
	MCP05: "Command Injection & Execution",
	MCP06: "Prompt Injection via Contextual Payloads",
	MCP07: "Insufficient Authentication",
	MCP08: "Lack of Audit and Telemetry",
	MCP09: "Shadow MCP Servers",
	MCP10: "Context Injection & Over-Sharing",
}

// Finding is a single security finding produced by a check.
type Finding struct {
	CheckID      string        `json:"check_id"`
	Title        string        `json:"title"`
	Detail       string        `json:"detail"`
	Severity     Severity      `json:"severity"`
	OWASP        OWASPCategory `json:"owasp"`
	ServerName   string        `json:"server_name"`
	Remediation  string        `json:"remediation"`
	Engine       string        `json:"engine"`
	AttackTactic string        `json:"attack_tactic,omitempty"`
	CWEID        string        `json:"cwe_id,omitempty"`
}

// ScanSummary aggregates counts and risk score for a scan.
type ScanSummary struct {
	Total          int      `json:"total"`
	Critical       int      `json:"critical"`
	High           int      `json:"high"`
	Medium         int      `json:"medium"`
	Low            int      `json:"low"`
	Info           int      `json:"info"`
	ServersScanned int      `json:"servers_scanned"`
	OWASPCoverage  []string `json:"owasp_coverage"`
	RiskScore      int      `json:"risk_score"`
	RiskGrade      string   `json:"risk_grade"`
}

// ScanResult is the top-level output of a scan — matches the Python API response shape.
type ScanResult struct {
	ScanID     string      `json:"scan_id"`
	ConfigHash string      `json:"config_hash"`
	Findings   []Finding   `json:"findings"`
	Summary    ScanSummary `json:"summary"`
	ScannedAt  string      `json:"scanned_at"`
}
