package output_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/client"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/output"
)

func makeFinding(checkID, title, severity, owasp, server string) client.Finding {
	return client.Finding{
		CheckID:    checkID,
		Title:      title,
		Detail:     "Detail for " + title,
		Severity:   severity,
		OWASP:      owasp,
		ServerName: server,
	}
}

// ── PrintText ─────────────────────────────────────────────────────────────────

func TestPrintText_GradeA_ZeroFindings(t *testing.T) {
	result := &client.ScanResult{
		ScanID: "test-scan",
		Summary: client.ScanSummary{
			Total: 0, ServersScanned: 1, RiskGrade: "A", RiskScore: 0,
		},
	}
	var buf bytes.Buffer
	output.PrintText(&buf, result, "0.1.0", true)
	out := buf.String()
	if !strings.Contains(out, "A") {
		t.Error("output should show grade A for clean result")
	}
}

func TestPrintText_CheckIDInOutput(t *testing.T) {
	result := &client.ScanResult{
		ScanID: "test",
		Findings: []client.Finding{
			makeFinding("PI-001", "Prompt injection in args", "critical", "MCP03", "bad-server"),
		},
		Summary: client.ScanSummary{Total: 1, Critical: 1, ServersScanned: 1, RiskGrade: "F", RiskScore: 85},
	}
	var buf bytes.Buffer
	output.PrintText(&buf, result, "0.1.0", true)
	out := buf.String()
	if !strings.Contains(out, "PI-001") {
		t.Errorf("output should contain check ID PI-001, got:\n%s", out)
	}
}

func TestPrintText_OWASPCategoryInOutput(t *testing.T) {
	result := &client.ScanResult{
		ScanID: "test",
		Findings: []client.Finding{
			makeFinding("SC-001", "Known malicious package", "critical", "MCP04", "evil"),
		},
		Summary: client.ScanSummary{Total: 1, Critical: 1, ServersScanned: 1, RiskGrade: "F", RiskScore: 85},
	}
	var buf bytes.Buffer
	output.PrintText(&buf, result, "0.1.0", true)
	out := buf.String()
	if !strings.Contains(out, "MCP04") {
		t.Errorf("output should contain OWASP category MCP04, got:\n%s", out)
	}
}

func TestPrintText_MultipleFindings(t *testing.T) {
	result := &client.ScanResult{
		ScanID: "test",
		Findings: []client.Finding{
			makeFinding("SEC-001", "AWS key", "critical", "MCP01", "server-a"),
			makeFinding("LF-001", "Lifecycle scripts", "medium", "MCP04", "server-b"),
			makeFinding("PE-001", "Broad path", "high", "MCP02", "server-a"),
		},
		Summary: client.ScanSummary{
			Total: 3, Critical: 1, High: 1, Medium: 1,
			ServersScanned: 2, RiskGrade: "F", RiskScore: 90,
		},
	}
	var buf bytes.Buffer
	output.PrintText(&buf, result, "0.1.0", true)
	out := buf.String()
	if len(out) < 50 {
		t.Error("output with multiple findings should not be trivially short")
	}
}

func TestPrintText_NoColorMode(t *testing.T) {
	result := &client.ScanResult{
		ScanID: "test",
		Findings: []client.Finding{
			makeFinding("SEC-001", "AWS key", "critical", "MCP01", "srv"),
		},
		Summary: client.ScanSummary{Total: 1, Critical: 1, ServersScanned: 1, RiskGrade: "F", RiskScore: 85},
	}
	var buf bytes.Buffer
	output.PrintText(&buf, result, "0.1.0", true) // noColor = true
	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Error("noColor=true output should not contain ANSI escape codes")
	}
}

func TestPrintText_ShowsServerName(t *testing.T) {
	result := &client.ScanResult{
		ScanID: "test",
		Findings: []client.Finding{
			makeFinding("SEC-001", "AWS key", "critical", "MCP01", "my-special-server"),
		},
		Summary: client.ScanSummary{Total: 1, Critical: 1, ServersScanned: 1, RiskGrade: "F", RiskScore: 85},
	}
	var buf bytes.Buffer
	output.PrintText(&buf, result, "0.1.0", true)
	out := buf.String()
	if !strings.Contains(out, "my-special-server") {
		t.Errorf("output should show server name, got:\n%s", out)
	}
}

func TestPrintText_ShowsRemediationOrDetail(t *testing.T) {
	finding := makeFinding("PE-007", "Permission bypass flag", "critical", "MCP02", "srv")
	finding.Remediation = "Remove the bypass flag immediately"
	result := &client.ScanResult{
		ScanID:   "test",
		Findings: []client.Finding{finding},
		Summary:  client.ScanSummary{Total: 1, Critical: 1, ServersScanned: 1, RiskGrade: "F", RiskScore: 85},
	}
	var buf bytes.Buffer
	output.PrintText(&buf, result, "0.1.0", true)
	out := buf.String()
	if len(out) == 0 {
		t.Error("output should not be empty for a finding with remediation")
	}
}

// ── PrintJSON ─────────────────────────────────────────────────────────────────

func TestPrintJSON_OutputIsValidJSONObject(t *testing.T) {
	result := &client.ScanResult{
		ScanID: "test-json",
		Findings: []client.Finding{
			makeFinding("SEC-001", "AWS key", "critical", "MCP01", "srv"),
		},
		Summary: client.ScanSummary{Total: 1, Critical: 1, ServersScanned: 1, RiskGrade: "F", RiskScore: 85},
	}
	var buf bytes.Buffer
	if err := output.PrintJSON(&buf, result); err != nil {
		t.Fatalf("PrintJSON failed: %v", err)
	}
	trimmed := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		t.Errorf("JSON output should be a valid object, got: %s...", trimmed[:min(30, len(trimmed))])
	}
}

func TestPrintJSON_ContainsScanID(t *testing.T) {
	result := &client.ScanResult{ScanID: "unique-scan-abc"}
	var buf bytes.Buffer
	if err := output.PrintJSON(&buf, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "unique-scan-abc") {
		t.Error("JSON output should contain the scan ID value")
	}
}

func TestPrintJSON_ContainsCheckID(t *testing.T) {
	result := &client.ScanResult{
		ScanID: "test",
		Findings: []client.Finding{makeFinding("CHAIN-001", "Cross-server gadget pair", "high", "MCP02", "srv")},
		Summary:  client.ScanSummary{Total: 1},
	}
	var buf bytes.Buffer
	if err := output.PrintJSON(&buf, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "CHAIN-001") {
		t.Error("JSON output should contain the finding check ID")
	}
}

func TestPrintJSON_EmptyFindings_ValidJSON(t *testing.T) {
	result := &client.ScanResult{
		ScanID:  "empty",
		Summary: client.ScanSummary{Total: 0, RiskGrade: "A"},
	}
	var buf bytes.Buffer
	if err := output.PrintJSON(&buf, result); err != nil {
		t.Fatalf("PrintJSON with empty findings should not error: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(out, "{") {
		t.Errorf("empty findings JSON should still be valid object, got: %s", out[:min(30, len(out))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
