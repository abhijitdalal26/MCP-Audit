package output_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/client"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/output"
)

func makeCleanResult() *client.ScanResult {
	return &client.ScanResult{
		ScanID: "abc123",
		Summary: client.ScanSummary{
			Total: 0, ServersScanned: 2, RiskGrade: "A", RiskScore: 0,
		},
	}
}

func makeDirtyResult() *client.ScanResult {
	return &client.ScanResult{
		ScanID: "abc123",
		Findings: []client.Finding{
			{
				CheckID:     "SEC-001",
				Title:       "AWS key hardcoded in env",
				Severity:    "critical",
				OWASP:       "MCP01",
				ServerName:  "filesystem",
				Remediation: "Remove the key.",
				CWEID:       "CWE-798",
			},
			{
				CheckID:     "PE-001",
				Title:       "Broad filesystem path",
				Severity:    "high",
				OWASP:       "MCP02",
				ServerName:  "filesystem",
				Remediation: "Restrict to a narrower path.",
			},
		},
		Summary: client.ScanSummary{
			Total: 2, Critical: 1, High: 1,
			ServersScanned: 1, RiskGrade: "F", RiskScore: 85,
		},
	}
}

func TestPrintText_Clean(t *testing.T) {
	var buf bytes.Buffer
	output.PrintText(&buf, makeCleanResult(), "0.1.0", true)
	out := buf.String()

	if !strings.Contains(out, "All 51 checks passed") {
		t.Errorf("expected clean message, got:\n%s", out)
	}
}

func TestPrintText_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	output.PrintText(&buf, makeDirtyResult(), "0.1.0", true)
	out := buf.String()

	checks := []string{"CRITICAL", "HIGH", "AWS key hardcoded", "SEC-001", "MCP01", "CWE-798"}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nGot:\n%s", want, out)
		}
	}
}

func TestPrintJSON(t *testing.T) {
	var buf bytes.Buffer
	err := output.PrintJSON(&buf, makeDirtyResult())
	if err != nil {
		t.Fatalf("PrintJSON: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"scan_id"`) {
		t.Errorf("JSON missing scan_id, got:\n%s", out)
	}
	if !strings.Contains(out, `"SEC-001"`) {
		t.Errorf("JSON missing check_id, got:\n%s", out)
	}
}
