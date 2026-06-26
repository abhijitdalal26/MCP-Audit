package cmd

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/client"
)

func TestCheckFailOn_NoFindings(t *testing.T) {
	result := &client.ScanResult{}
	if err := checkFailOn(result, "critical"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestCheckFailOn_None(t *testing.T) {
	result := &client.ScanResult{
		Findings: []client.Finding{{Severity: "critical"}},
	}
	if err := checkFailOn(result, "none"); err != nil {
		t.Errorf("fail-on none should never return error, got %v", err)
	}
}

func TestCheckFailOn_BelowThreshold(t *testing.T) {
	result := &client.ScanResult{
		Findings: []client.Finding{{Severity: "low"}},
	}
	// fail-on critical — low should NOT trigger exit 1
	if err := checkFailOn(result, "critical"); err != nil {
		t.Errorf("low finding should not trigger critical threshold, got %v", err)
	}
}

func TestCheckFailOn_AtThreshold(t *testing.T) {
	result := &client.ScanResult{
		Findings: []client.Finding{{Severity: "high"}},
	}
	err := checkFailOn(result, "high")
	if err == nil {
		t.Fatal("expected ExitCodeError, got nil")
	}
	ee, ok := err.(*ExitCodeError)
	if !ok {
		t.Fatalf("expected *ExitCodeError, got %T: %v", err, err)
	}
	if ee.Code != 1 {
		t.Errorf("exit code = %d, want 1", ee.Code)
	}
}

func TestCheckFailOn_AboveThreshold(t *testing.T) {
	result := &client.ScanResult{
		Findings: []client.Finding{{Severity: "critical"}},
	}
	// fail-on medium — critical is above threshold (worse), should trigger
	err := checkFailOn(result, "medium")
	if _, ok := err.(*ExitCodeError); !ok {
		t.Fatalf("expected *ExitCodeError, got %T: %v", err, err)
	}
}

func TestCheckFailOn_InvalidSeverity(t *testing.T) {
	result := &client.ScanResult{}
	err := checkFailOn(result, "unknown")
	if err == nil {
		t.Fatal("expected error for unknown severity")
	}
	if _, ok := err.(*ExitCodeError); ok {
		t.Fatal("unexpected ExitCodeError for unknown severity")
	}
}
