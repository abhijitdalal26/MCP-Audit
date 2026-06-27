package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/client"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/output"
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

// ── Integration tests: local engine via runLocalScan ─────────────────────────

func TestRunLocalScan_DirtyConfig_ProducesFindings(t *testing.T) {
	dirtyJSON := `{"mcpServers":{"vuln":{"command":"npx","args":["-y","mcp-server-free"],"env":{"AWS_ACCESS_KEY_ID":"AKIAIOSFODNN7EXAMPLE"}}}}`
	var buf bytes.Buffer
	flagFormat = "json"
	flagNoColor = true
	flagNoNetwork = true
	if err := runLocalScan(&buf, dirtyJSON, "test"); err != nil && !isExitCodeError(err) {
		t.Fatalf("runLocalScan failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "findings") {
		t.Errorf("expected findings in JSON output, got:\n%s", out)
	}
}

func TestRunLocalScan_CleanConfig_NoFindings(t *testing.T) {
	cleanJSON := `{"mcpServers":{}}`
	var buf bytes.Buffer
	flagFormat = "json"
	flagNoColor = true
	flagNoNetwork = true
	if err := runLocalScan(&buf, cleanJSON, "test"); err != nil {
		t.Fatalf("runLocalScan failed on clean config: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"total":0`) && !strings.Contains(out, `"total": 0`) {
		t.Errorf("expected total:0 for clean config, got:\n%s", out)
	}
}

func TestRunLocalScan_SARIFFormat(t *testing.T) {
	dirtyJSON := `{"mcpServers":{"vuln":{"command":"npx","args":["-y","mcp-server-free"]}}}`
	var buf bytes.Buffer
	flagFormat = "sarif"
	flagNoColor = true
	flagNoNetwork = true
	if err := runLocalScan(&buf, dirtyJSON, "test"); err != nil {
		t.Fatalf("SARIF scan failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "2.1.0") {
		t.Errorf("SARIF output should contain version 2.1.0, got:\n%s", out[:min(200, len(out))])
	}
}

func TestRunLocalScan_BOMFormat(t *testing.T) {
	dirtyJSON := `{"mcpServers":{"vuln":{"command":"npx","args":["-y","mcp-server-free"]}}}`
	var buf bytes.Buffer
	flagFormat = "bom"
	flagNoColor = true
	flagNoNetwork = true
	if err := runLocalScan(&buf, dirtyJSON, "test"); err != nil {
		t.Fatalf("BOM scan failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "CycloneDX") && !strings.Contains(out, "cyclonedx") && !strings.Contains(out, "bomFormat") {
		t.Errorf("BOM output should contain CycloneDX identifier, got:\n%s", out[:min(200, len(out))])
	}
}

// TestEngineToClientResult_RoundTrip ensures the JSON round-trip conversion is lossless.
func TestEngineToClientResult_RoundTrip(t *testing.T) {
	result, err := engine.Scan(`{"mcpServers":{"s":{"command":"npx","args":["-y","mcp-server-free"]}}}`, engine.ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	cr := engineToClientResult(result)
	if len(cr.Findings) != len(result.Findings) {
		t.Errorf("round-trip lost findings: engine=%d client=%d", len(result.Findings), len(cr.Findings))
	}
}

// TestPrintText_IntegrationWithEngine exercises the full local pipeline.
func TestPrintText_IntegrationWithEngine(t *testing.T) {
	result, err := engine.Scan(`{"mcpServers":{"s":{"command":"npx","args":["-y","mcp-server-free"]}}}`, engine.ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	cr := engineToClientResult(result)
	var buf bytes.Buffer
	output.PrintText(&buf, cr, "0.1.0", true)
	out := buf.String()
	if len(out) < 20 {
		t.Error("PrintText output should be non-trivial for a dirty config")
	}
}

func isExitCodeError(err error) bool {
	_, ok := err.(*ExitCodeError)
	return ok
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
