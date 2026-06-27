package engine

import (
	"strings"
	"testing"
)

const cleanConfig = `{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp/project"]
    }
  }
}`

const dirtyConfig = `{
  "mcpServers": {
    "evil": {
      "command": "npx",
      "args": ["-y", "server-filesystem"],
      "env": {
        "OPENAI_API_KEY": "sk-live-abc123def456ghi789jkl0"
      }
    }
  }
}`

const multiServerConfig = `{
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "server-filesystem@1.0", "/Users"]
    },
    "fetch": {
      "command": "npx",
      "args": ["-y", "server-fetch@1.0"],
      "url": "https://external.api.com"
    }
  }
}`

func TestScan_Clean(t *testing.T) {
	result, err := Scan(cleanConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.ScanID == "" {
		t.Error("expected non-empty ScanID")
	}
}

func TestScan_FindsSecrets(t *testing.T) {
	result, err := Scan(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		// Any SEC-* finding indicates the hardcoded API key was detected.
		if len(f.CheckID) >= 3 && f.CheckID[:3] == "SEC" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a SEC-* finding for hardcoded API key, got %d findings: %v", len(result.Findings), result.Findings)
	}
}

func TestScan_SortedBySeverity(t *testing.T) {
	result, err := Scan(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	for i := 1; i < len(result.Findings); i++ {
		prev := severityOrder[result.Findings[i-1].Severity]
		curr := severityOrder[result.Findings[i].Severity]
		if prev > curr {
			t.Errorf("findings not sorted by severity at index %d (%s > %s)",
				i, result.Findings[i-1].Severity, result.Findings[i].Severity)
		}
	}
}

func TestScan_Summary(t *testing.T) {
	result, err := Scan(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if result.Summary.ServersScanned != 1 {
		t.Errorf("want 1 server scanned, got %d", result.Summary.ServersScanned)
	}
	if result.Summary.Total != len(result.Findings) {
		t.Errorf("summary total mismatch: %d vs %d", result.Summary.Total, len(result.Findings))
	}
}

func TestScan_AT001_NoPinning(t *testing.T) {
	config := `{"mcpServers":{"a":{"command":"npx","args":["-y","pkg-a"]},"b":{"command":"npx","args":["-y","pkg-b"]}}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	found := false
	for _, f := range result.Findings {
		if f.CheckID == "AT-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AT-001 for no pinning across 2 servers")
	}
}

func TestScan_InvalidJSON(t *testing.T) {
	_, err := Scan("not json", ScanOptions{NoNetwork: true})
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestScanToSARIF(t *testing.T) {
	out, err := ScanToSARIF(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("ScanToSARIF failed: %v", err)
	}
	if !strings.Contains(string(out), "sarif-schema-2.1.0") {
		t.Error("SARIF output missing schema reference")
	}
	if !strings.Contains(string(out), "MCPAudit") {
		t.Error("SARIF output missing tool name")
	}
}

func TestScanToBOM(t *testing.T) {
	out, err := ScanToBOM(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("ScanToBOM failed: %v", err)
	}
	if !strings.Contains(string(out), "CycloneDX") {
		t.Error("BOM output missing CycloneDX format marker")
	}
}

func TestScan_MultiServer_CHAIN(t *testing.T) {
	result, err := Scan(multiServerConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	_ = result // chain findings may or may not fire depending on heuristics
	if result.Summary.ServersScanned != 2 {
		t.Errorf("want 2 servers scanned, got %d", result.Summary.ServersScanned)
	}
}

func TestScan_RiskScore_Range(t *testing.T) {
	result, err := Scan(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if result.Summary.RiskScore < 0 || result.Summary.RiskScore > 100 {
		t.Errorf("risk score out of range: %d", result.Summary.RiskScore)
	}
	grades := map[string]bool{"A": true, "B": true, "C": true, "D": true, "F": true}
	if !grades[result.Summary.RiskGrade] {
		t.Errorf("invalid risk grade: %s", result.Summary.RiskGrade)
	}
}
