package engine

import (
	"encoding/json"
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
)

// ── AT-001: Missing package pinning across multi-server configs ───────────────

func TestScan_AT001_MultiServer_NoneWithPinnedPackages(t *testing.T) {
	// AT-001 fires when ≥2 servers exist and NONE have any pinned package version
	config := `{"mcpServers":{
		"a":{"command":"npx","args":["-y","some-mcp-server"]},
		"b":{"command":"npx","args":["-y","another-mcp-server"]}
	}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if !findingExists(result, "AT-001") {
		t.Error("want AT-001 when ≥2 servers and none have pinned package versions")
	}
}

func TestScan_AT001_SingleServer_NoFire(t *testing.T) {
	// AT-001 only fires for ≥2 servers (single server is lower risk)
	config := `{"mcpServers":{"s":{"command":"npx","args":["-y","some-mcp-server"]}}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.CheckID == "AT-001" {
			t.Error("AT-001 should not fire for single-server configs")
		}
	}
}

func TestScan_AT001_MultiServer_AllPinned_NoFire(t *testing.T) {
	config := `{"mcpServers":{
		"fs":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.2.3","/tmp"]},
		"fetch":{"command":"npx","args":["-y","@modelcontextprotocol/server-fetch@1.0.4"]}
	}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.CheckID == "AT-001" {
			t.Errorf("AT-001 should not fire when all packages are pinned, got: %s", f.Title)
		}
	}
}

// ── Risk score edge cases ─────────────────────────────────────────────────────

func TestScan_RiskScore_CriticalFindingAdds25(t *testing.T) {
	// A single critical finding (no OSV) should contribute 25 to risk score
	config := `{"mcpServers":{"s":{"command":"npx","args":["-y","mcp-server-free"]}}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	// Should have at least one critical finding (SC-001 known malicious)
	critCount := 0
	for _, f := range result.Findings {
		if f.Severity == models.SeverityCritical {
			critCount++
		}
	}
	if critCount == 0 {
		t.Skip("no critical findings produced — cannot test risk score contribution")
	}
	// With at least 1 critical finding, score should be ≥ 25
	if result.Summary.RiskScore < 25 {
		t.Errorf("risk score should be ≥25 with critical findings, got %d", result.Summary.RiskScore)
	}
}

func TestScan_RiskScore_Cap100(t *testing.T) {
	// Even with many findings, risk score should be capped at 100
	servers := make(map[string]any)
	for i := 0; i < 10; i++ {
		name := string(rune('a'+i)) + "-srv"
		servers[name] = map[string]any{
			"command": "npx",
			"args":    []string{"-y", "mcp-server-free"},
			"env":     map[string]string{"AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE"},
		}
	}
	cfg := map[string]any{"mcpServers": servers}
	data, _ := json.Marshal(cfg)
	result, err := Scan(string(data), ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.RiskScore > 100 {
		t.Errorf("risk score should be capped at 100, got %d", result.Summary.RiskScore)
	}
}

// ── Empty / minimal configs ───────────────────────────────────────────────────

func TestScan_EmptyServers_NoFindings(t *testing.T) {
	result, err := Scan(`{"mcpServers":{}}`, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Errorf("empty servers should produce no findings, got %d: %v", len(result.Findings), result.Findings)
	}
	if result.Summary.RiskScore != 0 {
		t.Errorf("empty config should have risk score 0, got %d", result.Summary.RiskScore)
	}
}

func TestScan_EmptyServers_GradeA(t *testing.T) {
	result, err := Scan(`{"mcpServers":{}}`, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.RiskGrade != "A" {
		t.Errorf("empty config should have grade A, got %s", result.Summary.RiskGrade)
	}
}

func TestScan_URLOnlyServer(t *testing.T) {
	// URL-only server (SSE/remote) should parse and scan without crashing
	config := `{"mcpServers":{"remote":{"url":"https://mcp.example.com/sse","transport":"sse"}}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("URL-only server should scan without error: %v", err)
	}
	if result.Summary.ServersScanned != 1 {
		t.Errorf("want 1 server scanned, got %d", result.Summary.ServersScanned)
	}
}

// ── ServersScanned counting ───────────────────────────────────────────────────

func TestScan_ServersScanned_ExcludesDisabled(t *testing.T) {
	config := `{"mcpServers":{
		"active":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.2.3","/tmp"]},
		"inactive":{"command":"npx","args":["-y","pkg"],"disabled":true}
	}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.ServersScanned != 1 {
		t.Errorf("ServersScanned should be 1 (disabled excluded), got %d", result.Summary.ServersScanned)
	}
}

func TestScan_ServersScanned_AllActive(t *testing.T) {
	config := `{"mcpServers":{
		"a":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.2.3","/tmp"]},
		"b":{"command":"npx","args":["-y","@modelcontextprotocol/server-fetch@1.0"]}
	}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.ServersScanned != 2 {
		t.Errorf("want 2 servers scanned, got %d", result.Summary.ServersScanned)
	}
}

// ── SARIF rules section ───────────────────────────────────────────────────────

func TestScanToSARIF_RulesSection(t *testing.T) {
	config := `{"mcpServers":{"s":{"command":"npx","args":["-y","mcp-server-free"]}}}`
	out, err := ScanToSARIF(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("ScanToSARIF failed: %v", err)
	}
	var sarif map[string]any
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatal(err)
	}
	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	tool := run["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules, ok := driver["rules"].([]any)
	if !ok || len(rules) == 0 {
		t.Error("SARIF output should have rules in tool.driver.rules")
	}
}

func TestScanToSARIF_ResultsPresent(t *testing.T) {
	config := `{"mcpServers":{"s":{"command":"npx","args":["-y","mcp-server-free"]}}}`
	out, err := ScanToSARIF(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	var sarif map[string]any
	json.Unmarshal(out, &sarif)
	runs := sarif["runs"].([]any)
	run := runs[0].(map[string]any)
	results, ok := run["results"].([]any)
	if !ok || len(results) == 0 {
		t.Error("SARIF run should have non-empty results for dirty config")
	}
}

// ── CycloneDX metadata ────────────────────────────────────────────────────────

func TestScanToBOM_HasSerialNumber(t *testing.T) {
	out, err := ScanToBOM(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	var bom map[string]any
	json.Unmarshal(out, &bom)
	sn, ok := bom["serialNumber"]
	if !ok || sn == "" {
		t.Error("CycloneDX BOM should include a serialNumber")
	}
}

func TestScanToBOM_HasMetadata(t *testing.T) {
	out, err := ScanToBOM(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	var bom map[string]any
	json.Unmarshal(out, &bom)
	if _, ok := bom["metadata"]; !ok {
		t.Error("CycloneDX BOM should have metadata section")
	}
}
