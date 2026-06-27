package engine

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
)

// ── AT-005: Excessive server count ───────────────────────────────────────────

func TestScan_AT005_ExcessiveServers(t *testing.T) {
	// 10 servers should trigger AT-005
	servers := make(map[string]any)
	for i := 0; i < 10; i++ {
		name := string(rune('a'+i)) + "-server"
		servers[name] = map[string]any{
			"command": "npx",
			"args":    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp/" + name},
		}
	}
	cfg := map[string]any{"mcpServers": servers}
	data, _ := json.Marshal(cfg)
	result, err := Scan(string(data), ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range result.Findings {
		if f.CheckID == "AT-005" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AT-005 for 10 servers, got: %v findings", len(result.Findings))
	}
}

func TestScan_AT005_NineServers_NoFire(t *testing.T) {
	servers := make(map[string]any)
	for i := 0; i < 9; i++ {
		name := string(rune('a'+i)) + "-server"
		servers[name] = map[string]any{
			"command": "npx",
			"args":    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp/" + name},
		}
	}
	cfg := map[string]any{"mcpServers": servers}
	data, _ := json.Marshal(cfg)
	result, err := Scan(string(data), ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.CheckID == "AT-005" {
			t.Error("AT-005 should not fire for 9 servers")
		}
	}
}

// ── AT-006: Docker image without pinned tag ───────────────────────────────────

func TestScan_AT006_DockerLatestTag(t *testing.T) {
	config := `{"mcpServers":{"docker-srv":{"command":"docker","args":["run","myimage:latest"]}}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if !findingExists(result, "AT-006") {
		t.Error("expected AT-006 for docker image with :latest tag")
	}
}

func TestScan_AT006_DockerNoTag(t *testing.T) {
	config := `{"mcpServers":{"docker-srv":{"command":"docker","args":["run","myimage"]}}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if !findingExists(result, "AT-006") {
		t.Error("expected AT-006 for docker image without tag")
	}
}

func TestScan_AT006_DockerPinnedVersion_NoFire(t *testing.T) {
	config := `{"mcpServers":{"docker-srv":{"command":"docker","args":["run","myimage:1.2.3"]}}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.CheckID == "AT-006" {
			t.Errorf("AT-006 should not fire for pinned docker image :1.2.3")
		}
	}
}

func TestScan_AT006_DockerSHADigest_NoFire(t *testing.T) {
	config := `{"mcpServers":{"docker-srv":{"command":"docker","args":["run","myimage@sha256:abc123def456"]}}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.CheckID == "AT-006" {
			t.Errorf("AT-006 should not fire for SHA-digest pinned docker image")
		}
	}
}

// ── Disabled server handling ──────────────────────────────────────────────────

func TestScan_DisabledServer_Skipped(t *testing.T) {
	config := `{"mcpServers":{
		"evil":{"command":"npx","args":["-y","mcp-server-free"],"disabled":true},
		"clean":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.2.3","/tmp"]}
	}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if f.ServerName == "evil" {
			t.Errorf("disabled server should not be scanned, got finding: %s", f.CheckID)
		}
	}
	if result.Summary.ServersScanned != 1 {
		t.Errorf("want 1 server scanned (disabled excluded), got %d", result.Summary.ServersScanned)
	}
}

// ── JSONC config support ──────────────────────────────────────────────────────

func TestScan_JSONCConfig(t *testing.T) {
	// JSONC with comments — must parse correctly
	config := `{
		// Claude Desktop config
		"mcpServers": {
			"fs": {
				/* filesystem server */
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp"]
			}
		}
	}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("JSONC config should parse successfully: %v", err)
	}
	if result.Summary.ServersScanned != 1 {
		t.Errorf("want 1 server from JSONC config, got %d", result.Summary.ServersScanned)
	}
}

// ── SARIF structure ────────────────────────────────────────────────────────────

func TestScanToSARIF_ValidStructure(t *testing.T) {
	out, err := ScanToSARIF(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("ScanToSARIF failed: %v", err)
	}
	var sarif map[string]any
	if err := json.Unmarshal(out, &sarif); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	// Must have version, runs
	if sarif["version"] != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %v", sarif["version"])
	}
	runs, ok := sarif["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Error("expected exactly 1 run in SARIF output")
	}
}

func TestScanToSARIF_EmptyConfig_NoResults(t *testing.T) {
	config := `{"mcpServers":{}}`
	out, err := ScanToSARIF(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("ScanToSARIF failed: %v", err)
	}
	if !strings.Contains(string(out), "MCPAudit") {
		t.Error("SARIF output should contain tool name even when empty")
	}
}

// ── CycloneDX structure ────────────────────────────────────────────────────────

func TestScanToBOM_ValidStructure(t *testing.T) {
	out, err := ScanToBOM(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatalf("ScanToBOM failed: %v", err)
	}
	var bom map[string]any
	if err := json.Unmarshal(out, &bom); err != nil {
		t.Fatalf("BOM output is not valid JSON: %v", err)
	}
	if bom["bomFormat"] != "CycloneDX" {
		t.Errorf("expected bomFormat CycloneDX, got %v", bom["bomFormat"])
	}
	if bom["specVersion"] != "1.6" {
		t.Errorf("expected specVersion 1.6, got %v", bom["specVersion"])
	}
	if _, ok := bom["vulnerabilities"]; !ok {
		t.Error("BOM should have vulnerabilities section")
	}
}

// ── Risk score ────────────────────────────────────────────────────────────────

func TestScan_CleanConfig_GradeA(t *testing.T) {
	// cleanConfig uses npx -y which triggers LF-001 (medium = 4 pts). Grade A = score < 20.
	result, err := Scan(cleanConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Summary.RiskGrade != "A" {
		t.Errorf("clean config should have grade A, got %s (score=%d)", result.Summary.RiskGrade, result.Summary.RiskScore)
	}
}

func TestScan_OWASPCoverage_Populated(t *testing.T) {
	result, err := Scan(dirtyConfig, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Summary.OWASPCoverage) == 0 {
		t.Error("dirty config should have OWASP categories in coverage")
	}
	for _, cat := range result.Summary.OWASPCoverage {
		if !strings.HasPrefix(cat, "MCP") {
			t.Errorf("unexpected OWASP category format: %q", cat)
		}
	}
}

// ── ScanID and ConfigHash ─────────────────────────────────────────────────────

func TestScan_ScanID_Unique(t *testing.T) {
	r1, _ := Scan(cleanConfig, ScanOptions{NoNetwork: true})
	r2, _ := Scan(cleanConfig, ScanOptions{NoNetwork: true})
	if r1.ScanID == r2.ScanID {
		t.Error("each scan should produce a unique ScanID (UUIDs must differ)")
	}
}

func TestScan_ConfigHash_Deterministic(t *testing.T) {
	r1, _ := Scan(cleanConfig, ScanOptions{NoNetwork: true})
	r2, _ := Scan(cleanConfig, ScanOptions{NoNetwork: true})
	if r1.ConfigHash != r2.ConfigHash {
		t.Error("same config should always produce the same ConfigHash")
	}
}

func TestScan_DifferentConfig_DifferentHash(t *testing.T) {
	r1, _ := Scan(cleanConfig, ScanOptions{NoNetwork: true})
	r2, _ := Scan(dirtyConfig, ScanOptions{NoNetwork: true})
	if r1.ConfigHash == r2.ConfigHash {
		t.Error("different configs should produce different ConfigHash values")
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func findingExists(result *models.ScanResult, checkID string) bool {
	for _, f := range result.Findings {
		if f.CheckID == checkID {
			return true
		}
	}
	return false
}
