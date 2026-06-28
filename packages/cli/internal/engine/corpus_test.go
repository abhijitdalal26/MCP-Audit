package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusTest describes a real-world config fixture and expectations.
type corpusTest struct {
	file          string
	wantCheckIDs  []string // at least one of these should appear
	wantNoCrash   bool     // always true — just documents intent
	wantScore     [2]int   // [min, max] inclusive
	wantFindCount int      // minimum expected findings (0 = no assertion)
}

var corpusFixtures = []corpusTest{
	{
		file:         "real_confluent.json",
		wantNoCrash:  true,
		wantScore:    [2]int{0, 100},
		wantCheckIDs: []string{}, // Confluent is a known-good enterprise config
	},
	{
		file:        "real_terminal_server.jsonc",
		wantNoCrash: true,
		wantScore:   [2]int{0, 100},
		// JSONC with line comments — parser must handle gracefully
		// Terminal server uses uv; expects unpinned version findings
		wantCheckIDs:  []string{"SEC-006", "LF-001", "SH-001", "AT-001", "PE-001"},
		wantFindCount: 1,
	},
	{
		file:        "real_canfieldjuan.json",
		wantNoCrash: true,
		wantScore:   [2]int{0, 100},
		// 12-server multi-server config with env placeholders (should NOT fire secrets)
		wantCheckIDs:  []string{"SC-001", "SC-005", "AT-001"},
		wantFindCount: 1,
	},
	{
		file:        "real_angrysky56.json",
		wantNoCrash: true,
		wantScore:   [2]int{0, 100},
		// Windows root drive access patterns
		wantCheckIDs:  []string{"PE-001", "AT-001"},
		wantFindCount: 1,
	},
	{
		file:        "real_dezocode.json",
		wantNoCrash: true,
		wantScore:   [2]int{0, 100},
		// Custom binary with env discovery flags; expect SH-005 and SEC-006
		wantCheckIDs:  []string{"SH-005", "SEC-006", "SC-001", "SC-002", "SH-001"},
		wantFindCount: 1,
	},
	{
		file:        "synthetic_adversarial.json",
		wantNoCrash: true,
		wantScore:   [2]int{1, 100}, // adversarial config must produce non-zero score
		wantFindCount: 3,            // should produce multiple findings
	},
}

func TestCorpus_NoCrashAndValidOutput(t *testing.T) {
	for _, tc := range corpusFixtures {
		tc := tc
		t.Run(tc.file, func(t *testing.T) {
			path := filepath.Join("testdata", tc.file)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("corpus file not found (skip): %s", path)
			}

			result, err := Scan(string(data), ScanOptions{NoNetwork: true})
			if err != nil {
				t.Fatalf("Scan(%s) crashed: %v", tc.file, err)
			}

			// Risk score in [0, 100]
			if result.Summary.RiskScore < tc.wantScore[0] || result.Summary.RiskScore > tc.wantScore[1] {
				t.Errorf("%s: risk score %d outside expected [%d, %d]",
					tc.file, result.Summary.RiskScore, tc.wantScore[0], tc.wantScore[1])
			}

			// Risk grade is one of the valid grades
			validGrades := map[string]bool{"A": true, "B": true, "C": true, "D": true, "F": true}
			if !validGrades[result.Summary.RiskGrade] {
				t.Errorf("%s: invalid risk grade %q", tc.file, result.Summary.RiskGrade)
			}

			// ScanID is non-empty
			if result.ScanID == "" {
				t.Errorf("%s: ScanID should not be empty", tc.file)
			}

			// Findings count matches summary total
			if len(result.Findings) != result.Summary.Total {
				t.Errorf("%s: len(Findings)=%d != Summary.Total=%d",
					tc.file, len(result.Findings), result.Summary.Total)
			}

			// Minimum findings requirement
			if tc.wantFindCount > 0 && len(result.Findings) < tc.wantFindCount {
				t.Errorf("%s: expected ≥%d findings, got %d",
					tc.file, tc.wantFindCount, len(result.Findings))
			}

			// At least one expected check ID should appear (when specified)
			if len(tc.wantCheckIDs) > 0 {
				found := false
				for _, f := range result.Findings {
					for _, wantID := range tc.wantCheckIDs {
						if f.CheckID == wantID {
							found = true
						}
					}
				}
				if !found {
					ids := make([]string, len(result.Findings))
					for i, f := range result.Findings {
						ids[i] = f.CheckID
					}
					t.Errorf("%s: expected one of %v, got: %s",
						tc.file, tc.wantCheckIDs, strings.Join(ids, ", "))
				}
			}

			// All findings have required fields
			for _, f := range result.Findings {
				if f.CheckID == "" {
					t.Errorf("%s: finding has empty CheckID", tc.file)
				}
				if f.Severity == "" {
					t.Errorf("%s: finding %s has empty Severity", tc.file, f.CheckID)
				}
				if f.OWASP == "" {
					t.Errorf("%s: finding %s has empty OWASP", tc.file, f.CheckID)
				}
			}
		})
	}
}

func TestCorpus_ScanIsDeterministic(t *testing.T) {
	path := filepath.Join("testdata", "synthetic_adversarial.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("corpus fixture not found")
	}
	configJSON := string(data)

	r1, _ := Scan(configJSON, ScanOptions{NoNetwork: true})
	r2, _ := Scan(configJSON, ScanOptions{NoNetwork: true})

	// Total and grade must be deterministic
	if r1.Summary.Total != r2.Summary.Total {
		t.Errorf("scan not deterministic: run1 total=%d run2 total=%d", r1.Summary.Total, r2.Summary.Total)
	}
	if r1.Summary.RiskGrade != r2.Summary.RiskGrade {
		t.Errorf("scan not deterministic: run1 grade=%s run2 grade=%s", r1.Summary.RiskGrade, r2.Summary.RiskGrade)
	}
	// ConfigHash must be identical across runs
	if r1.ConfigHash != r2.ConfigHash {
		t.Errorf("ConfigHash differs between runs: %s vs %s", r1.ConfigHash, r2.ConfigHash)
	}
}

func TestCorpus_RiskScoreBounded(t *testing.T) {
	// All corpus configs must produce a score in [0, 100]
	dir := "testdata"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skip("testdata directory not found")
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".jsonc") {
			data, _ := os.ReadFile(filepath.Join(dir, name))
			result, err := Scan(string(data), ScanOptions{NoNetwork: true})
			if err != nil {
				t.Errorf("%s: scan error: %v", name, err)
				continue
			}
			if result.Summary.RiskScore < 0 || result.Summary.RiskScore > 100 {
				t.Errorf("%s: risk score %d out of [0, 100]", name, result.Summary.RiskScore)
			}
		}
	}
}

func TestCorpus_PlaceholderEnvNotFlaggedAsSecret(t *testing.T) {
	// Real config with env placeholders like ${ANTHROPIC_API_KEY} should not fire SEC-*
	config := `{"mcpServers":{"srv":{"command":"npx","args":["-y","pkg@1.0"],
		"env":{"ANTHROPIC_API_KEY":"${ANTHROPIC_API_KEY}","OPENAI_KEY":"$OPENAI_KEY"}}}}`
	result, err := Scan(config, ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range result.Findings {
		if strings.HasPrefix(f.CheckID, "SEC-") &&
			f.CheckID != "SEC-006" { // SEC-006 is version pinning, not a secret
			t.Errorf("placeholder env should not fire %s (title: %s)", f.CheckID, f.Title)
		}
	}
}

func TestCorpus_SARIFFromRealConfig(t *testing.T) {
	path := filepath.Join("testdata", "synthetic_adversarial.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("corpus fixture not found")
	}
	sarifBytes, err := ScanToSARIF(string(data), ScanOptions{NoNetwork: true})
	if err != nil {
		t.Fatal(err)
	}
	var sarif map[string]any
	if err := json.Unmarshal(sarifBytes, &sarif); err != nil {
		t.Fatalf("ScanToSARIF produced invalid JSON: %v", err)
	}
	if sarif["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", sarif["version"])
	}
}
