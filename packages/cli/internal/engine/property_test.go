package engine

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// ── Property invariants (mirrors Python test_property.py) ────────────────────
//
// These tests generate structurally-valid but randomly-valued MCP configs and
// assert invariants that must hold for ALL inputs. The engine must never crash,
// risk scores must always be bounded, and output must be internally consistent.

// randomConfig builds a syntactically valid MCP config JSON string.
func randomConfig(rng *rand.Rand, nServers int) string {
	commands := []string{"npx", "node", "python3", "uvx", "uv", "docker", ""}
	knownArgs := []string{
		"-y", "--ignore-scripts",
		"@modelcontextprotocol/server-filesystem",
		"@modelcontextprotocol/server-github",
		"/Users", "/tmp", "F:/",
		"run", "--directory", "--shell", "/bin/bash",
		"mcp-server-free", "@randomscope/some-mcp-server",
		"pkg@1.2.3", "pkg",
	}
	knownEnvKeys := []string{
		"API_KEY", "TOKEN", "DATABASE_URL", "SECRET", "NODE_ENV",
		"LOG_LEVEL", "PORT", "ENDPOINT", "MCP_AUTO_DISCOVERY",
	}
	knownEnvVals := []string{
		"true", "false", "debug", "production",
		"${API_KEY}", "$TOKEN", "placeholder",
		"http://localhost:3000", "1234",
	}
	knownURLs := []string{
		"", "http://localhost:3000/mcp", "https://api.example.com/mcp",
		"http://0.0.0.0:8000/mcp", "ws://localhost:8080",
	}

	servers := make(map[string]any)
	for i := 0; i < nServers; i++ {
		name := fmt.Sprintf("server-%d", i)
		cmd := commands[rng.Intn(len(commands))]

		nArgs := rng.Intn(5)
		args := make([]string, nArgs)
		for j := range args {
			args[j] = knownArgs[rng.Intn(len(knownArgs))]
		}

		nEnv := rng.Intn(4)
		env := make(map[string]string, nEnv)
		for j := 0; j < nEnv; j++ {
			k := knownEnvKeys[rng.Intn(len(knownEnvKeys))]
			v := knownEnvVals[rng.Intn(len(knownEnvVals))]
			env[k] = v
		}

		url := knownURLs[rng.Intn(len(knownURLs))]

		srv := map[string]any{
			"command": cmd,
			"args":    args,
			"env":     env,
		}
		if url != "" {
			srv["url"] = url
		}
		servers[name] = srv
	}

	data, _ := json.Marshal(map[string]any{"mcpServers": servers})
	return string(data)
}

func TestProperty_ScanNeverCrashes(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 200; i++ {
		nServers := 1 + rng.Intn(6)
		config := randomConfig(rng, nServers)
		result, err := Scan(config, ScanOptions{NoNetwork: true})
		if err != nil {
			t.Errorf("iteration %d: Scan crashed: %v\nconfig: %s", i, err, config[:min(200, len(config))])
		}
		if result == nil {
			t.Errorf("iteration %d: Scan returned nil result", i)
		}
	}
}

func TestProperty_RiskScoreAlwaysBounded(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	for i := 0; i < 200; i++ {
		nServers := 1 + rng.Intn(6)
		config := randomConfig(rng, nServers)
		result, err := Scan(config, ScanOptions{NoNetwork: true})
		if err != nil {
			continue // crash invariant tested separately
		}
		if result.Summary.RiskScore < 0 || result.Summary.RiskScore > 100 {
			t.Errorf("iteration %d: risk_score=%d out of [0,100]\nconfig: %s",
				i, result.Summary.RiskScore, config[:min(200, len(config))])
		}
	}
}

func TestProperty_RiskGradeAlwaysValid(t *testing.T) {
	validGrades := map[string]bool{"A": true, "B": true, "C": true, "D": true, "F": true}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 200; i++ {
		config := randomConfig(rng, 1+rng.Intn(6))
		result, err := Scan(config, ScanOptions{NoNetwork: true})
		if err != nil {
			continue
		}
		if !validGrades[result.Summary.RiskGrade] {
			t.Errorf("iteration %d: invalid risk grade %q", i, result.Summary.RiskGrade)
		}
	}
}

func TestProperty_FindingCountsConsistent(t *testing.T) {
	// total == len(findings) == critical+high+medium+low+info
	rng := rand.New(rand.NewSource(13))
	for i := 0; i < 200; i++ {
		config := randomConfig(rng, 1+rng.Intn(6))
		result, err := Scan(config, ScanOptions{NoNetwork: true})
		if err != nil {
			continue
		}
		s := result.Summary
		if s.Total != len(result.Findings) {
			t.Errorf("iteration %d: Summary.Total=%d != len(Findings)=%d",
				i, s.Total, len(result.Findings))
		}
		counted := s.Critical + s.High + s.Medium + s.Low + s.Info
		if s.Total != counted {
			t.Errorf("iteration %d: sum_severities=%d != Total=%d", i, counted, s.Total)
		}
	}
}

func TestProperty_FindingsHaveRequiredFields(t *testing.T) {
	validSeverities := map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	rng := rand.New(rand.NewSource(17))
	for i := 0; i < 100; i++ {
		config := randomConfig(rng, 1+rng.Intn(4))
		result, err := Scan(config, ScanOptions{NoNetwork: true})
		if err != nil {
			continue
		}
		for _, f := range result.Findings {
			if f.CheckID == "" {
				t.Errorf("iteration %d: finding has empty CheckID", i)
			}
			if !validSeverities[string(f.Severity)] {
				t.Errorf("iteration %d: finding %s has invalid severity %q", i, f.CheckID, f.Severity)
			}
			if f.ServerName == "" {
				t.Errorf("iteration %d: finding %s has empty ServerName", i, f.CheckID)
			}
			if string(f.OWASP) == "" {
				t.Errorf("iteration %d: finding %s has empty OWASP category", i, f.CheckID)
			}
		}
	}
}

func TestProperty_SARIFNeverCrashes(t *testing.T) {
	rng := rand.New(rand.NewSource(31))
	for i := 0; i < 100; i++ {
		config := randomConfig(rng, 1+rng.Intn(6))
		data, err := ScanToSARIF(config, ScanOptions{NoNetwork: true})
		if err != nil {
			t.Errorf("iteration %d: ScanToSARIF crashed: %v", i, err)
			continue
		}
		var sarif map[string]any
		if err := json.Unmarshal(data, &sarif); err != nil {
			t.Errorf("iteration %d: ScanToSARIF produced invalid JSON: %v", i, err)
			continue
		}
		if sarif["version"] != "2.1.0" {
			t.Errorf("iteration %d: SARIF version = %v, want 2.1.0", i, sarif["version"])
		}
	}
}

func TestProperty_BOMNeverCrashes(t *testing.T) {
	rng := rand.New(rand.NewSource(53))
	for i := 0; i < 100; i++ {
		config := randomConfig(rng, 1+rng.Intn(6))
		data, err := ScanToBOM(config, ScanOptions{NoNetwork: true})
		if err != nil {
			t.Errorf("iteration %d: ScanToBOM crashed: %v", i, err)
			continue
		}
		var bom map[string]any
		if err := json.Unmarshal(data, &bom); err != nil {
			t.Errorf("iteration %d: ScanToBOM produced invalid JSON: %v", i, err)
		}
	}
}

// ── Parser robustness ─────────────────────────────────────────────────────────

func TestProperty_ParserNeverCrashesOnArbitraryInput(t *testing.T) {
	// Parser must either succeed or return an error — never panic.
	// Mirrors Python: test_parser_never_crashes_on_arbitrary_input
	inputs := []string{
		"",
		"{}",
		"null",
		"[]",
		"not json at all",
		`{"mcpServers": null}`,
		`{"mcpServers": "string"}`,
		`{"mcpServers": 42}`,
		`// just a comment`,
		strings.Repeat("x", 10000),
		`{"mcpServers": {"s": {"command": null}}}`,
		`{"mcpServers": {"s": {"args": null}}}`,
		`{"mcpServers": {"s": {"env": "not-a-map"}}}`,
		`{"mcpServers": {"s": {"disabled": "yes"}}}`,
	}
	// Also add some random garbage
	rng := rand.New(rand.NewSource(0))
	chars := []byte("{}[]:,\"abcnpx/\\")
	for i := 0; i < 50; i++ {
		n := rng.Intn(200)
		buf := make([]byte, n)
		for j := range buf {
			buf[j] = chars[rng.Intn(len(chars))]
		}
		inputs = append(inputs, string(buf))
	}

	for _, input := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("parser panicked on input %q: %v", input[:min(50, len(input))], r)
				}
			}()
			Scan(input, ScanOptions{NoNetwork: true}) //nolint:errcheck
		}()
	}
}

func TestProperty_JSONRoundtripParse(t *testing.T) {
	// Config serialized as JSON must parse to same server count.
	cases := []struct {
		name    string
		servers map[string]any
	}{
		{"empty", map[string]any{}},
		{"one", map[string]any{"a": map[string]any{"command": "npx", "args": []string{}}}},
		{"five", func() map[string]any {
			m := make(map[string]any)
			for i := 0; i < 5; i++ {
				m[fmt.Sprintf("s%d", i)] = map[string]any{"command": "node", "args": []string{}}
			}
			return m
		}()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"mcpServers": tc.servers})
			result, err := Scan(string(raw), ScanOptions{NoNetwork: true})
			if err != nil {
				t.Fatalf("Scan failed: %v", err)
			}
			if result.Summary.ServersScanned != len(tc.servers) {
				t.Errorf("server count mismatch: want %d, got %d",
					len(tc.servers), result.Summary.ServersScanned)
			}
		})
	}
}
