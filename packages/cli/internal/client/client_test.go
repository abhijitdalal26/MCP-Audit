package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/client"
)

func makeResult() client.ScanResult {
	return client.ScanResult{
		ScanID:     "abc123",
		ConfigHash: "deadbeef",
		Findings: []client.Finding{
			{
				CheckID:    "SEC-001",
				Title:      "AWS key hardcoded",
				Severity:   "critical",
				OWASP:      "MCP01",
				ServerName: "fs",
				Remediation: "Remove the key",
				CWEID:      "CWE-798",
			},
		},
		Summary: client.ScanSummary{
			Total: 1, Critical: 1, ServersScanned: 1,
			RiskGrade: "F", RiskScore: 90,
		},
	}
}

func TestScan_Success(t *testing.T) {
	result := makeResult()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/scan" || r.Method != http.MethodPost {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	}))
	defer srv.Close()

	c := client.New(srv.URL, 5)
	got, err := c.Scan(context.Background(), `{"mcpServers":{}}`, "mcp.json")
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if got.ScanID != "abc123" {
		t.Errorf("ScanID = %q, want abc123", got.ScanID)
	}
	if len(got.Findings) != 1 {
		t.Errorf("findings count = %d, want 1", len(got.Findings))
	}
}

func TestScan_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"detail":"No MCP servers found."}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, 5)
	_, err := c.Scan(context.Background(), `{}`, "mcp.json")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestScanRaw_SARIF(t *testing.T) {
	payload := []byte(`{"version":"2.1.0"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/scan/sarif" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/sarif+json")
		w.Write(payload)
	}))
	defer srv.Close()

	c := client.New(srv.URL, 5)
	data, ct, err := c.ScanRaw(context.Background(), "/scan/sarif", `{"mcpServers":{}}`, "mcp.json")
	if err != nil {
		t.Fatalf("ScanRaw: %v", err)
	}
	if string(data) != string(payload) {
		t.Errorf("data mismatch")
	}
	if ct != "application/sarif+json" {
		t.Errorf("content-type = %q, want application/sarif+json", ct)
	}
}
