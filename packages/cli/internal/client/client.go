package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ScanRequest mirrors the API body.
type ScanRequest struct {
	Config     string `json:"config"`
	ConfigPath string `json:"config_path"`
}

// ScanResult mirrors the API response shape.
type ScanResult struct {
	ScanID     string      `json:"scan_id"`
	ConfigHash string      `json:"config_hash"`
	Findings   []Finding   `json:"findings"`
	Summary    ScanSummary `json:"summary"`
	ScannedAt  string      `json:"scanned_at"`
}

type Finding struct {
	CheckID      string `json:"check_id"`
	Title        string `json:"title"`
	Detail       string `json:"detail"`
	Severity     string `json:"severity"`
	OWASP        string `json:"owasp"`
	ServerName   string `json:"server_name"`
	Remediation  string `json:"remediation"`
	AttackTactic string `json:"attack_tactic,omitempty"`
	CWEID        string `json:"cwe_id,omitempty"`
}

type ScanSummary struct {
	Total          int      `json:"total"`
	Critical       int      `json:"critical"`
	High           int      `json:"high"`
	Medium         int      `json:"medium"`
	Low            int      `json:"low"`
	Info           int      `json:"info"`
	ServersScanned int      `json:"servers_scanned"`
	OWASPCoverage  []string `json:"owasp_coverage"`
	RiskScore      int      `json:"risk_score"`
	RiskGrade      string   `json:"risk_grade"`
}

// Client is a thin HTTP wrapper around the MCPAudit API.
type Client struct {
	apiURL  string
	timeout time.Duration
	http    *http.Client
}

// New creates a Client.
func New(apiURL string, timeoutSec int) *Client {
	d := time.Duration(timeoutSec) * time.Second
	return &Client{
		apiURL:  apiURL,
		timeout: d,
		http:    &http.Client{Timeout: d},
	}
}

// Scan calls POST /scan and returns a ScanResult.
func (c *Client) Scan(ctx context.Context, config, configPath string) (*ScanResult, error) {
	body, err := json.Marshal(ScanRequest{Config: config, ConfigPath: configPath})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/scan", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mcpaudit-cli/0.1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed — is the API reachable at %s? Error: %w", c.apiURL, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var apiErr struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Detail != "" {
			return nil, fmt.Errorf("API error %d: %s", resp.StatusCode, apiErr.Detail)
		}
		return nil, fmt.Errorf("API returned HTTP %d", resp.StatusCode)
	}

	var result ScanResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &result, nil
}

// ScanRaw calls an export endpoint and returns raw bytes with the content-type.
func (c *Client) ScanRaw(ctx context.Context, endpoint, config, configPath string) ([]byte, string, error) {
	body, err := json.Marshal(ScanRequest{Config: config, ConfigPath: configPath})
	if err != nil {
		return nil, "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mcpaudit-cli/0.1.0")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("API returned HTTP %d", resp.StatusCode)
	}
	return data, resp.Header.Get("Content-Type"), nil
}
