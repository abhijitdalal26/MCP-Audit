// Package engine is the public entry point for the MCPAudit local offline engine.
// It wraps the parser + scanner into three simple functions: Scan, ScanToSARIF, ScanToBOM.
// Zero network is required by default (OSV.dev lookup is optional via ScanOptions).
package engine

import (
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// Scan parses the MCP config JSON and runs all 51 security checks locally.
// Returns findings sorted by severity (critical first).
func Scan(configJSON string, opts ScanOptions) (*models.ScanResult, error) {
	cfg, err := parser.ParseConfig(configJSON)
	if err != nil {
		return nil, err
	}
	return scan(cfg, opts), nil
}

// ScanToSARIF parses the config and returns SARIF 2.1.0 output as JSON bytes.
func ScanToSARIF(configJSON string, opts ScanOptions) ([]byte, error) {
	result, err := Scan(configJSON, opts)
	if err != nil {
		return nil, err
	}
	return marshalSARIF(result)
}

// ScanToBOM parses the config and returns CycloneDX 1.6 AI-BOM as XML bytes.
func ScanToBOM(configJSON string, opts ScanOptions) ([]byte, error) {
	result, err := Scan(configJSON, opts)
	if err != nil {
		return nil, err
	}
	return marshalBOM(result)
}
