package engine

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
)

type bomProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type bomSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type bomRating struct {
	Source   bomSource `json:"source"`
	Severity string    `json:"severity"`
}

type bomAffect struct {
	Ref string `json:"ref"`
}

type bomVuln struct {
	BOMRef         string        `json:"bom-ref"`
	ID             string        `json:"id"`
	Source         bomSource     `json:"source"`
	Ratings        []bomRating   `json:"ratings"`
	Description    string        `json:"description"`
	Recommendation string        `json:"recommendation"`
	Properties     []bomProperty `json:"properties"`
	Affects        []bomAffect   `json:"affects"`
}

type bomComponent struct {
	Type        string        `json:"type"`
	BOMRef      string        `json:"bom-ref"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	PURL        string        `json:"purl,omitempty"`
	Version     string        `json:"version,omitempty"`
	Properties  []bomProperty `json:"properties"`
}

// marshalBOM produces a CycloneDX 1.6 AI-BOM JSON document.
// The function needs access to the parsed config to build the components list.
// We store it alongside the ScanResult via the helper below.
func marshalBOM(result *models.ScanResult) ([]byte, error) {
	// We do not have the config object here — BOM is generated from what ScanResult records.
	// Build minimal components from the findings' server names.
	seenServers := map[string]bool{}
	for _, f := range result.Findings {
		seenServers[f.ServerName] = true
	}

	components := []bomComponent{}
	for name := range seenServers {
		if name == "(all servers)" || strings.HasPrefix(name, "(") {
			continue
		}
		comp := bomComponent{
			Type:        "library",
			BOMRef:      "mcp-server:" + name,
			Name:        name,
			Description: fmt.Sprintf("MCP server — name: %s", name),
			Properties:  []bomProperty{},
		}
		count := 0
		for _, f := range result.Findings {
			if f.ServerName == name {
				count++
			}
		}
		if count > 0 {
			comp.Properties = append(comp.Properties, bomProperty{
				Name: "mcp:finding-count", Value: fmt.Sprintf("%d", count),
			})
		}
		components = append(components, comp)
	}

	vulns := []bomVuln{}
	for _, f := range result.Findings {
		props := []bomProperty{
			{Name: "owasp-mcp", Value: string(f.OWASP)},
			{Name: "mcp:server", Value: f.ServerName},
			{Name: "mcp:engine", Value: f.Engine},
		}
		if f.AttackTactic != "" {
			props = append(props, bomProperty{Name: "attack:tactic", Value: f.AttackTactic})
		}
		vulns = append(vulns, bomVuln{
			BOMRef:         fmt.Sprintf("vuln:%s:%s", f.CheckID, f.ServerName),
			ID:             f.CheckID,
			Source:         bomSource{Name: "MCPAudit", URL: fmt.Sprintf("https://mcpaudit.app/checks/%s", f.CheckID)},
			Ratings:        []bomRating{{Source: bomSource{Name: "MCPAudit"}, Severity: string(f.Severity)}},
			Description:    f.Detail,
			Recommendation: f.Remediation,
			Properties:     props,
			Affects:        []bomAffect{{Ref: "mcp-server:" + f.ServerName}},
		})
	}

	doc := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": fmt.Sprintf("urn:uuid:%s", result.ScanID),
		"version":      1,
		"metadata": map[string]any{
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"tools": []map[string]any{{
				"type":   "application",
				"vendor": "MCPAudit",
				"name":   "MCPAudit",
				"version": "0.1.0",
				"externalReferences": []map[string]any{{
					"type": "website",
					"url":  "https://mcpaudit.app",
				}},
			}},
			"component": map[string]any{
				"type":        "application",
				"name":        "MCP Configuration",
				"description": fmt.Sprintf("Scanned MCP config — hash %s", result.ConfigHash),
				"properties": []bomProperty{
					{Name: "mcp:servers-count", Value: fmt.Sprintf("%d", result.Summary.ServersScanned)},
					{Name: "mcp:scan-id", Value: result.ScanID},
				},
			},
		},
		"components":      components,
		"vulnerabilities": vulns,
	}

	return json.MarshalIndent(doc, "", "  ")
}

