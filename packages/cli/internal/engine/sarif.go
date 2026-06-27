package engine

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
)

var severityToSARIFLevel = map[models.Severity]string{
	models.SeverityCritical: "error",
	models.SeverityHigh:     "error",
	models.SeverityMedium:   "warning",
	models.SeverityLow:      "note",
	models.SeverityInfo:     "none",
}

var severityToSecuritySeverity = map[models.Severity]string{
	models.SeverityCritical: "9.8",
	models.SeverityHigh:     "7.5",
	models.SeverityMedium:   "5.0",
	models.SeverityLow:      "2.5",
	models.SeverityInfo:     "0.0",
}

func checkIDToName(checkID string) string {
	prefixes := map[string]string{
		"SEC": "SecretExposure", "SC": "SupplyChain", "PI": "PromptInjection",
		"DX": "DataExfiltration", "PE": "PrivilegeEscalation", "SH": "ShadowServer",
		"AT": "AuditTelemetry", "EX": "CodeExecution", "LF": "LifecycleScript",
		"CL": "ConfigLevel", "EC": "EnvironmentConfig", "CHAIN": "CrossServerChain",
	}
	parts := strings.SplitN(checkID, "-", 2)
	suffix := ""
	if len(parts) == 2 {
		suffix = parts[1]
	}
	if name, ok := prefixes[parts[0]]; ok {
		return name + suffix
	}
	return "SecurityCheck" + suffix
}

func marshalSARIF(result *models.ScanResult) ([]byte, error) {
	type sarifText struct {
		Text string `json:"text"`
	}
	type sarifArtifact struct {
		URI       string `json:"uri"`
		URIBaseID string `json:"uriBaseId"`
	}
	type sarifRegion struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn"`
	}
	type sarifPhysical struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           sarifRegion   `json:"region"`
	}
	type sarifLogical struct {
		Name              string `json:"name"`
		Kind              string `json:"kind"`
		FullyQualifiedName string `json:"fullyQualifiedName"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysical  `json:"physicalLocation"`
		LogicalLocations []sarifLogical `json:"logicalLocations"`
	}
	type sarifRuleProps struct {
		Tags             []string `json:"tags"`
		SecuritySeverity string   `json:"security-severity"`
		Precision        string   `json:"precision"`
		ProblemSeverity  string   `json:"problem.severity"`
	}
	type sarifDefaultConfig struct {
		Level string `json:"level"`
	}
	type sarifRule struct {
		ID                   string             `json:"id"`
		Name                 string             `json:"name"`
		ShortDescription     sarifText          `json:"shortDescription"`
		FullDescription      sarifText          `json:"fullDescription"`
		HelpURI              string             `json:"helpUri"`
		Properties           sarifRuleProps     `json:"properties"`
		DefaultConfiguration sarifDefaultConfig `json:"defaultConfiguration"`
	}
	type sarifResultProps struct {
		OWASP        string `json:"owasp"`
		Server       string `json:"server"`
		Engine       string `json:"engine"`
		CWE          string `json:"cwe,omitempty"`
		AttackTactic string `json:"attackTactic,omitempty"`
	}
	type sarifFingerprints struct {
		MCPAuditV1 string `json:"mcpAudit/v1"`
	}
	type sarifResult struct {
		RuleID       string            `json:"ruleId"`
		Level        string            `json:"level"`
		Message      sarifText         `json:"message"`
		Locations    []sarifLocation   `json:"locations"`
		Properties   sarifResultProps  `json:"properties"`
		Fingerprints sarifFingerprints `json:"fingerprints"`
	}

	rules := []sarifRule{}
	seenRules := map[string]bool{}
	results := []sarifResult{}

	for i, f := range result.Findings {
		if !seenRules[f.CheckID] {
			seenRules[f.CheckID] = true
			tags := []string{string(f.OWASP), "security", "mcp"}
			if f.CWEID != "" {
				tags = append(tags, f.CWEID)
			}
			rules = append(rules, sarifRule{
				ID:               f.CheckID,
				Name:             checkIDToName(f.CheckID),
				ShortDescription: sarifText{f.Title},
				FullDescription:  sarifText{f.Detail},
				HelpURI:          fmt.Sprintf("https://mcpaudit.app/checks/%s", f.CheckID),
				Properties: sarifRuleProps{
					Tags:             tags,
					SecuritySeverity: severityToSecuritySeverity[f.Severity],
					Precision:        "high",
					ProblemSeverity:  string(f.Severity),
				},
				DefaultConfiguration: sarifDefaultConfig{Level: severityToSARIFLevel[f.Severity]},
			})
		}

		msg := fmt.Sprintf("%s\n\n%s\n\nRemediation: %s", f.Title, f.Detail, f.Remediation)
		props := sarifResultProps{
			OWASP:        string(f.OWASP),
			Server:       f.ServerName,
			Engine:       f.Engine,
			CWE:          f.CWEID,
			AttackTactic: f.AttackTactic,
		}
		results = append(results, sarifResult{
			RuleID:  f.CheckID,
			Level:   severityToSARIFLevel[f.Severity],
			Message: sarifText{msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: "mcp.json", URIBaseID: "%SRCROOT%"},
					Region:           sarifRegion{StartLine: 1, StartColumn: 1},
				},
				LogicalLocations: []sarifLogical{{
					Name:               f.ServerName,
					Kind:               "member",
					FullyQualifiedName: fmt.Sprintf("mcpServers.%s", f.ServerName),
				}},
			}},
			Properties: props,
			Fingerprints: sarifFingerprints{
				MCPAuditV1: fmt.Sprintf("%s/%s/%s/%d", result.ConfigHash, f.CheckID, f.ServerName, i),
			},
		})
	}

	doc := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "MCPAudit",
					"version":        "0.1.0",
					"informationUri": "https://mcpaudit.app",
					"rules":          rules,
				},
			},
			"results": results,
			"automationDetails": map[string]any{
				"id": result.ScanID,
				"description": map[string]any{
					"text": fmt.Sprintf("MCPAudit scan %s — %d findings across %d server(s)",
						result.ScanID, len(result.Findings), result.Summary.ServersScanned),
				},
			},
			"versionControlProvenance": []any{},
		}},
	}

	return json.MarshalIndent(doc, "", "  ")
}
