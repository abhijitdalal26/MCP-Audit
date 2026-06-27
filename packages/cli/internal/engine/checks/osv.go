package checks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

const osvURL = "https://api.osv.dev/v1/query"
const maxOSVFindingsPerPkg = 3

// CheckOSV queries OSV.dev for known CVEs in pinned packages (SC-004).
// Only fires for pinned packages (no version to query for unpinned).
// Fails gracefully — network errors produce an INFO finding and the scan continues.
func CheckOSV(server *parser.MCPServer, timeout time.Duration) []models.Finding {
	eco := osvEcosystem(server)
	if eco == "" {
		return nil
	}

	findings := []models.Finding{}
	client := &http.Client{Timeout: timeout}

	for _, arg := range server.Args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		name, version := parsePackageVersion(arg)
		if name == "" || version == "" {
			continue // skip unpinned
		}

		vulns, err := queryOSV(client, name, version, eco)
		if err != nil {
			// Network unavailable or timeout — add an info finding and continue
			findings = append(findings, models.Finding{
				CheckID:    "SC-004",
				Title:      fmt.Sprintf("OSV.dev CVE check unavailable for `%s@%s`", name, version),
				Detail:     fmt.Sprintf("Server `%s`: could not query OSV.dev for `%s@%s` — network unavailable or timeout. Run `mcpaudit scan` with network access to check for known CVEs, or use --no-network to suppress this message.", server.Name, name, version),
				Severity:   models.SeverityInfo,
				OWASP:      models.MCP04,
				ServerName: server.Name,
				Remediation: "Retry with network access or check https://osv.dev manually.",
				Engine:     "osv",
			})
			continue
		}

		cap := maxOSVFindingsPerPkg
		if len(vulns) < cap {
			cap = len(vulns)
		}
		for _, vuln := range vulns[:cap] {
			vulnID := getString(vuln, "id", "UNKNOWN")
			summary := getString(vuln, "summary", "No summary available.")
			severity := osvSeverity(vuln)
			fix := osvFixVersion(vuln)
			fixHint := ""
			if fix != "" {
				fixHint = fmt.Sprintf(" Fix available in version `%s`.", fix)
			}
			refURL := fmt.Sprintf("https://osv.dev/vulnerability/%s", vulnID)
			if refs, ok := vuln["references"].([]interface{}); ok && len(refs) > 0 {
				if ref, ok := refs[0].(map[string]interface{}); ok {
					if u, ok := ref["url"].(string); ok && u != "" {
						refURL = u
					}
				}
			}

			findings = append(findings, models.Finding{
				CheckID:    "SC-004",
				Title:      fmt.Sprintf("CVE in `%s@%s`: %s", name, version, vulnID),
				Detail:     fmt.Sprintf("Server `%s` uses `%s@%s` which has a known vulnerability: %s — %s%s (Source: OSV.dev — open vulnerability database maintained by Google)", server.Name, name, version, vulnID, summary, fixHint),
				Severity:   severity,
				OWASP:      models.MCP04,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Upgrade `%s` to a non-vulnerable version.%s See full details at: %s", name, fixHint, refURL),
				Engine:     "osv",
			})
		}
	}

	return findings
}

func osvEcosystem(server *parser.MCPServer) string {
	cmd := cmdBasename(server)
	switch cmd {
	case "npx", "npm":
		return "npm"
	case "uvx", "pip", "pip3", "python", "python3":
		return "PyPI"
	}
	return ""
}

// parsePackageVersion extracts (name, version) from a pinned package arg.
// Returns ("", "") if the arg is not pinned.
func parsePackageVersion(arg string) (string, string) {
	if strings.HasPrefix(arg, "@") {
		// @scope/pkg@version — needs 2+ @ signs
		count := strings.Count(arg, "@")
		if count < 2 {
			return "", ""
		}
		idx := strings.LastIndex(arg, "@")
		return arg[:idx], arg[idx+1:]
	}
	if strings.Contains(arg, "@") && !strings.HasPrefix(arg, "-") {
		idx := strings.Index(arg, "@")
		return arg[:idx], arg[idx+1:]
	}
	return "", ""
}

type osvRequest struct {
	Version string         `json:"version"`
	Package osvPkgField    `json:"package"`
}

type osvPkgField struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []map[string]interface{} `json:"vulns"`
}

func queryOSV(client *http.Client, name, version, ecosystem string) ([]map[string]interface{}, error) {
	body, _ := json.Marshal(osvRequest{
		Version: version,
		Package: osvPkgField{Name: name, Ecosystem: ecosystem},
	})
	resp, err := client.Post(osvURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OSV returned %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result osvResponse
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Vulns, nil
}

func osvSeverity(vuln map[string]interface{}) models.Severity {
	if sevs, ok := vuln["severity"].([]interface{}); ok {
		for _, s := range sevs {
			if sm, ok := s.(map[string]interface{}); ok {
				if score, ok := sm["score"].(string); ok {
					var f float64
					fmt.Sscanf(score, "%f", &f)
					if f >= 9.0 {
						return models.SeverityCritical
					}
					if f >= 7.0 {
						return models.SeverityHigh
					}
					if f >= 4.0 {
						return models.SeverityMedium
					}
					return models.SeverityLow
				}
			}
		}
	}
	// Fallback: database_specific.severity
	if db, ok := vuln["database_specific"].(map[string]interface{}); ok {
		switch strings.ToUpper(fmt.Sprintf("%v", db["severity"])) {
		case "CRITICAL":
			return models.SeverityCritical
		case "HIGH":
			return models.SeverityHigh
		case "MODERATE", "MEDIUM":
			return models.SeverityMedium
		case "LOW":
			return models.SeverityLow
		}
	}
	return models.SeverityMedium
}

func osvFixVersion(vuln map[string]interface{}) string {
	affected, ok := vuln["affected"].([]interface{})
	if !ok {
		return ""
	}
	for _, a := range affected {
		am, ok := a.(map[string]interface{})
		if !ok {
			continue
		}
		ranges, ok := am["ranges"].([]interface{})
		if !ok {
			continue
		}
		for _, r := range ranges {
			rm, ok := r.(map[string]interface{})
			if !ok {
				continue
			}
			events, ok := rm["events"].([]interface{})
			if !ok {
				continue
			}
			for _, e := range events {
				em, ok := e.(map[string]interface{})
				if !ok {
					continue
				}
				if fix, ok := em["fixed"].(string); ok && fix != "" {
					return fix
				}
			}
		}
	}
	return ""
}

func getString(m map[string]interface{}, key, defaultVal string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return defaultVal
}
