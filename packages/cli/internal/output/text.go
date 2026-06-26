package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/client"
	"github.com/fatih/color"
)

var (
	criticalColor = color.New(color.FgRed, color.Bold)
	highColor     = color.New(color.FgYellow, color.Bold)
	mediumColor   = color.New(color.FgYellow)
	lowColor      = color.New(color.FgCyan)
	infoColor     = color.New(color.FgWhite)
	boldColor     = color.New(color.Bold)
	dimColor      = color.New(color.Faint)
	greenColor    = color.New(color.FgGreen, color.Bold)
	gradeColors   = map[string]*color.Color{
		"A": color.New(color.FgGreen, color.Bold),
		"B": color.New(color.FgGreen, color.Bold),
		"C": color.New(color.FgYellow, color.Bold),
		"D": color.New(color.FgYellow, color.Bold),
		"F": color.New(color.FgRed, color.Bold),
	}
)

// PrintText writes the human-readable scan output to w.
func PrintText(w io.Writer, result *client.ScanResult, ver string, noColor bool) {
	if noColor {
		color.NoColor = true
	}

	s := result.Summary
	fmt.Fprintf(w, "\nMCPAudit v%s — %d server%s scanned\n\n",
		ver, s.ServersScanned, plural(s.ServersScanned))

	// Grade
	gradeStr := fmt.Sprintf("Risk Grade: %s  (score: %d/100)", s.RiskGrade, s.RiskScore)
	if c, ok := gradeColors[s.RiskGrade]; ok {
		c.Fprintln(w, gradeStr)
	} else {
		fmt.Fprintln(w, gradeStr)
	}
	fmt.Fprintln(w)

	if s.Total == 0 {
		greenColor.Fprintf(w, "  ✓  All 51 checks passed. No security issues found.\n")
		fmt.Fprintln(w)
		return
	}

	// Findings
	for _, f := range result.Findings {
		printFinding(w, &f)
	}

	// Summary line
	parts := []string{}
	if s.Critical > 0 {
		parts = append(parts, criticalColor.Sprintf("%d critical", s.Critical))
	}
	if s.High > 0 {
		parts = append(parts, highColor.Sprintf("%d high", s.High))
	}
	if s.Medium > 0 {
		parts = append(parts, mediumColor.Sprintf("%d medium", s.Medium))
	}
	if s.Low > 0 {
		parts = append(parts, lowColor.Sprintf("%d low", s.Low))
	}
	if s.Info > 0 {
		parts = append(parts, infoColor.Sprintf("%d info", s.Info))
	}
	fmt.Fprintf(w, "%d finding%s: %s\n\n",
		s.Total, plural(s.Total), strings.Join(parts, ", "))

	dimColor.Fprintf(w, "Run with --format sarif to upload to GitHub Security tab.\n")
	dimColor.Fprintf(w, "Scan ID: %s\n\n", result.ScanID)
}

func printFinding(w io.Writer, f *client.Finding) {
	var sevLabel string
	switch strings.ToLower(f.Severity) {
	case "critical":
		sevLabel = criticalColor.Sprintf("  CRITICAL")
	case "high":
		sevLabel = highColor.Sprintf("  HIGH    ")
	case "medium":
		sevLabel = mediumColor.Sprintf("  MEDIUM  ")
	case "low":
		sevLabel = lowColor.Sprintf("  LOW     ")
	default:
		sevLabel = infoColor.Sprintf("  INFO    ")
	}

	boldColor.Fprintf(w, "%s  %s\n", sevLabel, f.Title)

	meta := fmt.Sprintf("Server: %s | %s | %s", f.ServerName, f.CheckID, f.OWASP)
	if f.CWEID != "" {
		meta += " | " + f.CWEID
	}
	if f.AttackTactic != "" {
		meta += " | ATT&CK: " + f.AttackTactic
	}
	dimColor.Fprintf(w, "           %s\n", meta)
	fmt.Fprintf(w, "           → %s\n\n", f.Remediation)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
