package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/client"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	flagAPIURL  string
	flagFormat  string
	flagOutput  string
	flagFailOn  string
	flagNoColor bool
	flagTimeout int
	flagStdin   bool
)

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVar(&flagAPIURL, "api-url", "https://api.mcpaudit.app", "MCPAudit API base URL")
	scanCmd.Flags().StringVar(&flagFormat, "format", "text", "Output format: text, json, sarif, bom")
	scanCmd.Flags().StringVar(&flagOutput, "output", "", "Write output to file (default: stdout)")
	scanCmd.Flags().StringVar(&flagFailOn, "fail-on", "critical", "Exit 1 if findings at or above severity (critical/high/medium/low/info/none)")
	scanCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable ANSI color output")
	scanCmd.Flags().IntVar(&flagTimeout, "timeout", 30, "HTTP timeout in seconds")
	scanCmd.Flags().BoolVar(&flagStdin, "stdin", false, "Read MCP config JSON from stdin")
}

var scanCmd = &cobra.Command{
	Use:   "scan [file]",
	Short: "Scan an MCP config file for security vulnerabilities",
	Long: `Scan a claude_desktop_config.json or .cursor/mcp.json for security issues.

Examples:
  mcpaudit scan ~/.claude/claude_desktop_config.json
  mcpaudit scan mcp.json --format sarif > results.sarif
  mcpaudit scan mcp.json --fail-on high
  mcpaudit scan mcp.json --api-url http://localhost:8000
  cat mcp.json | mcpaudit scan --stdin`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScan,
}

func runScan(_ *cobra.Command, args []string) error {
	// ── Read config ───────────────────────────────────────────────────────────
	var configJSON, configPath string

	if flagStdin {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		configJSON = string(data)
		configPath = "stdin"
	} else {
		if len(args) == 0 {
			return fmt.Errorf("provide a config file path or use --stdin\n\nUsage: mcpaudit scan <file>")
		}
		configPath = args[0]
		data, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("read %q: %w", configPath, err)
		}
		configJSON = string(data)
	}

	// ── Output destination ────────────────────────────────────────────────────
	var w io.Writer = os.Stdout
	if flagOutput != "" {
		f, err := os.Create(flagOutput)
		if err != nil {
			return fmt.Errorf("create output file %q: %w", flagOutput, err)
		}
		defer f.Close()
		w = f
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(flagTimeout)*time.Second)
	defer cancel()

	c := client.New(flagAPIURL, flagTimeout)

	// ── SARIF / BOM: hit export endpoints directly ────────────────────────────
	switch strings.ToLower(flagFormat) {
	case "sarif":
		data, _, err := c.ScanRaw(ctx, "/scan/sarif", configJSON, configPath)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err

	case "bom":
		data, _, err := c.ScanRaw(ctx, "/scan/bom", configJSON, configPath)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}

	// ── text / json: call /scan ───────────────────────────────────────────────
	result, err := c.Scan(ctx, configJSON, configPath)
	if err != nil {
		return err
	}

	switch strings.ToLower(flagFormat) {
	case "json":
		if err := output.PrintJSON(w, result); err != nil {
			return err
		}
	default: // "text"
		output.PrintText(w, result, version, flagNoColor)
	}

	return checkFailOn(result, flagFailOn)
}

// severityRank maps severity to a rank (lower = more severe).
var severityRank = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}

// checkFailOn returns an ExitCodeError{1} if any finding meets the threshold.
func checkFailOn(result *client.ScanResult, failOn string) error {
	if strings.ToLower(failOn) == "none" {
		return nil
	}
	threshold, ok := severityRank[strings.ToLower(failOn)]
	if !ok {
		return fmt.Errorf("unknown --fail-on value %q (valid: critical/high/medium/low/info/none)", failOn)
	}
	for _, f := range result.Findings {
		if rank, ok := severityRank[strings.ToLower(f.Severity)]; ok && rank <= threshold {
			return &ExitCodeError{Code: 1}
		}
	}
	return nil
}
