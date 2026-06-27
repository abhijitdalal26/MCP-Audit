package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/client"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/output"
	"github.com/spf13/cobra"
)

var (
	flagAPIURL    string
	flagFormat    string
	flagOutput    string
	flagFailOn    string
	flagNoColor   bool
	flagTimeout   int
	flagStdin     bool
	flagNoNetwork bool
)

func init() {
	rootCmd.AddCommand(scanCmd)

	// Empty default = offline mode (local engine). Set --api-url to use remote API.
	scanCmd.Flags().StringVar(&flagAPIURL, "api-url", "", "MCPAudit API base URL (default: run locally, no data sent)")
	scanCmd.Flags().StringVar(&flagFormat, "format", "text", "Output format: text, json, sarif, bom")
	scanCmd.Flags().StringVar(&flagOutput, "output", "", "Write output to file (default: stdout)")
	scanCmd.Flags().StringVar(&flagFailOn, "fail-on", "critical", "Exit 1 if findings at or above severity (critical/high/medium/low/info/none)")
	scanCmd.Flags().BoolVar(&flagNoColor, "no-color", false, "Disable ANSI color output")
	scanCmd.Flags().IntVar(&flagTimeout, "timeout", 30, "HTTP timeout in seconds")
	scanCmd.Flags().BoolVar(&flagStdin, "stdin", false, "Read MCP config JSON from stdin")
	scanCmd.Flags().BoolVar(&flagNoNetwork, "no-network", false, "Skip OSV.dev CVE lookup (faster, fully offline)")
}

var scanCmd = &cobra.Command{
	Use:   "scan [file]",
	Short: "Scan an MCP config file for security vulnerabilities",
	Long: `Scan a claude_desktop_config.json or .cursor/mcp.json for security issues.
By default the scan runs entirely offline — your config never leaves your machine.
With no arguments, auto-detects your Claude Desktop or Cursor config.

Examples:
  mcpaudit scan                                # auto-detect config
  mcpaudit scan ~/Library/.../claude_desktop_config.json
  mcpaudit scan mcp.json --format sarif > results.sarif
  mcpaudit scan mcp.json --fail-on high
  mcpaudit scan mcp.json --no-network          # skip OSV CVE lookup
  mcpaudit scan mcp.json --api-url https://api.mcpaudit.app  # use remote API
  cat mcp.json | mcpaudit scan --stdin`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
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
			// Auto-detect Claude Desktop / Cursor config
			found := detectConfigs()
			if len(found) == 0 {
				return fmt.Errorf("no MCP config file found automatically\n\nProvide a path: mcpaudit scan <file>\n\nExpected locations:\n  macOS:   ~/Library/Application Support/Claude/claude_desktop_config.json\n  Windows: %%APPDATA%%\\Claude\\claude_desktop_config.json\n  Linux:   ~/.config/claude/claude_desktop_config.json\n  Cursor:  ~/.cursor/mcp.json")
			}
			// Use the first found config (Claude Desktop takes priority over Cursor)
			configPath = found[0].Path
			if !flagNoColor {
				fmt.Fprintf(os.Stderr, "Auto-detected %s config: %s\n", found[0].Source, configPath)
			}
		} else {
			configPath = args[0]
		}
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

	// ── Route: local engine (default) or remote API ──────────────────────────
	if flagAPIURL == "" {
		return runLocalScan(w, configJSON, configPath)
	}
	return runRemoteScan(w, configJSON, configPath)
}

// runLocalScan executes the embedded Go engine — zero data leaves the machine.
func runLocalScan(w io.Writer, configJSON, _ string) error {
	opts := engine.ScanOptions{
		NoNetwork:  flagNoNetwork,
		OSVTimeout: time.Duration(flagTimeout) * time.Second,
	}

	switch strings.ToLower(flagFormat) {
	case "sarif":
		data, err := engine.ScanToSARIF(configJSON, opts)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		_, err = w.Write(data)
		return err

	case "bom":
		data, err := engine.ScanToBOM(configJSON, opts)
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		_, err = w.Write(data)
		return err
	}

	result, err := engine.Scan(configJSON, opts)
	if err != nil {
		return fmt.Errorf("scan: %w", err)
	}

	// Convert engine.ScanResult to client.ScanResult for shared output formatters.
	cr := engineToClientResult(result)

	switch strings.ToLower(flagFormat) {
	case "json":
		if err := output.PrintJSON(w, cr); err != nil {
			return err
		}
	default:
		output.PrintText(w, cr, version, flagNoColor)
	}
	return checkFailOn(cr, flagFailOn)
}

// runRemoteScan sends the config to the MCPAudit API (user opted in via --api-url).
func runRemoteScan(w io.Writer, configJSON, configPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(flagTimeout)*time.Second)
	defer cancel()

	c := client.New(flagAPIURL, flagTimeout)

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

	result, err := c.Scan(ctx, configJSON, configPath)
	if err != nil {
		return err
	}

	switch strings.ToLower(flagFormat) {
	case "json":
		if err := output.PrintJSON(w, result); err != nil {
			return err
		}
	default:
		output.PrintText(w, result, version, flagNoColor)
	}
	return checkFailOn(result, flagFailOn)
}

// engineToClientResult converts the local engine's ScanResult to the client type
// so the shared text/json output formatters work for both local and remote modes.
// Both structs share identical json tags so a round-trip marshal works correctly.
func engineToClientResult(r any) *client.ScanResult {
	data, err := json.Marshal(r)
	if err != nil {
		panic("engine result marshal: " + err.Error())
	}
	var cr client.ScanResult
	if err := json.Unmarshal(data, &cr); err != nil {
		panic("client result unmarshal: " + err.Error())
	}
	return &cr
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
