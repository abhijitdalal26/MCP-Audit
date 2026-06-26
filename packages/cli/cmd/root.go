package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version string

// ExitCodeError carries a specific exit code without printing a message.
// Used by scan to exit 1 on threshold breach.
type ExitCodeError struct{ Code int }

func (e *ExitCodeError) Error() string { return "" }

var rootCmd = &cobra.Command{
	Use:   "mcpaudit",
	Short: "MCPAudit — MCP server configuration security scanner",
	Long: `MCPAudit scans your MCP server configuration for security vulnerabilities.
51 checks across the OWASP MCP Top 10: secrets, supply chain, privilege
escalation, prompt injection, and more.`,
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute is called by main with the build-time version string.
func Execute(v string) {
	version = v
	if err := rootCmd.Execute(); err != nil {
		if ee, ok := err.(*ExitCodeError); ok {
			os.Exit(ee.Code)
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(2)
	}
}
