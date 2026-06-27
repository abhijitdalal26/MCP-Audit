package checks

import (
	"fmt"
	"strings"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

var ignoreScriptsFlags = map[string]bool{
	"--ignore-scripts":      true,
	"--ignore-scripts=true": true,
}

// CheckLifecycle checks for npm lifecycle script execution risks (LF-001).
func CheckLifecycle(server *parser.MCPServer) []models.Finding {
	findings := []models.Finding{}

	cmd := cmdBasename(server)
	if cmd != "npx" && cmd != "npm" {
		return findings
	}

	var pkg string
	hasIgnore := false
	hasY := false

	for _, arg := range server.Args {
		if ignoreScriptsFlags[arg] {
			hasIgnore = true
		} else if arg == "-y" || arg == "--yes" {
			hasY = true
		} else if !strings.HasPrefix(arg, "-") && pkg == "" {
			pkg = arg
		}
	}

	if pkg == "" {
		return findings
	}

	if hasY && !hasIgnore {
		findings = append(findings, models.Finding{
			CheckID:  "LF-001",
			Title:    fmt.Sprintf("npm lifecycle scripts will run on install: `%s`", pkg),
			Detail:   fmt.Sprintf("Server `%s` runs `%s -y %s` without `--ignore-scripts`. npm packages can define `preinstall`, `install`, and `postinstall` scripts that execute automatically when the package is installed or updated. A malicious package or a compromised update can use these scripts to run arbitrary code on your machine before you've had a chance to review the package contents.", server.Name, cmd, pkg),
			Severity: models.SeverityMedium,
			OWASP:    models.MCP04,
			ServerName: server.Name,
			Remediation: fmt.Sprintf("Add `--ignore-scripts` to the args for `%s` to prevent automatic lifecycle script execution: `\"args\": [\"-y\", \"--ignore-scripts\", \"%s\"]`. Note: some packages require lifecycle scripts to function (native modules, binary downloads). Review the package's scripts block before deciding — run `npm show %s scripts` to inspect.", server.Name, pkg, pkg),
			Engine:       "custom",
			AttackTactic: "execution",
			CWEID:        "CWE-912",
		})
	}

	return findings
}
