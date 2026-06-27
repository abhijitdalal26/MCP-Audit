package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/checks"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// ScanOptions controls optional behaviour of the local engine.
type ScanOptions struct {
	NoNetwork  bool          // skip OSV.dev CVE lookup
	OSVTimeout time.Duration // timeout for OSV queries (default 3s)
}

var severityOrder = map[models.Severity]int{
	models.SeverityCritical: 0,
	models.SeverityHigh:     1,
	models.SeverityMedium:   2,
	models.SeverityLow:      3,
	models.SeverityInfo:     4,
}

const at005HighServerThreshold = 10

// scan runs all checks on the parsed config and returns a ScanResult.
func scan(config *parser.MCPConfig, opts ScanOptions) *models.ScanResult {
	osvTimeout := opts.OSVTimeout
	if osvTimeout == 0 {
		osvTimeout = 3 * time.Second
	}

	allFindings := []models.Finding{}
	perServer := map[string][]models.Finding{}

	activeServers := make([]parser.MCPServer, 0, len(config.Servers))
	for _, s := range config.Servers {
		if !s.Disabled {
			activeServers = append(activeServers, s)
		}
	}

	for _, srv := range activeServers {
		s := srv // capture range var
		sf := []models.Finding{}
		sf = append(sf, checks.CheckSecrets(&s)...)
		sf = append(sf, checks.CheckSupplyChain(&s)...)
		sf = append(sf, checks.CheckToolPoisoning(&s)...)
		sf = append(sf, checks.CheckPrivilege(&s)...)
		sf = append(sf, checks.CheckShadow(&s)...)
		sf = append(sf, checks.CheckCodeExecution(&s)...)
		sf = append(sf, checks.CheckAudit(&s)...)
		sf = append(sf, checks.CheckLifecycle(&s)...)
		if !opts.NoNetwork {
			sf = append(sf, checks.CheckOSV(&s, osvTimeout)...)
		}
		perServer[s.Name] = sf
		allFindings = append(allFindings, sf...)
	}

	// Config-level and cross-server checks
	allFindings = append(allFindings, checks.CheckConfigLevel(config, perServer)...)
	allFindings = append(allFindings, checks.CheckCrossServerChains(config, perServer)...)

	n := len(activeServers)

	// AT-001: No version pinning across any configured server
	if n >= 2 {
		pinnedCount := 0
		for _, srv := range activeServers {
			if anyPinned(&srv) {
				pinnedCount++
			}
		}
		if pinnedCount == 0 {
			allFindings = append(allFindings, models.Finding{
				CheckID:    "AT-001",
				Title:      "No version pinning across any configured server",
				Detail:     fmt.Sprintf("None of the %d configured MCP server(s) pin their package versions. Without version pins, every Claude Desktop or Cursor restart may silently pull a different (potentially compromised) version of each server package.", n),
				Severity:   models.SeverityMedium,
				OWASP:      models.MCP08,
				ServerName: "(all servers)",
				Remediation: "Pin all package versions in server args (e.g., `@modelcontextprotocol/server-filesystem@1.2.3`). This ensures reproducibility and protects against silent rug pulls.",
				Engine:   "custom",
				CWEID:    "CWE-1104",
			})
		}
	}

	// AT-005: Excessive server count
	if n >= at005HighServerThreshold {
		allFindings = append(allFindings, models.Finding{
			CheckID:    "AT-005",
			Title:      fmt.Sprintf("Excessive MCP server count: %d servers configured", n),
			Detail:     fmt.Sprintf("This config registers %d MCP servers. Each server is an independent process with its own tool set, permissions, and attack surface. Configurations with %d+ servers are statistically more likely to contain at least one compromised or misconfigured server, and the total attack surface grows with each addition. Real-world research found that 70%% of MCP servers have at least one security finding.", n, at005HighServerThreshold),
			Severity:   models.SeverityInfo,
			OWASP:      models.MCP08,
			ServerName: "(all servers)",
			Remediation: fmt.Sprintf("Audit each of the %d servers and remove any that are no longer actively used. For each server, confirm you understand what permissions it has and why it needs them. A smaller, well-audited set of servers is safer than a large unreviewed collection.", n),
			Engine:   "custom",
		})
	}

	// AT-006: Docker image with unpinned tag
	for _, srv := range activeServers {
		s := srv
		if cmdBase := checks.CmdBasename(&s); cmdBase == "docker" {
			if image := extractDockerImage(s.Args); image != "" && !dockerImagePinned(image) {
				allFindings = append(allFindings, models.Finding{
					CheckID:    "AT-006",
					Title:      fmt.Sprintf("Docker image without pinned tag: `%s`", image),
					Detail:     fmt.Sprintf("Server `%s` uses Docker image `%s` without a specific version tag or SHA digest. Without pinning, every restart can pull a different image version. An attacker who compromises the image registry or performs a tag-overwrite attack can silently replace the running MCP server code. Using `:latest` or no tag is equivalent to `@*` in npm — never reproducible, never auditable.", s.Name, image),
					Severity:   models.SeverityMedium,
					OWASP:      models.MCP04,
					ServerName: s.Name,
					Remediation: fmt.Sprintf("Pin the image to a specific version tag or SHA digest: `%s:1.2.3` or `%s@sha256:<digest>`. SHA digest pinning is stronger (tags are mutable; digests are not). Re-pin intentionally when you want to upgrade, not automatically.", image, image),
					Engine:       "custom",
					AttackTactic: "initial-access",
					CWEID:        "CWE-1104",
				})
			}
		}
	}

	// Sort by severity
	sort.SliceStable(allFindings, func(i, j int) bool {
		ri := severityOrder[allFindings[i].Severity]
		rj := severityOrder[allFindings[j].Severity]
		return ri < rj
	})

	return &models.ScanResult{
		ScanID:     uuid.New().String(),
		ConfigHash: config.ConfigHash,
		Findings:   allFindings,
		Summary:    summarize(allFindings, n),
		ScannedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

func anyPinned(server *parser.MCPServer) bool {
	for _, arg := range server.Args {
		if checks.IsPackageArg(arg) && checks.IsPinned(arg) {
			return true
		}
	}
	// Python packages: mcp-server==1.2.3 is pinned
	for _, pkg := range checks.ExtractPackages(server) {
		if pkg.Runtime == "pypi" && strings.Contains(pkg.Name, "==") {
			return true
		}
	}

	return false
}

func extractDockerImage(args []string) string {
	runIdx := -1
	for i, a := range args {
		if strings.ToLower(a) == "run" {
			runIdx = i
			break
		}
	}
	if runIdx < 0 {
		return ""
	}
	skipNextArg := map[string]bool{
		"-e": true, "--env": true, "-v": true, "--volume": true, "--name": true,
		"-p": true, "--publish": true, "--network": true, "--user": true, "-u": true,
		"--entrypoint": true, "--workdir": true, "-w": true, "--label": true,
		"-l": true, "--runtime": true, "--platform": true, "--memory": true,
		"-m": true, "--cpus": true, "--add-host": true, "--dns": true, "--env-file": true,
	}
	i := runIdx + 1
	for i < len(args) {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			if skipNextArg[arg] {
				i += 2
			} else {
				i++
			}
		} else {
			return arg
		}
	}
	return ""
}

var dockerFloatingTags = map[string]bool{
	"latest": true, "stable": true, "edge": true, "main": true,
	"master": true, "dev": true, "development": true, "test": true, "prod": true,
}

func dockerImagePinned(image string) bool {
	if strings.Contains(image, "@sha256:") {
		return true
	}
	if !strings.Contains(image, ":") {
		return false
	}
	tag := image[strings.LastIndex(image, ":")+1:]
	return !dockerFloatingTags[tag]
}

func summarize(findings []models.Finding, serverCount int) models.ScanSummary {
	counts := map[models.Severity]int{}
	owaspHit := map[string]bool{}
	for _, f := range findings {
		counts[f.Severity]++
		owaspHit[string(f.OWASP)] = true
	}
	score, grade := riskScore(findings)
	coverage := make([]string, 0, len(owaspHit))
	for k := range owaspHit {
		coverage = append(coverage, k)
	}
	sort.Strings(coverage)
	return models.ScanSummary{
		Total:          len(findings),
		Critical:       counts[models.SeverityCritical],
		High:           counts[models.SeverityHigh],
		Medium:         counts[models.SeverityMedium],
		Low:            counts[models.SeverityLow],
		Info:           counts[models.SeverityInfo],
		ServersScanned: serverCount,
		OWASPCoverage:  coverage,
		RiskScore:      score,
		RiskGrade:      grade,
	}
}

func riskScore(findings []models.Finding) (int, string) {
	raw := 0
	for _, f := range findings {
		raw += models.SeverityScoreWeights[f.Severity]
	}
	if raw > 100 {
		raw = 100
	}
	grade := "A"
	switch {
	case raw >= 80:
		grade = "F"
	case raw >= 60:
		grade = "D"
	case raw >= 40:
		grade = "C"
	case raw >= 20:
		grade = "B"
	}
	return raw, grade
}
