package checks

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// knownMalicious is an allowlist-blocklist of confirmed malicious or spoofed MCP packages.
// Sources: tooltrust AS-008, Ox.Security advisory April 2026, Trend Micro MCP CVEs.
var knownMalicious = map[string]bool{
	"mcp-server-free":            true,
	"modelcontextprotocl":        true, // missing 'o' in protocol
	"modelcontextprotocol-free":  true,
	"mcp-filesystem-server":      true,
	"mcp-server-free-filesystem": true,
	"mcp-github-server":          true,
	"mcp-postgres-server":        true,
	"mcp-filesystem":             true,
	"mcp-memory-server":          true,
	"claude-mcp-server":          true,
	"anthropic-mcp":              true,
	"mcp-tool-helper":            true,
	"mcp-server-helper":          true,
	"free-mcp-server":            true,
	"claude-desktop-mcp":         true,
	"mcp-server-claude":          true,
	"mcp-installer":              true,
	"universal-mcp":              true,
	"mcp-bridge":                 true,
	"mcp-proxy-server":           true,
	"mcp-auto-setup":             true,
	"oura-mcp":                   true,
}

// knownMaliciousByRuntime: packages malicious only on specific runtimes.
// e.g., "litellm" is legitimate on PyPI but was supply-chain-attacked on npm.
var knownMaliciousByRuntime = map[string]map[string]bool{
	"npx": {"litellm": true, "trivy": true},
	"npm": {"litellm": true, "trivy": true},
}

// trustedScopes: verified npm org accounts with established security practices.
var trustedScopes = map[string]bool{
	"@modelcontextprotocol": true,
	"@anthropic":            true,
	"@aws-sdk":              true,
	"@aws-cdk":              true,
	"@google-cloud":         true,
	"@googleapis":           true,
	"@azure":                true,
	"@microsoft":            true,
	"@openai":               true,
	"@github":               true,
	"@vercel":               true,
	"@supabase":             true,
	"@cloudflare":           true,
	"@stripe":               true,
	"@sentry":               true,
	"@elastic":              true,
	"@smithery":             true,
	"@raycast":              true,
	"@e2b":                  true,
	"@upstash":              true,
	"@linear":               true,
}

// sc008TarballRE matches tarball/zip URLs used as npm/PyPI package arguments.
var sc008TarballRE = regexp.MustCompile(`(?i)^https?://.*\.(tar\.gz|tgz|zip|tar\.bz2)$`)

// sc009RelRE matches relative path installs: ./ ../ .\ ..\
var sc009RelRE = regexp.MustCompile(`^\.{1,2}[/\\]`)

// sc009DriveRE matches Windows absolute path installs: C:\ or D:/
var sc009DriveRE = regexp.MustCompile(`^[A-Za-z]:[/\\]`)

// typosquatPattern holds a string-based check (RE2 doesn't support lookaheads).
type typosquatPattern struct {
	// matchFn returns true if the package name matches this typosquat pattern.
	matchFn func(lower string) bool
	reason  string
}

// typosquatPatterns mirrors Python's _TYPOSQUAT_PATTERNS.
// NOTE: The Python SC-002 check used `@modelcontextprotoc(?!ol/)` — a negative lookahead.
// RE2 (Go) does not support lookaheads. Rewritten as two-condition string checks.
var typosquatPatterns = []typosquatPattern{
	{
		// Matches @modelcontextprotoc... but NOT the legitimate @modelcontextprotocol/
		matchFn: func(s string) bool {
			return strings.Contains(s, "@modelcontextprotoc") && !strings.Contains(s, "@modelcontextprotocol/")
		},
		reason: "missing/altered 'ol' in 'protocol'",
	},
	{
		matchFn: func(s string) bool { return regexp.MustCompile(`@modelcontextprot0col/`).MatchString(s) },
		reason:  "zero replacing 'o' in 'protocol'",
	},
	{
		matchFn: func(s string) bool { return regexp.MustCompile(`@m0delcontextprotocol/`).MatchString(s) },
		reason:  "zero replacing 'o' in 'model'",
	},
	{
		matchFn: func(s string) bool { return regexp.MustCompile(`mcp-serv[e3]r-`).MatchString(s) },
		reason:  "leet-speak substitution in 'server'",
	},
	{
		matchFn: func(s string) bool { return regexp.MustCompile(`@modelc0ntextprotocol/`).MatchString(s) },
		reason:  "zero replacing 'o' in 'context'",
	},
	{
		matchFn: func(s string) bool { return regexp.MustCompile(`@modelcontexptrotocol/`).MatchString(s) },
		reason:  "transposed letters in 'context'",
	},
	{
		matchFn: func(s string) bool { return regexp.MustCompile(`@modelcontextprotocol\.`).MatchString(s) },
		reason:  "dot instead of slash after scope",
	},
}

type pkgEntry struct {
	Name    string
	Runtime string // "npm" or "pypi"
}

// PkgEntry is exported for use by scanner.go's anyPinned helper.
type PkgEntry = pkgEntry

// ExtractPackages is the exported version of extractPackages.
func ExtractPackages(server *parser.MCPServer) []PkgEntry { return extractPackages(server) }

// extractPackages returns all packages to check for a server (npx/npm → npm, uvx/uv → pypi).
func extractPackages(server *parser.MCPServer) []pkgEntry {
	cmd := cmdBasename(server)
	switch cmd {
	case "npx", "npm":
		for _, arg := range server.Args {
			if !strings.HasPrefix(arg, "-") {
				return []pkgEntry{{Name: arg, Runtime: "npm"}}
			}
		}
	case "uvx":
		for _, arg := range server.Args {
			if !strings.HasPrefix(arg, "-") {
				return []pkgEntry{{Name: arg, Runtime: "pypi"}}
			}
		}
	case "uv":
		var pkgs []pkgEntry
		args := server.Args
		for i := 0; i < len(args); i++ {
			if (args[i] == "--with" || args[i] == "-w") && i+1 < len(args) {
				pkgs = append(pkgs, pkgEntry{Name: args[i+1], Runtime: "pypi"})
				i++
			} else if strings.HasPrefix(args[i], "--with=") {
				pkgs = append(pkgs, pkgEntry{Name: strings.SplitN(args[i], "=", 2)[1], Runtime: "pypi"})
			}
		}
		return pkgs
	}
	return nil
}

// basePackageName strips version pin to get bare name.
// npm:  @scope/pkg@1.0 → @scope/pkg;  pkg@1.0 → pkg
// pypi: mcp-server==1.2.3 → mcp-server
var versionSplitRE = regexp.MustCompile(`[@=<>!]`)

func basePackageName(pkg string) string {
	if strings.HasPrefix(pkg, "@") {
		// @scope/name@ver → keep @scope/name
		rest := pkg[1:] // "scope/name@ver"
		slashIdx := strings.Index(rest, "/")
		if slashIdx == -1 {
			return pkg
		}
		nameVer := rest[slashIdx+1:] // "name@ver"
		atIdx := strings.Index(nameVer, "@")
		if atIdx == -1 {
			return pkg
		}
		return "@" + rest[:slashIdx] + "/" + nameVer[:atIdx]
	}
	parts := versionSplitRE.Split(pkg, 2)
	return parts[0]
}

// CheckSupplyChain checks for known-malicious packages, typosquats, unverified scopes,
// git ref dependencies, homoglyph characters, and registry overrides (SC-001..007).
func CheckSupplyChain(server *parser.MCPServer) []models.Finding {
	findings := []models.Finding{}
	packages := extractPackages(server)
	if len(packages) == 0 {
		return findings
	}

	cmd := cmdBasename(server)

	for _, pkg := range packages {
		base := strings.ToLower(basePackageName(pkg.Name))
		lower := strings.ToLower(pkg.Name)

		// SC-001: Known malicious package
		runtimeBlock := knownMaliciousByRuntime[cmd]
		if knownMalicious[base] || (runtimeBlock != nil && runtimeBlock[base]) {
			findings = append(findings, models.Finding{
				CheckID:  "SC-001",
				Title:    fmt.Sprintf("Known malicious or compromised package: `%s`", pkg.Name),
				Detail:   fmt.Sprintf("Server `%s` installs `%s`, which is flagged as known malicious, confirmed typosquatted, or part of a supply chain attack. (Sources: tooltrust AS-008 embedded blocklist, Ox.Security advisory April 2026)", server.Name, pkg.Name),
				Severity: models.SeverityCritical,
				OWASP:    models.MCP04,
				ServerName: server.Name,
				Remediation: "Remove this server from your config immediately. Find the official equivalent at registry.modelcontextprotocol.io. If this is `litellm` or `trivy`, verify you are using the official distribution channel (pip install litellm from PyPI, not npm).",
				Engine:   "custom",
				CWEID:    "CWE-829",
			})
			continue // skip further checks on confirmed bad package
		}

		// SC-002: Typosquatting
		for _, tp := range typosquatPatterns {
			if tp.matchFn(lower) {
				findings = append(findings, models.Finding{
					CheckID:  "SC-002",
					Title:    fmt.Sprintf("Possible typosquatted package: `%s`", pkg.Name),
					Detail:   fmt.Sprintf("Server `%s` installs `%s`, which resembles a legitimate MCP package but contains a subtle spelling error (%s). This is a common typosquatting attack pattern.", server.Name, pkg.Name, tp.reason),
					Severity: models.SeverityHigh,
					OWASP:    models.MCP04,
					ServerName: server.Name,
					Remediation: "Verify the exact package name at registry.modelcontextprotocol.io or npmjs.com. Do not install until you have confirmed the correct spelling.",
					Engine:   "custom",
					CWEID:    "CWE-829",
				})
				break
			}
		}

		// SC-003: Unverified npm scope
		if pkg.Runtime == "npm" && strings.HasPrefix(pkg.Name, "@") {
			scope := strings.SplitN(pkg.Name, "/", 2)[0]
			if !trustedScopes[scope] {
				findings = append(findings, models.Finding{
					CheckID:  "SC-003",
					Title:    fmt.Sprintf("Package from unverified scope: `%s`", scope),
					Detail:   fmt.Sprintf("Server `%s` installs `%s` from scope `%s`, which is not an officially verified MCP publisher. Third-party packages may not have undergone any security review.", server.Name, pkg.Name, scope),
					Severity: models.SeverityMedium,
					OWASP:    models.MCP04,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Verify `%s` on npmjs.com and cross-reference with registry.modelcontextprotocol.io or glama.ai/mcp/servers before trusting it. Check the package's GitHub repo for source code and maintainer history.", pkg.Name),
					Engine:   "custom",
					CWEID:    "CWE-829",
				})
			}
		}

		// SC-005: Direct git ref dependency (bypasses registry audit trail)
		for _, host := range []string{"github:", "bitbucket:", "gitlab:"} {
			if strings.HasPrefix(lower, host) {
				hostCap := strings.ToUpper(host[:1]) + host[1:len(host)-1]
				findings = append(findings, models.Finding{
					CheckID:  "SC-005",
					Title:    fmt.Sprintf("Direct %s ref dependency: `%s`", hostCap, pkg.Name),
					Detail:   fmt.Sprintf("Server `%s` installs `%s` directly from %s, bypassing the npm registry entirely. This means: no npm audit trail, no integrity hash verification, no locked version. A maintainer can force-push to that branch and silently change what code runs on your machine the next time the MCP server starts (rug pull attack).", server.Name, pkg.Name, hostCap),
					Severity: models.SeverityHigh,
					OWASP:    models.MCP04,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Replace `%s` with a published npm package version if the author has one. If you must use a git ref, pin to a specific commit SHA (e.g., `github:user/repo#abc1234`) and verify the commit before pinning. Consider forking the repo to your own account to control when updates are pulled.", pkg.Name),
					Engine:        "custom",
					AttackTactic:  "initial-access",
					CWEID:         "CWE-829",
				})
				break
			}
		}

		// SC-008: VCS URL install (git+https://, git+ssh://) or tarball URL.
		// Complements SC-005 (which catches github:/bitbucket:/gitlab: shorthands).
		// These forms also bypass the registry with no integrity hash verification.
		sc008Prefixes := []string{"git+https://", "git+ssh://", "git+http://"}
		isSC008VCS := false
		for _, pfx := range sc008Prefixes {
			if strings.HasPrefix(lower, pfx) {
				isSC008VCS = true
				break
			}
		}
		isSC008Tarball := sc008TarballRE.MatchString(pkg.Name)
		if isSC008VCS || isSC008Tarball {
			installType := "VCS URL install"
			detailExtra := "The remote git repository can be force-pushed at any time to deliver malicious code."
			if isSC008Tarball {
				installType = "tarball URL install"
				detailExtra = "The tarball URL can be replaced at any time and there is no checksum verification."
			}
			findings = append(findings, models.Finding{
				CheckID:  "SC-008",
				Title:    fmt.Sprintf("Registry bypass via %s: `%s`", installType, pkg.Name),
				Detail:   fmt.Sprintf("Server `%s` installs `%s` via a direct %s instead of the npm/PyPI registry. This bypasses all registry integrity checks, CVE auditing, and provenance verification. %s No legitimate MCP server requires a git URL or tarball install for production use.", server.Name, pkg.Name, installType, detailExtra),
				Severity: models.SeverityHigh,
				OWASP:    models.MCP04,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Replace `%s` with the official published package version from npmjs.com or pypi.org. If the package is not published to a registry, review the source code, pin to a specific commit SHA, and consider publishing to a private registry with integrity verification.", pkg.Name),
				Engine:       "custom",
				AttackTactic: "initial-access",
				CWEID:        "CWE-494",
			})
		}

		// SC-009: Local filesystem install via file: protocol or relative/absolute path.
		// `npx file:../evil` or `npx ./local-pkg` loads an arbitrary local directory —
		// no registry, no integrity hash, no audit trail.
		// If an attacker can write to that path (e.g., /tmp, ../), they control the install.
		sc009FilePrefix := strings.HasPrefix(lower, "file:") || strings.HasPrefix(lower, "file://")
		sc009Rel := sc009RelRE.MatchString(pkg.Name)
		sc009Drive := sc009DriveRE.MatchString(pkg.Name)
		if sc009FilePrefix || sc009Rel || sc009Drive {
			findings = append(findings, models.Finding{
				CheckID:  "SC-009",
				Title:    fmt.Sprintf("Registry bypass via local filesystem install: `%s`", pkg.Name),
				Detail:   fmt.Sprintf("Server `%s` installs `%s` from the local filesystem instead of the npm or PyPI registry. Local installs have no integrity hash, no CVE audit trail, and no provenance verification. If an attacker can write to the target path (e.g., /tmp or relative paths), they can replace the package with malicious code that runs on the next server invocation.", server.Name, pkg.Name),
				Severity: models.SeverityHigh,
				OWASP:    models.MCP04,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Publish `%s` to the npm or PyPI registry and reference it by name and pinned version. If this is a local development install, remove it from the shared/committed config before deployment.", pkg.Name),
				Engine:       "custom",
				AttackTactic: "initial-access",
				CWEID:        "CWE-494",
			})
		}

		// SC-006: Non-ASCII / homoglyph characters in package name
		// npm names are ASCII-only [a-z0-9_.\-@/]; PyPI names are [A-Za-z0-9._-].
		// Any codepoint > 127 is a homoglyph spoofing attempt.
		var sc006Hits []string
		for i, r := range pkg.Name {
			if r > 127 {
				cat := "Cf"
				if unicode.IsLetter(r) {
					cat = "L"
				} else if unicode.IsNumber(r) {
					cat = "N"
				}
				sc006Hits = append(sc006Hits, fmt.Sprintf("'%c' at pos %d (U+%04X [%s])", r, i, r, cat))
			}
		}
		if len(sc006Hits) > 0 {
			detail := strings.Join(sc006Hits, "; ")
			if len(sc006Hits) > 3 {
				detail = strings.Join(sc006Hits[:3], "; ") + fmt.Sprintf(" (+%d more)", len(sc006Hits)-3)
			}
			findings = append(findings, models.Finding{
				CheckID:  "SC-006",
				Title:    fmt.Sprintf("Non-ASCII/homoglyph characters in package name: `%s`", pkg.Name),
				Detail:   fmt.Sprintf("Server `%s` installs `%s` which contains non-ASCII Unicode character(s): %s. npm and PyPI package names are restricted to ASCII characters. Non-ASCII characters are the hallmark of homoglyph spoofing attacks — a visually identical character (e.g., Cyrillic 'а' U+0430 vs Latin 'a' U+0061) that resolves to a completely different package controlled by an attacker.", server.Name, pkg.Name, detail),
				Severity: models.SeverityHigh,
				OWASP:    models.MCP04,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Do not install `%s`. Manually type the correct package name at npmjs.com or pypi.org — never copy-paste package names from untrusted sources (chat, web pages, emails). Homoglyph attacks rely entirely on visual similarity to deceive the installer.", pkg.Name),
				Engine:       "custom",
				AttackTactic: "initial-access",
				CWEID:        "CWE-1007",
			})
		}
	}

	// SC-007: Custom npm/PyPI registry override (Birsan dependency confusion attack)
	checkRegistryOverride(server, cmd, &findings)

	return findings
}

func checkRegistryOverride(server *parser.MCPServer, cmd string, findings *[]models.Finding) {
	// npm --registry flag
	if cmd == "npx" || cmd == "npm" {
		for i, arg := range server.Args {
			var registryURL string
			if arg == "--registry" && i+1 < len(server.Args) {
				registryURL = server.Args[i+1]
			} else if strings.HasPrefix(arg, "--registry=") {
				registryURL = strings.SplitN(arg, "=", 2)[1]
			}
			if registryURL != "" && !strings.HasPrefix(registryURL, "https://registry.npmjs.org") {
				*findings = append(*findings, models.Finding{
					CheckID:  "SC-007",
					Title:    fmt.Sprintf("Custom npm registry override: `%s`", registryURL),
					Detail:   fmt.Sprintf("Server `%s` passes `--registry %s` in its args. This redirects ALL npm package resolution to the specified registry instead of the official https://registry.npmjs.org. An attacker-controlled registry can serve malicious packages that shadow any package name, including official ones — with no warning to the user. (Attack: Alex Birsan dependency confusion, 2021)", server.Name, registryURL),
					Severity: models.SeverityHigh,
					OWASP:    models.MCP04,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Verify that `%s` is your organization's internal registry and that it applies strict package name validation to prevent dependency confusion. If you do not recognize this registry, remove the flag and use the official npm registry.", registryURL),
					Engine:       "custom",
					AttackTactic: "initial-access",
					CWEID:        "CWE-829",
				})
				return
			}
		}
		// npm env var registry override
		for k, v := range server.Env {
			if (strings.ToUpper(k) == "NPM_CONFIG_REGISTRY" || strings.ToUpper(k) == "NPM_REGISTRY") && v != "" {
				if !strings.HasPrefix(v, "https://registry.npmjs.org") {
					*findings = append(*findings, models.Finding{
						CheckID:  "SC-007",
						Title:    fmt.Sprintf("Custom npm registry via env var `%s`: `%s`", k, v),
						Detail:   fmt.Sprintf("Server `%s` sets `%s=%s`, overriding the default npm registry for all package operations. This is a common vector for dependency confusion attacks — all npm installs in this server's runtime will resolve against the specified registry instead of the official https://registry.npmjs.org.", server.Name, k, v),
						Severity: models.SeverityHigh,
						OWASP:    models.MCP04,
						ServerName: server.Name,
						Remediation: fmt.Sprintf("Verify that `%s` is a trusted registry. Use Verdaccio or Nexus proxy registries with upstream mirroring rather than standalone registries to prevent dependency confusion attacks.", v),
						Engine:       "custom",
						AttackTactic: "initial-access",
						CWEID:        "CWE-829",
					})
					return
				}
			}
		}
	}

	// PyPI --index-url / --extra-index-url override
	if cmd == "uv" || cmd == "uvx" || cmd == "pip" || cmd == "pip3" || cmd == "python" || cmd == "python3" {
		for i, arg := range server.Args {
			var indexURL string
			if (arg == "--index-url" || arg == "-i" || arg == "--extra-index-url") && i+1 < len(server.Args) {
				indexURL = server.Args[i+1]
			} else if strings.HasPrefix(arg, "--index-url=") || strings.HasPrefix(arg, "--extra-index-url=") {
				indexURL = strings.SplitN(arg, "=", 2)[1]
			}
			if indexURL != "" && !strings.Contains(strings.ToLower(indexURL), "pypi.org") {
				*findings = append(*findings, models.Finding{
					CheckID:  "SC-007",
					Title:    fmt.Sprintf("Custom PyPI index override: `%s`", indexURL),
					Detail:   fmt.Sprintf("Server `%s` passes a custom PyPI index `%s` in its args. This redirects Python package resolution to a custom index instead of the official https://pypi.org. A malicious custom index can return any content for any package name, enabling dependency confusion and supply chain attacks.", server.Name, indexURL),
					Severity: models.SeverityHigh,
					OWASP:    models.MCP04,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Verify `%s` is a trusted mirror or internal registry. Use `--extra-index-url` with the official PyPI as the primary index and enable `--index-strategy first-match` (uv) to prevent shadowing.", indexURL),
					Engine:       "custom",
					AttackTactic: "initial-access",
					CWEID:        "CWE-829",
				})
				return
			}
		}
	}
}
