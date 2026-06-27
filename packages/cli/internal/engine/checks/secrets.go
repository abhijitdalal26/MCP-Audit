package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// checkCWESecrets maps check IDs to their CWE identifiers.
var checkCWESecrets = map[string]string{
	"SEC-001": "CWE-798", // Hard-Coded Credentials
	"SEC-002": "CWE-798",
	"SEC-003": "CWE-798",
	"SEC-004": "CWE-798",
	"SEC-005": "CWE-312", // Cleartext Storage
	"SEC-006": "CWE-1104",
	"SEC-007": "CWE-918", // SSRF
	"SEC-008": "CWE-312",
}

type valuePattern struct {
	checkID  string
	title    string
	re       *regexp.Regexp
	severity models.Severity
}

// valuePatterns mirrors Python's _VALUE_PATTERNS — checked against field values.
var valuePatterns = []valuePattern{
	// SEC-001: AWS
	{"SEC-001", "AWS Access Key ID", regexp.MustCompile(`AKIA[0-9A-Z]{16}`), models.SeverityCritical},
	// SEC-002: VCS tokens
	{"SEC-002", "GitHub Personal Access Token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`), models.SeverityCritical},
	{"SEC-002", "GitHub OAuth Token", regexp.MustCompile(`gho_[A-Za-z0-9]{36,}`), models.SeverityCritical},
	{"SEC-002", "GitHub App Token", regexp.MustCompile(`ghs_[A-Za-z0-9]{36,}`), models.SeverityCritical},
	{"SEC-002", "GitHub Fine-Grained PAT", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82,}`), models.SeverityCritical},
	{"SEC-002", "GitLab Personal Access Token", regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`), models.SeverityCritical},
	// SEC-003: DB connection strings
	{"SEC-003", "PostgreSQL connection string with credentials", regexp.MustCompile(`postgres(?:ql)?://[^:@\s]+:[^@\s]+@`), models.SeverityCritical},
	{"SEC-003", "MySQL connection string with credentials", regexp.MustCompile(`mysql://[^:@\s]+:[^@\s]+@`), models.SeverityCritical},
	{"SEC-003", "MongoDB connection string with credentials", regexp.MustCompile(`mongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@`), models.SeverityCritical},
	{"SEC-003", "Redis connection string with credentials", regexp.MustCompile(`redis://:[^@\s]+@`), models.SeverityHigh},
	{"SEC-003", "HTTP Basic Auth credentials embedded in URL", regexp.MustCompile(`https?://[^:@\s]{1,64}:[^@\s]{3,}@[a-zA-Z0-9]`), models.SeverityHigh},
	// SEC-007: Cloud instance metadata endpoint (SSRF / credential theft)
	{"SEC-007", "Cloud instance metadata endpoint (IMDS) URL",
		regexp.MustCompile(`(?i)169\.254\.169\.254|169\.254\.170\.2|metadata\.google\.internal`), models.SeverityCritical},
	// SEC-004: API keys
	{"SEC-004", "OpenAI API key", regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9_-]{40,}`), models.SeverityHigh},
	{"SEC-004", "Anthropic API key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{32,}`), models.SeverityHigh},
	{"SEC-004", "Stripe live secret key", regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`), models.SeverityHigh},
	{"SEC-004", "Stripe live publishable key", regexp.MustCompile(`pk_live_[A-Za-z0-9]{24,}`), models.SeverityHigh},
	{"SEC-004", "Slack bot token", regexp.MustCompile(`xoxb-[0-9A-Za-z-]{40,}`), models.SeverityHigh},
	{"SEC-004", "Slack OAuth token", regexp.MustCompile(`xoxp-[0-9A-Za-z-]{40,}`), models.SeverityHigh},
	{"SEC-004", "Slack app-level token", regexp.MustCompile(`xapp-[0-9A-Za-z-]{80,}`), models.SeverityHigh},
	{"SEC-004", "npm access token", regexp.MustCompile(`npm_[A-Za-z0-9]{36,}`), models.SeverityHigh},
	{"SEC-004", "Hugging Face access token", regexp.MustCompile(`hf_[A-Za-z0-9]{36,}`), models.SeverityHigh},
	{"SEC-004", "Replicate API token", regexp.MustCompile(`r8_[A-Za-z0-9]{40,}`), models.SeverityHigh},
	{"SEC-004", "Firebase / GCP API key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`), models.SeverityHigh},
	{"SEC-004", "Twilio Account SID", regexp.MustCompile(`AC[a-zA-Z0-9]{32}`), models.SeverityHigh},
	{"SEC-004", "SendGrid API key", regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`), models.SeverityHigh},
	{"SEC-004", "Shopify shared secret / access token", regexp.MustCompile(`shp(?:ss|at|ca)_[a-fA-F0-9]{32}`), models.SeverityHigh},
	// SEC-005: JWT / SSH keys
	{"SEC-005", "JWT token (encoded)", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`), models.SeverityHigh},
	{"SEC-005", "SSH private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`), models.SeverityCritical},
}

type varNamePattern struct {
	checkID  string
	re       *regexp.Regexp
	severity models.Severity
}

// varNamePatterns checks env/header key names regardless of value content.
var varNamePatterns = []varNamePattern{
	{"SEC-001", regexp.MustCompile(`(?i)^(aws_access_key_id|aws_secret_access_key|aws_session_token)$`), models.SeverityCritical},
	{"SEC-003", regexp.MustCompile(`(?i)(database_url|db_password|postgres_password|mysql_password|db_url|connection_string)`), models.SeverityCritical},
	{"SEC-003", regexp.MustCompile(`(?i)(admin_password|root_password|sudo_password)`), models.SeverityCritical},
	{"SEC-005", regexp.MustCompile(`(?i)(jwt_secret|signing_key|jwt_signing|secret_key|signing_secret)`), models.SeverityHigh},
	{"SEC-004", regexp.MustCompile(`(?i)^(openai_api_key|anthropic_api_key|stripe_secret_key|stripe_sk)$`), models.SeverityHigh},
	{"SEC-004", regexp.MustCompile(`(?i)^(slack_bot_token|slack_token|slack_oauth_token|slack_signing_secret)$`), models.SeverityHigh},
	{"SEC-004", regexp.MustCompile(`(?i)^(npm_token|npm_auth_token)$`), models.SeverityHigh},
	{"SEC-004", regexp.MustCompile(`(?i)^(hf_token|hugging_face_hub_token|huggingface_token)$`), models.SeverityHigh},
	{"SEC-004", regexp.MustCompile(`(?i)^(replicate_api_token|replicate_api_key)$`), models.SeverityHigh},
	{"SEC-004", regexp.MustCompile(`(?i)^(firebase_api_key|firebase_service_account)$`), models.SeverityHigh},
	{"SEC-004", regexp.MustCompile(`(?i)^(twilio_auth_token|twilio_account_sid)$`), models.SeverityHigh},
	{"SEC-004", regexp.MustCompile(`(?i)^(sendgrid_api_key)$`), models.SeverityHigh},
	{"SEC-004", regexp.MustCompile(`(?i)^(shopify_access_token|shopify_api_secret)$`), models.SeverityHigh},
}

var (
	distTagRE    = regexp.MustCompile(`(?i)^(latest|next|beta|alpha|canary|rc|nightly|stable|dev|edge|experimental)$`)
	semverStartRE = regexp.MustCompile(`^\d+\.`)
)

// CheckSecrets scans a server for hardcoded credentials (SEC-001..008).
func CheckSecrets(server *parser.MCPServer) []models.Finding {
	findings := []models.Finding{}
	seen := map[string]bool{}

	// Env vars
	for k, v := range server.Env {
		scanCredentialField(&findings, seen, server, k, v, "environment variable", "env")
	}

	// HTTP headers
	for k, v := range server.Headers {
		scanCredentialField(&findings, seen, server, k, v, "HTTP header", "header")
	}

	// Command args — scan values for embedded secrets
	for i, arg := range server.Args {
		if arg == "" || strings.HasPrefix(arg, "-") || placeholderRE.MatchString(arg) {
			continue
		}
		for _, vp := range valuePatterns {
			dedup := fmt.Sprintf("%s:%s:arg:%d:val", vp.checkID, server.Name, i)
			if seen[dedup] {
				continue
			}
			if vp.re.MatchString(arg) {
				seen[dedup] = true
				findings = append(findings, models.Finding{
					CheckID:  vp.checkID,
					Title:    fmt.Sprintf("%s hardcoded in command args", vp.title),
					Detail:   fmt.Sprintf("Server `%s` has what appears to be a %s hardcoded directly in the command args (arg #%d: `%s`). Credentials passed as command-line arguments appear in process listings, shell history, and are readable by anyone with file system access to the config.", server.Name, strings.ToLower(vp.title), i+1, mask(arg)),
					Severity: vp.severity,
					OWASP:    models.MCP01,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Move the %s to an environment variable instead. Replace the inline value with an env var reference (e.g., `$API_KEY`) so the plaintext never appears in the config or process table.", strings.ToLower(vp.title)),
					Engine:   "custom",
					CWEID:    checkCWESecrets[vp.checkID],
				})
				break
			}
		}
	}

	// SEC-008: Credentials embedded in the server url: field
	if server.URL != "" && !placeholderRE.MatchString(server.URL) {
		for _, vp := range valuePatterns {
			dedup := fmt.Sprintf("SEC-008:%s:url:%s", server.Name, vp.checkID)
			if !seen[dedup] && vp.re.MatchString(server.URL) {
				seen[dedup] = true
				findings = append(findings, models.Finding{
					CheckID:  "SEC-008",
					Title:    fmt.Sprintf("%s embedded in server URL", vp.title),
					Detail:   fmt.Sprintf("Server `%s` has what appears to be a %s embedded directly in its `url` field (`%s`). Credentials in URLs are recorded by web servers, proxies, and load balancers; appear in browser history if the URL is opened; and are visible to anyone who reads the MCP config file. MCP configs are frequently synced via cloud backup (iCloud, Google Drive) or accidentally committed to git.", server.Name, strings.ToLower(vp.title), mask(server.URL)),
					Severity: vp.severity,
					OWASP:    models.MCP01,
					ServerName: server.Name,
					Remediation: "Move the credential out of the URL and into a dedicated environment variable. Most API providers accept tokens via a header (e.g., `Authorization: Bearer $TOKEN`) rather than requiring them in the URL. Reference the variable with `$ENV_VAR` syntax so the plaintext never appears in the config file.",
					Engine:   "custom",
					CWEID:    "CWE-312",
				})
				break
			}
		}
	}

	// SEC-006: Unpinned package versions (rug pull risk)
	for _, arg := range server.Args {
		if isPackageArg(arg) && !isPinned(arg) {
			findings = append(findings, models.Finding{
				CheckID:  "SEC-006",
				Title:    fmt.Sprintf("Unpinned package version: `%s`", arg),
				Detail:   fmt.Sprintf("Server `%s` installs `%s` without a pinned version. Unpinned packages are vulnerable to rug pull attacks where a malicious update silently replaces the package after you've reviewed it.", server.Name, arg),
				Severity: models.SeverityMedium,
				OWASP:    models.MCP04,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Pin the package to an exact version, e.g. `%s@x.y.z`. Check the latest stable version on npmjs.com and commit that exact version string.", arg),
				Engine:   "custom",
				CWEID:    "CWE-1104",
			})
		}
	}

	return findings
}

func scanCredentialField(findings *[]models.Finding, seen map[string]bool, server *parser.MCPServer, fieldKey, fieldVal, fieldLabel, fieldKind string) {
	if fieldVal == "" || placeholderRE.MatchString(fieldVal) {
		return
	}

	// Check value against secret patterns
	for _, vp := range valuePatterns {
		dedup := fmt.Sprintf("%s:%s:%s:%s:val", vp.checkID, server.Name, fieldKind, fieldKey)
		if seen[dedup] {
			continue
		}
		if vp.re.MatchString(fieldVal) {
			seen[dedup] = true
			*findings = append(*findings, models.Finding{
				CheckID:  vp.checkID,
				Title:    fmt.Sprintf("%s hardcoded in `%s` (%s)", vp.title, fieldKey, fieldKind),
				Detail:   fmt.Sprintf("Server `%s` has what appears to be a %s hardcoded in %s `%s` (value: `%s`). Credentials in MCP config files are readable by anyone with file system access and are often synced to cloud backup or version control.", server.Name, strings.ToLower(vp.title), fieldLabel, fieldKey, mask(fieldVal)),
				Severity: vp.severity,
				OWASP:    models.MCP01,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Remove the hardcoded value from `%s`. Reference a secrets manager or environment variable substitution so the plaintext never appears in the config file.", fieldKey),
				Engine:   "custom",
				CWEID:    checkCWESecrets[vp.checkID],
			})
			break
		}
	}

	// Check key name for sensitive variable patterns
	dedupName := fmt.Sprintf("name:%s:%s:%s", server.Name, fieldKind, fieldKey)
	if !seen[dedupName] {
		for _, np := range varNamePatterns {
			if np.re.MatchString(fieldKey) {
				seen[dedupName] = true
				*findings = append(*findings, models.Finding{
					CheckID:  np.checkID,
					Title:    fmt.Sprintf("Sensitive %s `%s` with hardcoded value", fieldKind, fieldKey),
					Detail:   fmt.Sprintf("Server `%s` sets `%s` in %s, which by name indicates it holds a secret credential. Hardcoding secrets in MCP configs risks accidental exposure in backups, logs, or version control.", server.Name, fieldKey, fieldLabel),
					Severity: np.severity,
					OWASP:    models.MCP01,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Ensure `%s` is not stored in plaintext in the config. Use environment variable substitution or a secrets management tool.", fieldKey),
					Engine:   "custom",
					CWEID:    checkCWESecrets[np.checkID],
				})
				break
			}
		}
	}
}

// IsPackageArg and IsPinned are exported for use by the scanner.
func IsPackageArg(arg string) bool { return isPackageArg(arg) }
func IsPinned(arg string) bool     { return isPinned(arg) }

// isPackageArg returns true if the arg looks like a package name (used for SEC-006).
func isPackageArg(arg string) bool {
	if strings.HasPrefix(arg, "-") {
		return false
	}
	// Must be a package-like string: starts with @ (scoped) or has no path separator
	if strings.HasPrefix(arg, "@") {
		return true
	}
	if strings.Contains(arg, "/") || strings.HasPrefix(arg, "C:\\") || strings.HasPrefix(arg, "/") {
		return false
	}
	return true
}

// extractVersionTag returns the version portion of a package@version string, or "".
func extractVersionTag(arg string) string {
	if strings.HasPrefix(arg, "@") {
		// @scope/pkg@ver → split on @ after the scope
		rest := arg[1:] // "scope/pkg@ver"
		idx := strings.Index(rest, "@")
		if idx == -1 {
			return ""
		}
		return rest[idx+1:]
	}
	idx := strings.Index(arg, "@")
	if idx == -1 {
		return ""
	}
	return arg[idx+1:]
}

// isPinned returns true only if the package is pinned to a specific semver.
func isPinned(arg string) bool {
	version := extractVersionTag(arg)
	if version == "" {
		return false
	}
	if distTagRE.MatchString(version) {
		return false // @latest, @next, etc. are NOT pinned
	}
	return semverStartRE.MatchString(version) // must start with digits
}
