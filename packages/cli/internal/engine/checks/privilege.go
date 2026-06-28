package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

var broadPaths = []string{
	"/", "/Users", "/home", "/root", "/etc", "/var",
	"C:\\", "C:\\Users", "C:\\Windows", "/usr", "/opt",
}

var winDriveRootRE = regexp.MustCompile(`^[A-Za-z]:[/\\]?$`)

var dockerDangerFlags = map[string]string{
	"--privileged":                          "grants full host root access — all host devices + capabilities (equivalent to running as root on the host)",
	"--cap-add=all":                         "grants ALL Linux capabilities — equivalent to root on the container's namespace",
	"--network=host":                        "bypasses network isolation — container shares host network stack, can bind any host port",
	"--pid=host":                            "shares host PID namespace — container can observe/signal all host processes",
	"--ipc=host":                            "shares host IPC namespace — access to all host inter-process communication resources",
	"--security-opt=no-new-privileges=false": "allows privilege escalation via SUID binaries inside the container",
	"--userns=host":                         "disables user namespace isolation — container root is host root",
}

var dockerSensitiveMounts = []string{
	"/", "/etc", "/root", "/proc", "/sys", "/dev", "/run", "/boot",
	"/lib", "/lib64", "/usr", "/var/run", "/var/run/docker.sock",
}

var elevatedCmdBasenames = map[string]bool{
	"sudo": true, "su": true, "doas": true, "pkexec": true, "runas": true,
}

var sudoInArgsRE = regexp.MustCompile(`(?i)(?:^|[\s;|&])(sudo|doas|pkexec)\s`)

var permissionBypassFlags = map[string]bool{
	"--dangerously-skip-permissions":       true,
	"--dangerously-allow-all-permissions":  true,
	"--skip-permissions":                   true,
	"--allow-all-permissions":              true,
	"--bypass-permissions":                 true,
	"--no-permissions":                     true,
}

// dockerDangerousCaps: individual Linux capabilities that enable container breakout.
var dockerDangerousCaps = map[string]string{
	"sys_admin":      "enables mount/cgroup/ioctl — used in CVE-2022-0492 Docker cgroup escape and multiple container breakouts",
	"sys_ptrace":     "traces and modifies any process memory — enables container breakout via nsenter or memory injection",
	"net_admin":      "manipulates host network stack, routing, and firewall rules — can intercept or redirect all traffic",
	"dac_override":   "bypasses UNIX file permission bits — can read/write any file as if running as root",
	"dac_read_search": "bypasses read/execute permission checks — can traverse and read any directory or file",
	"sys_module":     "loads arbitrary kernel modules — direct kernel code execution, effectively root",
	"sys_rawio":      "raw block device I/O — can read/write disk sectors directly, bypassing filesystem permissions",
}

var adminEnvPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(sudo_password|root_token|root_password|admin_key|admin_password|admin_token)`),
	regexp.MustCompile(`(?i)(master_key|super_admin|superuser_password|master_password)`),
}

var dbReadOnlyMarkers = []string{
	"?mode=ro", "readonly=true", "read_only=true", "?readOnly=true",
}

var dbEnvRE = regexp.MustCompile(`(?i)(database_url|db_url|postgres_url|mysql_url|connection_string)`)
var writeServerRE = regexp.MustCompile(`(?i)(write|insert|update|delete|admin|migrate)`)
var pathTraversalRE = regexp.MustCompile(`(?:^|[/\\])\.\.[/\\]|(?:^|[/\\])\.\.(?:$)`)

var shellKeywords = []string{
	"--exec", "--shell", "--cmd", "--command",
	"--eval", "--run", "--execute",
	"/bin/sh", "/bin/bash", "cmd.exe", "powershell.exe",
}

func isBroadPath(arg, broad string) bool {
	if arg == broad {
		return true
	}
	sep := "/"
	if strings.Contains(broad, "\\") {
		sep = "\\"
	}
	if strings.HasPrefix(arg, broad+sep) || strings.HasPrefix(arg, broad+"/") {
		broadDepth := len(strings.Split(strings.ReplaceAll(strings.TrimRight(broad, "/\\"), "\\", "/"), "/"))
		argDepth := len(strings.Split(strings.ReplaceAll(strings.TrimRight(arg, "/\\"), "\\", "/"), "/"))
		return argDepth <= broadDepth+1
	}
	return false
}

// CheckPrivilege checks for privilege escalation risks (PE-001..009).
func CheckPrivilege(server *parser.MCPServer) []models.Finding {
	findings := []models.Finding{}

	// PE-001: Filesystem server with overly broad paths
	if isNodeLikeCommand(server) {
		seen001 := map[string]bool{}
		for _, arg := range server.Args {
			if seen001[arg] {
				continue
			}
			flagged := false
			for _, broad := range broadPaths {
				if isBroadPath(arg, broad) {
					flagged = true
					break
				}
			}
			if !flagged && winDriveRootRE.MatchString(arg) {
				flagged = true
			}
			if flagged {
				seen001[arg] = true
				findings = append(findings, models.Finding{
					CheckID:  "PE-001",
					Title:    fmt.Sprintf("Over-broad filesystem path: `%s`", arg),
					Detail:   fmt.Sprintf("Server `%s` has access to `%s`, an overly broad filesystem path. This grants the MCP server read/write access to far more files than it needs, including potentially sensitive system files, SSH keys, and credentials.", server.Name, arg),
					Severity: models.SeverityHigh,
					OWASP:    models.MCP02,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Restrict the path to the minimum required directory. Replace `%s` with only the specific project folder this server needs (e.g., `/Users/you/projects/myapp` instead of `/Users`).", arg),
					Engine:   "custom",
					CWEID:    "CWE-732",
				})
			}
		}
	}

	// PE-002: Shell execution capabilities in args
	for _, arg := range server.Args {
		argLower := strings.ToLower(arg)
		for _, kw := range shellKeywords {
			if strings.Contains(argLower, strings.ToLower(kw)) {
				findings = append(findings, models.Finding{
					CheckID:  "PE-002",
					Title:    fmt.Sprintf("Shell execution argument detected: `%s`", arg),
					Detail:   fmt.Sprintf("Server `%s` passes `%s` as an argument, suggesting it has shell execution capabilities. MCP servers with shell access can run arbitrary commands on your machine under your user account.", server.Name, arg),
					Severity: models.SeverityHigh,
					OWASP:    models.MCP05,
					ServerName: server.Name,
					Remediation: "Only allow shell-execution MCP servers from verified, well-reviewed sources. Audit the server's source code before installing. Consider using a more restricted alternative if shell access is not required.",
					Engine:   "custom",
					CWEID:    "CWE-77",
				})
				break
			}
		}
	}

	// PE-003: Admin/root credential patterns in env var keys
	seen003 := map[string]bool{}
	for envKey := range server.Env {
		if seen003[envKey] {
			continue
		}
		for _, pat := range adminEnvPatterns {
			if pat.MatchString(envKey) {
				seen003[envKey] = true
				findings = append(findings, models.Finding{
					CheckID:  "PE-003",
					Title:    fmt.Sprintf("Admin/root credential in env var: `%s`", envKey),
					Detail:   fmt.Sprintf("Server `%s` sets `%s`, suggesting it uses administrative or root-level credentials. Granting MCP servers admin access significantly expands the blast radius of any compromise.", server.Name, envKey),
					Severity: models.SeverityHigh,
					OWASP:    models.MCP02,
					ServerName: server.Name,
					Remediation: "Avoid giving MCP servers admin or root credentials. Create a least-privilege service account with only the permissions this specific server actually requires.",
					Engine:   "custom",
					CWEID:    "CWE-250",
				})
				break
			}
		}
	}

	// PE-004: Database connection without read-only constraint
	for envKey, envVal := range server.Env {
		if dbEnvRE.MatchString(envKey) && envVal != "" {
			hasRO := false
			for _, marker := range dbReadOnlyMarkers {
				if strings.Contains(strings.ToLower(envVal), marker) {
					hasRO = true
					break
				}
			}
			if !hasRO && !writeServerRE.MatchString(server.Name) {
				findings = append(findings, models.Finding{
					CheckID:  "PE-004",
					Title:    fmt.Sprintf("Database connection without read-only constraint in `%s`", envKey),
					Detail:   fmt.Sprintf("Server `%s` has a database connection string in `%s` without an explicit read-only flag. If this server only needs read access, granting implicit write access violates the principle of least privilege.", server.Name, envKey),
					Severity: models.SeverityMedium,
					OWASP:    models.MCP10,
					ServerName: server.Name,
					Remediation: "If this server only needs read access, use a read-only database user or append `?mode=ro` (SQLite) to the connection string. For PostgreSQL, create a role with only SELECT privileges.",
					Engine:   "custom",
					CWEID:    "CWE-732",
				})
			}
		}
	}

	// PE-005 + PE-009: Docker privilege flags and sensitive mounts
	dockerCmd := cmdBasename(server)
	if dockerCmd == "docker" {
		argsLower := make([]string, len(server.Args))
		for i, a := range server.Args {
			argsLower[i] = strings.ToLower(a)
		}
		argsJoined := strings.Join(argsLower, " ")

		pe005Done := false
		for flag, desc := range dockerDangerFlags {
			flagPrefix := strings.SplitN(flag, "=", 2)[0]
			if strings.Contains(argsJoined, flag) ||
				func() bool {
					for _, a := range argsLower {
						if strings.HasPrefix(a, flagPrefix+"=") {
							return true
						}
					}
					return false
				}() {
				findings = append(findings, models.Finding{
					CheckID:  "PE-005",
					Title:    fmt.Sprintf("Docker container with dangerous privilege flag: `%s`", flag),
					Detail:   fmt.Sprintf("Server `%s` runs a Docker container with the `%s` flag: %s. Dangerous Docker flags break the isolation between the container and the host, allowing an MCP server to access host files, processes, or gain root-equivalent capabilities — defeating the purpose of containerization.", server.Name, flag, desc),
					Severity: models.SeverityCritical,
					OWASP:    models.MCP05,
					ServerName: server.Name,
					Remediation: fmt.Sprintf("Remove `%s` from the Docker run command. Run the container without privileged access and with a minimal set of capabilities. Use `--cap-drop=ALL --cap-add=<only-what-you-need>` for fine-grained control.", flag),
					Engine:       "custom",
					AttackTactic: "privilege-escalation",
					CWEID:        "CWE-250",
				})
				pe005Done = true
				break
			}
		}

		// Docker sensitive mount check
		if !pe005Done {
			for i, arg := range server.Args {
				var mountSpec string
				if (arg == "-v" || arg == "--volume") && i+1 < len(server.Args) {
					mountSpec = server.Args[i+1]
				} else if strings.HasPrefix(arg, "--volume=") || strings.HasPrefix(arg, "-v=") {
					mountSpec = strings.SplitN(arg, "=", 2)[1]
				} else if strings.HasPrefix(arg, "--mount") {
					mountSpec = arg
				}
				if mountSpec == "" {
					continue
				}
				hostPath := strings.SplitN(mountSpec, ":", 2)[0]
				if hostPath == "" {
					hostPath = "/"
				}
				hostPath = strings.TrimRight(hostPath, "/")
				if hostPath == "" {
					hostPath = "/"
				}
				for _, sensitive := range dockerSensitiveMounts {
					if hostPath == sensitive || strings.HasPrefix(hostPath, sensitive+"/") {
						findings = append(findings, models.Finding{
							CheckID:  "PE-005",
							Title:    fmt.Sprintf("Docker container mounts sensitive host path: `%s`", hostPath),
							Detail:   fmt.Sprintf("Server `%s` mounts `%s` from the host into the container. This gives the containerized MCP server read/write access to sensitive host files. Mounting `/etc` exposes credentials; `/` exposes everything; `/var/run/docker.sock` gives the container control over the Docker daemon itself.", server.Name, hostPath),
							Severity: models.SeverityCritical,
							OWASP:    models.MCP05,
							ServerName: server.Name,
							Remediation: fmt.Sprintf("Replace the host mount `%s:...` with a specific subdirectory containing only the files this server actually needs. Never mount system directories, /etc, /root, or the Docker socket into MCP containers.", hostPath),
							Engine:       "custom",
							AttackTactic: "privilege-escalation",
							CWEID:        "CWE-732",
						})
						break
					}
				}
			}
		}

		// PE-009: Specific dangerous Linux capabilities via --cap-add
		hasRun := false
		for _, a := range argsLower {
			if a == "run" {
				hasRun = true
				break
			}
		}
		if hasRun {
			for i, arg := range server.Args {
				argL := strings.ToLower(arg)
				var capRaw string
				if strings.HasPrefix(argL, "--cap-add=") {
					capRaw = strings.TrimPrefix(argL, "--cap-add=")
				} else if argL == "--cap-add" && i+1 < len(server.Args) {
					capRaw = strings.ToLower(server.Args[i+1])
				}
				if capRaw == "" {
					continue
				}
				capKey := strings.TrimPrefix(capRaw, "cap_")
				if risk, ok := dockerDangerousCaps[capKey]; ok {
					findings = append(findings, models.Finding{
						CheckID:  "PE-009",
						Title:    fmt.Sprintf("Docker container grants dangerous Linux capability: `%s`", strings.ToUpper(capRaw)),
						Detail:   fmt.Sprintf("Server `%s` adds the `%s` Linux capability to its Docker container via `--cap-add`. Risk: %s. Each of these capabilities independently enables known container breakout techniques — attackers only need one to escape the container and reach the host.", server.Name, strings.ToUpper(capRaw), risk),
						Severity: models.SeverityHigh,
						OWASP:    models.MCP02,
						ServerName: server.Name,
						Remediation: fmt.Sprintf("Remove `--cap-add=%s` from the Docker run command. Start with `--cap-drop=ALL` and add only the minimum capabilities the server actually requires. Most MCP server workloads need zero additional capabilities.", strings.ToUpper(capRaw)),
						Engine:       "custom",
						AttackTactic: "privilege-escalation",
						CWEID:        "CWE-250",
					})
					break
				}
			}
		}
	}

	// PE-006: Server command requests elevated OS privileges
	cmdBase := cmdBasename(server)
	if elevatedCmdBasenames[cmdBase] {
		findings = append(findings, models.Finding{
			CheckID:  "PE-006",
			Title:    fmt.Sprintf("MCP server runs with elevated privileges: `%s`", server.Command),
			Detail:   fmt.Sprintf("Server `%s` uses `%s` as its command, requesting elevated operating system privileges (root/admin). Running an MCP server as sudo gives it unrestricted host access — any tool poisoning, prompt injection, or supply chain attack against this server would gain root-level execution capability.", server.Name, server.Command),
			Severity: models.SeverityCritical,
			OWASP:    models.MCP02,
			ServerName: server.Name,
			Remediation: fmt.Sprintf("Remove `%s` and run the MCP server under a regular user account. If the server genuinely requires root access for a specific operation, isolate that operation in a separate privileged process and grant only the minimum required capability.", server.Command),
			Engine:       "custom",
			AttackTactic: "privilege-escalation",
			CWEID:        "CWE-250",
		})
	} else {
		// Also check args for sudo usage
		fullArgs := strings.Join(server.Args, " ")
		if m := sudoInArgsRE.FindStringSubmatch(fullArgs); len(m) > 1 {
			findings = append(findings, models.Finding{
				CheckID:  "PE-006",
				Title:    fmt.Sprintf("Privilege escalation via `%s` in server arguments", m[1]),
				Detail:   fmt.Sprintf("Server `%s` argument string contains `%s`, which would execute subsequent commands with elevated privileges. This is often used in post-install scripts or shell wrappers to silently escalate from user to root during MCP server execution.", server.Name, m[1]),
				Severity: models.SeverityHigh,
				OWASP:    models.MCP02,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Remove the `%s` call from server arguments. MCP servers should operate entirely within user-level permissions. If a privileged operation is required, extract it into a separate, auditable process with minimal capabilities.", m[1]),
				Engine:       "custom",
				AttackTactic: "privilege-escalation",
				CWEID:        "CWE-250",
			})
		}
	}

	// PE-007: Permission bypass flag in server args
	for _, arg := range server.Args {
		if permissionBypassFlags[strings.ToLower(arg)] {
			findings = append(findings, models.Finding{
				CheckID:  "PE-007",
				Title:    fmt.Sprintf("Permission bypass flag in server args: `%s`", arg),
				Detail:   fmt.Sprintf("Server `%s` passes `%s` in its arguments. This flag instructs the MCP client to automatically approve ALL tool calls from this server without showing the user a confirmation prompt. The MCP permission model exists specifically to prevent unauthorized tool calls — bypassing it means any prompt injection, tool poisoning, or supply chain attack against this server executes silently with zero user interaction. This flag is intended for trusted local development only; it must never appear in shared, team, or production configurations.", server.Name, arg),
				Severity: models.SeverityCritical,
				OWASP:    models.MCP02,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Remove `%s` from the server args immediately. The user permission prompt is a primary defense layer for MCP security — it gives users the opportunity to review and block unexpected tool calls. If you need to reduce approval friction for trusted servers, use per-tool approval policies rather than blanket bypass flags.", arg),
				Engine:       "custom",
				AttackTactic: "defense-evasion",
				CWEID:        "CWE-284",
			})
			break
		}
	}

	// PE-008: Path traversal sequences in server args
	for _, arg := range server.Args {
		if pathTraversalRE.MatchString(arg) {
			snip := arg
			if len(snip) > 80 {
				snip = snip[:80]
			}
			findings = append(findings, models.Finding{
				CheckID:  "PE-008",
				Title:    fmt.Sprintf("Path traversal sequence in server arg: `%s`", snip),
				Detail:   fmt.Sprintf("Server `%s` has an argument containing `..` path traversal: `%s`. Legitimate MCP configs always use absolute, canonical paths. The presence of `..` sequences suggests either a misconfiguration or an injection attempt to escape the intended directory sandbox — for example, `/home/user/projects/../../etc/passwd` resolves to `/etc/passwd`. (CVE reference: Anthropic Git MCP server path traversal + argument injection, Nov 2025)", server.Name, snip),
				Severity: models.SeverityHigh,
				OWASP:    models.MCP02,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Replace the argument `%s` with the resolved absolute path (run `realpath` on the intended directory). Never use `..` sequences in MCP filesystem server arguments. If this argument came from external input, ensure it is canonicalized before use.", snip),
				Engine:       "custom",
				AttackTactic: "privilege-escalation",
				CWEID:        "CWE-22",
			})
			break
		}
	}

	// PE-010: LD_PRELOAD / DYLD_INSERT_LIBRARIES and library path overrides in env vars.
	// These variables inject arbitrary shared libraries into every process spawned by the server.
	// LD_PRELOAD / DYLD_INSERT_LIBRARIES → CRITICAL (full code injection primitive)
	// LD_LIBRARY_PATH / DYLD_LIBRARY_PATH → HIGH (attacker-controlled search path)
	// Legitimate MCP servers have no reason to override the dynamic linker search path.
	pe010Critical := map[string]bool{"ld_preload": true, "dyld_insert_libraries": true}
	pe010High := map[string]bool{"ld_library_path": true, "dyld_library_path": true, "dyld_fallback_library_path": true}
	for key, value := range server.Env {
		if value == "" {
			continue
		}
		lk := strings.ToLower(key)
		if pe010Critical[lk] {
			findings = append(findings, models.Finding{
				CheckID:  "PE-010",
				Title:    fmt.Sprintf("Code injection via `%s` dynamic linker override in `%s`", key, server.Name),
				Detail:   fmt.Sprintf("Server `%s` sets `%s=%q`. `%s` causes the dynamic linker to inject the specified shared library into every process the server spawns. An attacker who controls this value or the file it points to achieves arbitrary code execution with the MCP server's privileges. No legitimate MCP server requires this variable.", server.Name, key, value, key),
				Severity: models.SeverityCritical,
				OWASP:    models.MCP05,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Remove `%s` from this server's env block. If a native library dependency requires it, link the library statically or use a container with a fixed, read-only library path.", key),
				Engine:       "custom",
				AttackTactic: "privilege-escalation",
				CWEID:        "CWE-427",
			})
			break
		}
		if pe010High[lk] {
			findings = append(findings, models.Finding{
				CheckID:  "PE-010",
				Title:    fmt.Sprintf("Library search path override: `%s` set in `%s`", key, server.Name),
				Detail:   fmt.Sprintf("Server `%s` sets `%s=%q`. This prepends attacker-controlled directories to the linker search path. A malicious shared library in that directory can replace a legitimate system library at load time. If the path is world-writable (e.g., /tmp), this is a full privilege escalation primitive.", server.Name, key, value),
				Severity: models.SeverityHigh,
				OWASP:    models.MCP05,
				ServerName: server.Name,
				Remediation: fmt.Sprintf("Remove `%s` from this server's env block. Ensure the server binary links against system libraries directly.", key),
				Engine:       "custom",
				AttackTactic: "privilege-escalation",
				CWEID:        "CWE-427",
			})
			break
		}
	}

	return findings
}
