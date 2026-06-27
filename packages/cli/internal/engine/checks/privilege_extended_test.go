package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckPrivilege_NoFindings_Baseline(t *testing.T) {
	s := &parser.MCPServer{
		Name: "clean", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp/project"},
	}
	findings := CheckPrivilege(s)
	for _, f := range findings {
		t.Errorf("unexpected privilege finding for clean server: %s", f.CheckID)
	}
}

func TestCheckPrivilege_PE001_RootPath(t *testing.T) {
	// PE-001: node-like server with over-broad filesystem path
	s := &parser.MCPServer{
		Name: "fs-broad", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-001") {
		t.Error("want PE-001 for / root path on filesystem server")
	}
}

func TestCheckPrivilege_PE001_HomeDir(t *testing.T) {
	// /Users (macOS home parent) is a broad path
	s := &parser.MCPServer{
		Name: "fs-users", Command: "npx",
		Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/Users"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-001") {
		t.Error("want PE-001 for /Users broad path")
	}
}

func TestCheckPrivilege_PE002_SensitiveMount_DockerSock(t *testing.T) {
	s := &parser.MCPServer{
		Name: "docker-sock", Command: "docker",
		Args: []string{"run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "myimage:1.0"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-005") {
		t.Error("want PE-005 for docker socket mount")
	}
}

func TestCheckPrivilege_PE003_ProcMount(t *testing.T) {
	s := &parser.MCPServer{
		Name: "proc", Command: "docker",
		Args: []string{"run", "-v", "/proc:/proc", "myimage:1.0"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-005") {
		t.Error("want PE-005 for /proc mount")
	}
}

func TestCheckPrivilege_PE003_AdminEnvKey(t *testing.T) {
	// PE-003: admin/root credential pattern in env key name
	s := &parser.MCPServer{
		Name: "admin-key", Command: "node",
		Args: []string{"server.js"},
		Env:  map[string]string{"ADMIN_PASSWORD": "changeme123"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-003") {
		t.Error("want PE-003 for ADMIN_PASSWORD env key")
	}
}

func TestCheckPrivilege_PE005_PrivilegedFlag(t *testing.T) {
	s := &parser.MCPServer{
		Name: "priv", Command: "docker",
		Args: []string{"run", "--privileged", "myimage:1.0"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-005") {
		t.Error("want PE-005 for --privileged docker flag")
	}
}

func TestCheckPrivilege_PE006_SudoCommand(t *testing.T) {
	s := &parser.MCPServer{
		Name: "sudo-server", Command: "sudo",
		Args: []string{"node", "server.js"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-006") {
		t.Error("want PE-006 for sudo as command")
	}
}

func TestCheckPrivilege_PE007_DangerouslySkipPermissions(t *testing.T) {
	s := &parser.MCPServer{
		Name: "skip-perms", Command: "node",
		Args: []string{"server.js", "--dangerously-skip-permissions"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-007") {
		t.Error("want PE-007 for --dangerously-skip-permissions flag")
	}
}

func TestCheckPrivilege_PE008_PathTraversalArg(t *testing.T) {
	s := &parser.MCPServer{
		Name: "traversal", Command: "node",
		Args: []string{"server.js", "--root", "../../etc/passwd"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-008") {
		t.Error("want PE-008 for path traversal in args")
	}
}

func TestCheckPrivilege_PE009_CapAdd(t *testing.T) {
	s := &parser.MCPServer{
		Name: "cap", Command: "docker",
		Args: []string{"run", "--cap-add", "SYS_ADMIN", "myimage:1.0"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-009") {
		t.Error("want PE-009 for --cap-add in docker run")
	}
}

func TestCheckPrivilege_PE009_CapAddEqual(t *testing.T) {
	s := &parser.MCPServer{
		Name: "cap2", Command: "docker",
		Args: []string{"run", "--cap-add=NET_ADMIN", "myimage:1.0"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-009") {
		t.Error("want PE-009 for --cap-add=NET_ADMIN")
	}
}

func TestCheckPrivilege_PE005_CapAddAll_EqualForm(t *testing.T) {
	// --cap-add=all (equal form, lowercase) is in dockerDangerFlags → PE-005
	s := &parser.MCPServer{
		Name: "all-caps", Command: "docker",
		Args: []string{"run", "--cap-add=all", "myimage:1.0"},
	}
	if !hasCheckID(CheckPrivilege(s), "PE-005") {
		t.Error("want PE-005 for --cap-add=all (all capabilities via danger flag)")
	}
}

func TestCheckPrivilege_NetworkHost_Flagged(t *testing.T) {
	s := &parser.MCPServer{
		Name: "net-host", Command: "docker",
		Args: []string{"run", "--network=host", "myimage:1.0"},
	}
	// --network=host with --privileged or mount of /proc is very dangerous
	// Even standalone it should produce a finding (PE-002 or higher)
	findings := CheckPrivilege(s)
	if len(findings) == 0 {
		t.Error("want at least one privilege finding for --network=host")
	}
}

func TestCheckPrivilege_NormalDockerRun_Clean(t *testing.T) {
	s := &parser.MCPServer{
		Name: "normal-docker", Command: "docker",
		Args: []string{"run", "-v", "/home/user/projects:/projects", "myimage:1.2.3"},
	}
	// Standard volume mount with non-sensitive path, no privileged flags
	findings := CheckPrivilege(s)
	for _, f := range findings {
		if f.CheckID == "PE-005" || f.CheckID == "PE-009" {
			t.Errorf("unexpected %s for normal docker volume mount: %s", f.CheckID, f.Title)
		}
	}
}
