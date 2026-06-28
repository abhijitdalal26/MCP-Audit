package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/models"
	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckPrivilege_Clean(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "clean",
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/tmp/project"},
	}
	findings := CheckPrivilege(s)
	if len(findings) != 0 {
		t.Errorf("want 0, got %d: %v", len(findings), findings)
	}
}

func TestCheckPrivilege_PE001_BroadPath(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "fs-server",
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/"},
	}
	findings := CheckPrivilege(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "PE-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PE-001 for / path, got: %v", findings)
	}
}

// Docker --privileged maps to PE-005 in the Go engine.
func TestCheckPrivilege_PE005_DockerPrivileged(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "docker-server",
		Command: "docker",
		Args:    []string{"run", "--privileged", "myimage:1.0"},
	}
	findings := CheckPrivilege(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "PE-005" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PE-005 for --privileged, got: %v", findings)
	}
}

// Docker sensitive mount (/var/run/docker.sock) also maps to PE-005.
func TestCheckPrivilege_PE005_SensitiveMount(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "docker-server",
		Command: "docker",
		Args:    []string{"run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "myimage:1.0"},
	}
	findings := CheckPrivilege(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "PE-005" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PE-005 for docker.sock mount, got: %v", findings)
	}
}

// sudo as command maps to PE-006.
func TestCheckPrivilege_PE006_Sudo(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "elevated",
		Command: "sudo",
		Args:    []string{"node", "server.js"},
	}
	findings := CheckPrivilege(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "PE-006" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PE-006 for sudo, got: %v", findings)
	}
}

// --dangerously-skip-permissions maps to PE-007.
func TestCheckPrivilege_PE007_PermissionBypass(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "cursor-bypass",
		Command: "npx",
		Args:    []string{"-y", "some-server", "--dangerously-skip-permissions"},
	}
	findings := CheckPrivilege(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "PE-007" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PE-007 for --dangerously-skip-permissions, got: %v", findings)
	}
}

// Path traversal `..` in args maps to PE-008.
func TestCheckPrivilege_PE008_PathTraversal(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "traversal",
		Command: "node",
		Args:    []string{"server.js", "--root", "../../etc/passwd"},
	}
	findings := CheckPrivilege(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "PE-008" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PE-008 for path traversal, got: %v", findings)
	}
}

// --network=host maps to PE-005 (dangerous docker flag).
func TestCheckPrivilege_PE005_NetworkHost(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "net-host",
		Command: "docker",
		Args:    []string{"run", "--network=host", "myimage:1.0"},
	}
	findings := CheckPrivilege(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "PE-005" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PE-005 for --network=host, got: %v", findings)
	}
}

// --cap-add=SYS_ADMIN maps to PE-009.
func TestCheckPrivilege_PE009_DangerousCap(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "docker-cap",
		Command: "docker",
		Args:    []string{"run", "--cap-add=SYS_ADMIN", "myimage:1.0"},
	}
	findings := CheckPrivilege(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "PE-009" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PE-009 for SYS_ADMIN cap, got: %v", findings)
	}
}

// sudo appearing inside args (not command) also triggers PE-006.
func TestCheckPrivilege_PE006_SudoInArgs(t *testing.T) {
	s := &parser.MCPServer{
		Name:    "elevated-via-args",
		Command: "bash",
		Args:    []string{"-c", "sudo node server.js"},
	}
	findings := CheckPrivilege(s)
	found := false
	for _, f := range findings {
		if f.CheckID == "PE-006" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected PE-006 for sudo in args, got: %v", findings)
	}
}

func TestCheckPrivilege_PE010_LdPreload_Critical(t *testing.T) {
	s := &parser.MCPServer{
		Name: "evil", Command: "node", Args: []string{"server.js"},
		Env: map[string]string{"LD_PRELOAD": "/tmp/evil.so"},
	}
	findings := CheckPrivilege(s)
	pe10 := filterID(findings, "PE-010")
	if len(pe10) == 0 {
		t.Error("want PE-010 for LD_PRELOAD")
	}
	if pe10[0].Severity != "critical" {
		t.Errorf("want critical, got %s", pe10[0].Severity)
	}
}

func TestCheckPrivilege_PE010_DyldInsertLibraries_Critical(t *testing.T) {
	s := &parser.MCPServer{
		Name: "mac-evil", Command: "node", Args: []string{"server.js"},
		Env: map[string]string{"DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib"},
	}
	findings := CheckPrivilege(s)
	pe10 := filterID(findings, "PE-010")
	if len(pe10) == 0 {
		t.Error("want PE-010 for DYLD_INSERT_LIBRARIES")
	}
	if pe10[0].Severity != "critical" {
		t.Errorf("want critical, got %s", pe10[0].Severity)
	}
}

func TestCheckPrivilege_PE010_LdLibraryPath_High(t *testing.T) {
	s := &parser.MCPServer{
		Name: "suspicious", Command: "node", Args: []string{"server.js"},
		Env: map[string]string{"LD_LIBRARY_PATH": "/tmp:/lib"},
	}
	findings := CheckPrivilege(s)
	pe10 := filterID(findings, "PE-010")
	if len(pe10) == 0 {
		t.Error("want PE-010 for LD_LIBRARY_PATH")
	}
	if pe10[0].Severity != "high" {
		t.Errorf("want high, got %s", pe10[0].Severity)
	}
}

func TestCheckPrivilege_PE010_NoFire_NormalEnv(t *testing.T) {
	s := &parser.MCPServer{
		Name: "normal", Command: "node", Args: []string{"server.js"},
		Env: map[string]string{"NODE_ENV": "production", "PORT": "3000"},
	}
	findings := CheckPrivilege(s)
	if len(filterID(findings, "PE-010")) > 0 {
		t.Error("PE-010 must not fire for normal env vars")
	}
}

func filterID(findings []models.Finding, id string) []models.Finding {
	var out []models.Finding
	for _, f := range findings {
		if f.CheckID == id {
			out = append(out, f)
		}
	}
	return out
}
