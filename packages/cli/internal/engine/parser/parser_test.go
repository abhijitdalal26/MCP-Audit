package parser

import (
	"strings"
	"testing"
)

func TestStripJSONCComments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"no comments", `{"key": "value"}`, `{"key": "value"}`},
		{"line comment", `{"key": "value" // comment` + "\n}", `{"key": "value" ` + "\n}"},
		{"block comment", `{"key": /* comment */ "value"}`, `{"key":  "value"}`},
		{"comment in string not stripped", `{"key": "// not a comment"}`, `{"key": "// not a comment"}`},
		{"escaped quote in string", `{"key": "say \"hi\" // not comment"}`, `{"key": "say \"hi\" // not comment"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := stripJSONCComments(tc.input)
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseConfig_Basic(t *testing.T) {
	cfg := `{
		"mcpServers": {
			"test-server": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
				"env": {"API_KEY": "secret123"}
			}
		}
	}`
	result, err := ParseConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(result.Servers))
	}
	s := result.Servers[0]
	if s.Name != "test-server" {
		t.Errorf("name: want test-server, got %s", s.Name)
	}
	if s.Command != "npx" {
		t.Errorf("command: want npx, got %s", s.Command)
	}
	if len(s.Args) != 3 {
		t.Errorf("args: want 3, got %d", len(s.Args))
	}
	if s.Env["API_KEY"] != "secret123" {
		t.Errorf("env: want secret123, got %s", s.Env["API_KEY"])
	}
}

func TestParseConfig_NoServers(t *testing.T) {
	cfg := `{}`
	result, err := ParseConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Servers) != 0 {
		t.Errorf("want 0 servers, got %d", len(result.Servers))
	}
}

func TestParseConfig_InvalidJSON(t *testing.T) {
	_, err := ParseConfig(`not json`)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseConfig_DisabledServer(t *testing.T) {
	cfg := `{"mcpServers": {"s": {"command": "npx", "disabled": true}}}`
	result, err := ParseConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Servers[0].Disabled {
		t.Error("want disabled=true")
	}
}

func TestParseConfig_HTTPServer(t *testing.T) {
	cfg := `{"mcpServers": {"remote": {"url": "https://example.com/mcp", "transport": "sse", "headers": {"Authorization": "Bearer tok"}}}}`
	result, err := ParseConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := result.Servers[0]
	if s.URL != "https://example.com/mcp" {
		t.Errorf("url: got %s", s.URL)
	}
	if s.Headers["Authorization"] != "Bearer tok" {
		t.Errorf("header: got %s", s.Headers["Authorization"])
	}
}

func TestParseConfig_JSONC(t *testing.T) {
	cfg := `{
		// This is a comment
		"mcpServers": {
			"s": {
				"command": "node", /* block comment */
				"args": []
			}
		}
	}`
	result, err := ParseConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(result.Servers))
	}
}

func TestParseConfig_ConfigHash(t *testing.T) {
	cfg := `{"mcpServers": {}}`
	r1, _ := ParseConfig(cfg)
	r2, _ := ParseConfig(cfg)
	if r1.ConfigHash != r2.ConfigHash {
		t.Error("same input should produce same hash")
	}
	if len(r1.ConfigHash) != 16 {
		t.Errorf("hash length want 16, got %d", len(r1.ConfigHash))
	}
}

func TestParseConfig_AutoApprove(t *testing.T) {
	cfg := `{"mcpServers": {"s": {"command": "npx", "autoApprove": ["read_file", "list_dir"]}}}`
	result, err := ParseConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	s := result.Servers[0]
	if s.AutoApprove == nil || len(s.AutoApprove.List) != 2 {
		t.Error("want autoApprove list with 2 items")
	}
}

func TestParseConfig_MultipleServers(t *testing.T) {
	cfg := `{"mcpServers": {"a": {"command": "node"}, "b": {"command": "python3"}, "c": {"url": "http://localhost:9000"}}}`
	result, err := ParseConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Servers) != 3 {
		t.Errorf("want 3 servers, got %d", len(result.Servers))
	}
}

func TestParseConfig_AlwaysAllow(t *testing.T) {
	// Cursor format uses alwaysAllow instead of autoApprove
	cfg := `{"mcpServers": {"s": {"command": "npx", "alwaysAllow": ["*"]}}}`
	result, err := ParseConfig(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Servers[0].AutoApprove == nil {
		t.Error("want alwaysAllow parsed into AutoApprove")
	}
}

func TestExtractFirstJSONObject(t *testing.T) {
	input := `   {"key": "val"}  extra`
	got := extractFirstJSONObject(input)
	if !strings.HasPrefix(got, "{") || !strings.HasSuffix(got, "}") {
		t.Errorf("want JSON object, got %q", got)
	}
}
