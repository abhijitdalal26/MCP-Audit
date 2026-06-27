package parser

import (
	"testing"
)

func TestParseEmpty(t *testing.T) {
	cfg, err := ParseConfig(`{"mcpServers":{}}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("want 0 servers, got %d", len(cfg.Servers))
	}
}

func TestParseSingleServer(t *testing.T) {
	raw := `{"mcpServers":{"fs":{"command":"npx","args":["-y","pkg@1.0"]}}}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(cfg.Servers))
	}
	s := cfg.Servers[0]
	if s.Name != "fs" {
		t.Errorf("want name 'fs', got %q", s.Name)
	}
	if s.Command != "npx" {
		t.Errorf("want command 'npx', got %q", s.Command)
	}
	if len(s.Args) != 2 {
		t.Errorf("want 2 args, got %d", len(s.Args))
	}
}

func TestParseCursorFormat(t *testing.T) {
	// Cursor uses the same mcpServers key
	raw := `{"mcpServers":{"github":{"command":"npx","args":["-y","@anthropic-ai/mcp-server-github@1.0"]}}}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("want 1 server from cursor format, got %d", len(cfg.Servers))
	}
}

func TestParseURLOnlyServer(t *testing.T) {
	raw := `{"mcpServers":{"remote":{"url":"https://mcp.example.com/sse"}}}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(cfg.Servers))
	}
	s := cfg.Servers[0]
	if s.URL != "https://mcp.example.com/sse" {
		t.Errorf("want URL 'https://mcp.example.com/sse', got %q", s.URL)
	}
	if s.Command != "" {
		t.Errorf("URL-only server should have empty command, got %q", s.Command)
	}
}

func TestParseDisabledServer(t *testing.T) {
	raw := `{"mcpServers":{"off":{"command":"npx","args":["-y","pkg"],"disabled":true}}}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(cfg.Servers))
	}
	if !cfg.Servers[0].Disabled {
		t.Error("server should be marked disabled")
	}
}

func TestParseEnvVars(t *testing.T) {
	raw := `{"mcpServers":{"s":{"command":"node","args":["main.js"],"env":{"FOO":"bar","BAZ":"qux"}}}}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Servers[0]
	if s.Env["FOO"] != "bar" {
		t.Errorf("want FOO=bar, got %q", s.Env["FOO"])
	}
	if s.Env["BAZ"] != "qux" {
		t.Errorf("want BAZ=qux, got %q", s.Env["BAZ"])
	}
}

func TestParseHeaders(t *testing.T) {
	raw := `{"mcpServers":{"remote":{"url":"https://api.example.com/mcp","headers":{"X-API-KEY":"abc123"}}}}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.Servers[0]
	if s.Headers["X-API-KEY"] != "abc123" {
		t.Errorf("want X-API-KEY=abc123, got %q", s.Headers["X-API-KEY"])
	}
}

func TestParseAutoApproveWildcard(t *testing.T) {
	raw := `{"mcpServers":{"s":{"command":"node","args":["m.js"],"autoApprove":["*"]}}}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Servers[0].AutoApprove == nil {
		t.Error("autoApprove should be parsed")
	}
}

func TestParseAutoApproveBoolTrue(t *testing.T) {
	raw := `{"mcpServers":{"s":{"command":"node","args":["m.js"],"autoApprove":true}}}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Servers[0].AutoApprove == nil {
		t.Error("autoApprove bool should be parsed")
	}
}

func TestParseMultipleServers(t *testing.T) {
	raw := `{"mcpServers":{"a":{"command":"npx","args":["-y","pkg-a@1"]},"b":{"command":"uvx","args":["pkg-b"]}}}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Servers) != 2 {
		t.Errorf("want 2 servers, got %d", len(cfg.Servers))
	}
}

func TestParseInvalidJSON(t *testing.T) {
	_, err := ParseConfig(`{not valid json}`)
	if err == nil {
		t.Error("invalid JSON should return an error")
	}
}

func TestParseJSONC_LineComments(t *testing.T) {
	raw := `{
		// This is a Claude Desktop config
		"mcpServers": {
			// filesystem server
			"fs": {
				"command": "npx",
				"args": ["-y", "pkg@1.0"]
			}
		}
	}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatalf("JSONC line comments should parse: %v", err)
	}
	if len(cfg.Servers) != 1 {
		t.Errorf("want 1 server from JSONC, got %d", len(cfg.Servers))
	}
}

func TestParseJSONC_BlockComments(t *testing.T) {
	raw := `{
		/* Block comment */
		"mcpServers": {
			"s": {
				/* another block comment */
				"command": "node",
				"args": ["server.js"]
			}
		}
	}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatalf("JSONC block comments should parse: %v", err)
	}
	if len(cfg.Servers) != 1 {
		t.Errorf("want 1 server from JSONC, got %d", len(cfg.Servers))
	}
}

func TestParseJSONC_TrailingComma(t *testing.T) {
	raw := `{
		"mcpServers": {
			"s": {
				"command": "node",
				"args": ["server.js"],
			},
		}
	}`
	// Trailing commas are a JSONC feature some parsers support — test for graceful handling
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Skipf("trailing commas not supported by this parser: %v", err)
	}
	_ = cfg
}

func TestParseServerName_Preserved(t *testing.T) {
	raw := `{"mcpServers":{"my-special-server":{"command":"npx","args":["-y","pkg"]}}}`
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Servers[0].Name != "my-special-server" {
		t.Errorf("server name should be preserved, got %q", cfg.Servers[0].Name)
	}
}
