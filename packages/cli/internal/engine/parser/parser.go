// Package parser handles MCP config parsing (claude_desktop_config.json and .cursor/mcp.json).
// It strips JSONC comments before unmarshaling, matching the Python parser.py logic exactly.
package parser

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// AutoApprove holds the autoApprove / alwaysAllow field, which can be bool, string, or []string.
type AutoApprove struct {
	Bool   *bool
	Str    *string
	List   []string
}

// MCPServer represents one entry in mcpServers.
type MCPServer struct {
	Name        string
	Command     string
	Args        []string
	Env         map[string]string
	Headers     map[string]string
	URL         string
	Transport   string
	AutoApprove *AutoApprove
	Disabled    bool
}

// MCPConfig is the parsed representation of the full config file.
type MCPConfig struct {
	ConfigHash string
	Servers    []MCPServer
}

// ParseConfig parses a claude_desktop_config.json or .cursor/mcp.json string.
// Handles JSONC (comments), extracts the first JSON object, and normalises fields.
func ParseConfig(configJSON string) (*MCPConfig, error) {
	stripped := stripJSONCComments(configJSON)
	extracted := extractFirstJSONObject(stripped)

	var data map[string]json.RawMessage
	if err := json.Unmarshal([]byte(extracted), &data); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(configJSON)))
	configHash := hash[:16]

	rawServers, ok := data["mcpServers"]
	if !ok {
		return &MCPConfig{ConfigHash: configHash, Servers: nil}, nil
	}

	var serversMap map[string]json.RawMessage
	if err := json.Unmarshal(rawServers, &serversMap); err != nil {
		return nil, fmt.Errorf("'mcpServers' must be an object")
	}

	servers := make([]MCPServer, 0, len(serversMap))
	for name, raw := range serversMap {
		s, err := parseServer(name, raw)
		if err != nil {
			continue // skip malformed server entries, matching Python behaviour
		}
		servers = append(servers, s)
	}

	return &MCPConfig{ConfigHash: configHash, Servers: servers}, nil
}

func parseServer(name string, raw json.RawMessage) (MCPServer, error) {
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		return MCPServer{}, err
	}

	s := MCPServer{
		Name:    name,
		Env:     map[string]string{},
		Headers: map[string]string{},
	}

	if v, ok := d["command"]; ok {
		json.Unmarshal(v, &s.Command) //nolint:errcheck
	}
	if v, ok := d["url"]; ok {
		json.Unmarshal(v, &s.URL) //nolint:errcheck
	}
	if v, ok := d["transport"]; ok {
		json.Unmarshal(v, &s.Transport) //nolint:errcheck
	}

	if v, ok := d["args"]; ok {
		var rawArgs []json.RawMessage
		if err := json.Unmarshal(v, &rawArgs); err == nil {
			for _, a := range rawArgs {
				var str string
				if json.Unmarshal(a, &str) == nil {
					s.Args = append(s.Args, str)
				}
			}
		}
	}

	if v, ok := d["env"]; ok {
		var rawEnv map[string]json.RawMessage
		if json.Unmarshal(v, &rawEnv) == nil {
			for k, val := range rawEnv {
				var str string
				if json.Unmarshal(val, &str) == nil {
					s.Env[k] = str
				}
			}
		}
	}

	if v, ok := d["headers"]; ok {
		var rawHeaders map[string]json.RawMessage
		if json.Unmarshal(v, &rawHeaders) == nil {
			for k, val := range rawHeaders {
				var str string
				if json.Unmarshal(val, &str) == nil {
					s.Headers[k] = str
				}
			}
		}
	}

	if v, ok := d["autoApprove"]; ok {
		s.AutoApprove = parseAutoApprove(v)
	} else if v, ok := d["alwaysAllow"]; ok {
		s.AutoApprove = parseAutoApprove(v)
	}

	if v, ok := d["disabled"]; ok {
		s.Disabled = parseDisabled(v)
	}

	return s, nil
}

func parseAutoApprove(raw json.RawMessage) *AutoApprove {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return &AutoApprove{Bool: &b}
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return &AutoApprove{Str: &s}
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return &AutoApprove{List: list}
	}
	return nil
}

func parseDisabled(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch s {
		case "true", "1", "yes", "on":
			return true
		}
	}
	return false
}

// stripJSONCComments removes // line comments and /* */ block comments from JSONC text.
// This is a string-aware state machine that handles escaped characters inside strings
// so backslash-escaped quotes don't falsely toggle the in-string state.
func stripJSONCComments(text string) string {
	result := make([]byte, 0, len(text))
	inString := false
	i := 0
	for i < len(text) {
		ch := text[i]
		if inString {
			if ch == '\\' && i+1 < len(text) {
				// Escaped char — consume both without toggling state
				result = append(result, ch, text[i+1])
				i += 2
				continue
			}
			if ch == '"' {
				inString = false
			}
			result = append(result, ch)
		} else {
			if ch == '"' {
				inString = true
				result = append(result, ch)
			} else if ch == '/' && i+1 < len(text) {
				if text[i+1] == '/' {
					// Line comment — skip to end of line
					for i < len(text) && text[i] != '\n' {
						i++
					}
					continue
				} else if text[i+1] == '*' {
					// Block comment — skip to */
					i += 2
					for i < len(text)-1 {
						if text[i] == '*' && text[i+1] == '/' {
							i += 2
							break
						}
						i++
					}
					continue
				} else {
					result = append(result, ch)
				}
			} else {
				result = append(result, ch)
			}
		}
		i++
	}
	return string(result)
}

// extractFirstJSONObject returns the first complete {...} block from text.
// String-aware: braces inside quoted strings are not counted.
func extractFirstJSONObject(text string) string {
	depth := 0
	inString := false
	start := -1
	i := 0
	for i < len(text) {
		ch := text[i]
		if ch == '\\' && inString {
			i += 2
			continue
		}
		if ch == '"' {
			inString = !inString
		} else if !inString {
			if ch == '{' {
				if depth == 0 {
					start = i
				}
				depth++
			} else if ch == '}' {
				depth--
				if depth == 0 && start != -1 {
					return text[start : i+1]
				}
			}
		}
		i++
	}
	if start != -1 {
		return text[start:]
	}
	return text
}
