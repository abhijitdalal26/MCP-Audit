package cmd

import (
	"os"
	"path/filepath"
	"runtime"
)

// configCandidate is a potential MCP config file with a source label.
type configCandidate struct {
	Path   string
	Source string // "Claude Desktop", "Cursor", etc.
}

// detectConfigs returns known MCP config paths for the current OS that actually exist.
// Checks Claude Desktop and Cursor locations in priority order.
func detectConfigs() []configCandidate {
	var candidates []configCandidate

	switch runtime.GOOS {
	case "windows":
		candidates = windowsCandidates()
	case "darwin":
		candidates = macosCandidates()
	default: // linux and others
		candidates = linuxCandidates()
	}

	var found []configCandidate
	for _, c := range candidates {
		if _, err := os.Stat(c.Path); err == nil {
			found = append(found, c)
		}
	}
	return found
}

func windowsCandidates() []configCandidate {
	appData := os.Getenv("APPDATA")
	localAppData := os.Getenv("LOCALAPPDATA")
	userProfile := os.Getenv("USERPROFILE")

	var out []configCandidate

	// Claude Desktop — standard direct install location
	if appData != "" {
		out = append(out, configCandidate{
			Path:   filepath.Join(appData, "Claude", "claude_desktop_config.json"),
			Source: "Claude Desktop",
		})
	}

	// Claude Desktop — Microsoft Store (UWP) install location
	if localAppData != "" {
		// Glob for the UWP package directory (contains a random suffix)
		pattern := filepath.Join(localAppData, "Packages", "Claude_*", "LocalCache", "Roaming", "Claude", "claude_desktop_config.json")
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			out = append(out, configCandidate{Path: m, Source: "Claude Desktop (Store)"})
		}
	}

	// Cursor
	if userProfile != "" {
		out = append(out, configCandidate{
			Path:   filepath.Join(userProfile, ".cursor", "mcp.json"),
			Source: "Cursor",
		})
	}

	return out
}

func macosCandidates() []configCandidate {
	home, _ := os.UserHomeDir()
	if home == "" {
		return nil
	}
	return []configCandidate{
		{
			Path:   filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			Source: "Claude Desktop",
		},
		{
			Path:   filepath.Join(home, ".cursor", "mcp.json"),
			Source: "Cursor",
		},
	}
}

func linuxCandidates() []configCandidate {
	home, _ := os.UserHomeDir()
	if home == "" {
		return nil
	}

	// XDG_CONFIG_HOME takes precedence if set
	xdgConfig := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" {
		xdgConfig = filepath.Join(home, ".config")
	}

	return []configCandidate{
		{
			Path:   filepath.Join(xdgConfig, "claude", "claude_desktop_config.json"),
			Source: "Claude Desktop",
		},
		{
			Path:   filepath.Join(home, ".cursor", "mcp.json"),
			Source: "Cursor",
		},
	}
}
