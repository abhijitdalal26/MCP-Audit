package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/client"
)

// PrintJSON writes the full ScanResult as indented JSON.
func PrintJSON(w io.Writer, result *client.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}
