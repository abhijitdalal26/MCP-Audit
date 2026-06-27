package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

// TestCheckSecrets_SEC003_DatabaseURLInEnv mirrors Python test_http_basic_auth_url_detected:
// a DB connection string with embedded credentials fires SEC-003.
func TestCheckSecrets_SEC003_DatabaseURLInEnv(t *testing.T) {
	s := &parser.MCPServer{
		Name: "db-server", Command: "node",
		Args: []string{"server.js"},
		Env:  map[string]string{"DB_URL": "postgresql://admin:mysecretpassword@internal.db.example.com:5432/mydb"},
	}
	if !hasCheckID(CheckSecrets(s), "SEC-003") {
		t.Error("want SEC-003 for postgres:// connection string with credentials in env var")
	}
}
