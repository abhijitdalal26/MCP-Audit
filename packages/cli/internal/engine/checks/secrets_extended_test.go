package checks

import (
	"testing"

	"github.com/abhijitdalal26/MCP-Audit/cli/internal/engine/parser"
)

func TestCheckSecrets_AnthropicKey(t *testing.T) {
	// ANTHROPIC_API_KEY fires via varNamePattern regardless of value format
	s := serverWith(map[string]string{"ANTHROPIC_API_KEY": "anthropic-test-key-not-a-real-key"})
	if !hasCheckID(CheckSecrets(s), "SEC-004") {
		t.Error("want SEC-004 for ANTHROPIC_API_KEY env var name")
	}
}

func TestCheckSecrets_StripeKey(t *testing.T) {
	// STRIPE_SK (short alias) fires SEC-004 via varNamePattern.
	// Note: STRIPE_SECRET_KEY fires SEC-005 first (contains "secret_key" substring).
	s := serverWith(map[string]string{"STRIPE_SK": "stripe-test-value-not-real"})
	if !hasCheckID(CheckSecrets(s), "SEC-004") {
		t.Error("want SEC-004 for STRIPE_SK env var name")
	}
}

func TestCheckSecrets_SlackToken(t *testing.T) {
	// SLACK_TOKEN fires via varNamePattern regardless of value format
	s := serverWith(map[string]string{"SLACK_TOKEN": "slack-test-token-value-not-a-real-token"})
	if !hasCheckID(CheckSecrets(s), "SEC-004") {
		t.Error("want SEC-004 for SLACK_TOKEN env var name")
	}
}

func TestCheckSecrets_JWTToken(t *testing.T) {
	// JWT tokens are SEC-005 (cleartext JWT / signing material), not SEC-004
	s := serverWith(map[string]string{"TOKEN": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"})
	if !hasCheckID(CheckSecrets(s), "SEC-005") {
		t.Error("want SEC-005 for JWT token")
	}
}

func TestCheckSecrets_MongoDBURL(t *testing.T) {
	s := serverWith(map[string]string{"MONGODB_URI": "mongodb://admin:s3cr3tpassword@cluster0.example.mongodb.net/mydb"})
	if !hasCheckID(CheckSecrets(s), "SEC-003") {
		t.Error("want SEC-003 for MongoDB URI with credentials")
	}
}

func TestCheckSecrets_MySQLURL(t *testing.T) {
	s := serverWith(map[string]string{"DB_URL": "mysql://root:password123@localhost:3306/mydb"})
	if !hasCheckID(CheckSecrets(s), "SEC-003") {
		t.Error("want SEC-003 for MySQL URL with credentials")
	}
}

func TestCheckSecrets_HeaderWithDatabaseURL(t *testing.T) {
	// DATABASE_URL in a header key should trigger SEC-003 via varNamePattern
	s := &parser.MCPServer{
		Name: "test", Command: "npx", Args: []string{"-y", "some-server"},
		Env: map[string]string{},
		Headers: map[string]string{
			"DATABASE_URL": "anything",
		},
	}
	if !hasCheckID(CheckSecrets(s), "SEC-003") {
		t.Error("want SEC-003 for DATABASE_URL header key")
	}
}

func TestCheckSecrets_BearerTokenHeader(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", Command: "npx", Args: []string{"-y", "some-server"},
		Env: map[string]string{},
		Headers: map[string]string{
			"Authorization": "Bearer ghp_abcdefghijklmnopqrstuvwxyz012345678901",
		},
	}
	// Bearer tokens in headers should trigger a credential finding
	findings := CheckSecrets(s)
	if len(findings) == 0 {
		t.Error("want at least one finding for Bearer token in headers")
	}
}

func TestCheckSecrets_GitLabToken(t *testing.T) {
	s := serverWith(map[string]string{"GITLAB_TOKEN": "glpat-abcdefghijklmnopqrstu"})
	if !hasCheckID(CheckSecrets(s), "SEC-002") {
		t.Error("want SEC-002 for GitLab personal access token")
	}
}

func TestCheckSecrets_AWSSecretAccessKey(t *testing.T) {
	s := serverWith(map[string]string{
		"AWS_ACCESS_KEY_ID":     "AKIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	})
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-001") {
		t.Error("want SEC-001 for AWS credentials")
	}
}

func TestCheckSecrets_PlaceholderAngleBracket(t *testing.T) {
	s := serverWith(map[string]string{"OPENAI_API_KEY": "<your-openai-key>"})
	if hasCheckID(CheckSecrets(s), "SEC-004") {
		t.Error("angle bracket placeholder should not trigger SEC-004")
	}
}

func TestCheckSecrets_PlaceholderXXX(t *testing.T) {
	s := serverWith(map[string]string{"API_KEY": "xxxx"})
	findings := CheckSecrets(s)
	for _, f := range findings {
		if f.CheckID == "SEC-001" || f.CheckID == "SEC-004" {
			t.Errorf("xxx placeholder should not trigger %s", f.CheckID)
		}
	}
}

func TestCheckSecrets_RedisURL(t *testing.T) {
	s := serverWith(map[string]string{"REDIS_URL": "redis://:s3cr3t@redis.example.com:6379/0"})
	if !hasCheckID(CheckSecrets(s), "SEC-003") {
		t.Error("want SEC-003 for Redis URL with password")
	}
}

func TestCheckSecrets_IMDSv2Endpoint(t *testing.T) {
	// IMDSv2 token endpoint
	s := serverWith(map[string]string{"METADATA_ENDPOINT": "http://169.254.169.254/latest/api/token"})
	if !hasCheckID(CheckSecrets(s), "SEC-007") {
		t.Error("want SEC-007 for IMDSv2 endpoint")
	}
}

func TestCheckSecrets_CredentialInURLPassword(t *testing.T) {
	s := &parser.MCPServer{
		Name: "test", URL: "https://user:mysecretpassword@example.com/mcp",
		Env: map[string]string{}, Headers: map[string]string{},
	}
	// Credentials in URL should trigger SEC-008
	if !hasCheckID(CheckSecrets(s), "SEC-008") {
		t.Error("want SEC-008 for password in URL")
	}
}

func TestCheckSecrets_SensitiveVarNameDatabase(t *testing.T) {
	// DB_PASSWORD matches varNamePattern → SEC-003 (database credential)
	s := serverWith(map[string]string{"DB_PASSWORD": "mydbpass123"})
	findings := CheckSecrets(s)
	if !hasCheckID(findings, "SEC-003") {
		t.Error("want SEC-003 for sensitive var name DB_PASSWORD")
	}
}
