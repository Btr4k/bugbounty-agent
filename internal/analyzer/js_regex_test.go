package analyzer

import (
	"fmt"
	"strings"
	"testing"
)

func TestScanJSWithRegex(t *testing.T) {
	awsKey := "AKIA" + "1234567890ABCDEF"
	awsSecret := "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYREALKEY12"
	googleKey := "AIza" + "SyA1234567890abcdefghijklmnopqrstuvw"
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	password := "Super" + "Secret123!"
	databaseURL := "mongodb://admin:" + "pass123@internal-db.company.com:27017/prod"
	bearer := "Bearer " + "synthetic-long-token-for-testing-1234567890"
	jsFiles := []struct {
		URL     string
		Content string
		Size    int
		Source  string
	}{
		{
			URL: "https://example.com/app.js?signature=opaque-query-secret#private",
			Content: fmt.Sprintf(`
				// AWS key leak
				var awsKey = "%s";
				var secret = "%s";
				
				// Google API key
				var googleKey = "%s";
				
				// JWT token
				var token = "%s";
				
				// Hardcoded password
				password = "%s";
				
				// Internal API
				fetch("/api/admin/users");
				
				// Private IP
				var server = "10.0.1.50";
				
				// Database URL
				var db = "%s";
				
				// Bearer token  
				headers["Authorization"] = "%s";
				
				// Debug mode
				DEBUG = true;

				// WebSocket
				var ws = new WebSocket("wss://socket.example.com/live");
			`, awsKey, awsSecret, googleKey, jwt, password, databaseURL, bearer),
			Size:   1200,
			Source: "katana",
		},
		{
			URL: "https://example.com/clean.js",
			Content: `
				// Clean file with no secrets
				function add(a, b) { return a + b; }
				console.log("Hello World");
			`,
			Size:   80,
			Source: "katana",
		},
	}

	findings := ScanJSWithRegex(jsFiles)

	if len(findings) == 0 {
		t.Fatal("Expected findings but got none")
	}

	// Check that we found key pattern types
	foundTypes := make(map[string]bool)
	for _, f := range findings {
		if meta, ok := f.Metadata["pattern"]; ok {
			foundTypes[meta] = true
		}
		t.Logf("  Found: [%s] %s — %s", f.Severity, f.Title, f.Evidence[:min(60, len(f.Evidence))])
		if strings.Contains(f.URL, "opaque-query-secret") || strings.Contains(f.Description, "opaque-query-secret") ||
			strings.Contains(f.Metadata["file_url"], "opaque-query-secret") || strings.Contains(f.URL, "#private") {
			t.Fatalf("JS URL secret survived scanner-boundary sanitization: %#v", f)
		}
	}

	expectedTypes := []string{"aws_key", "jwt", "hardcoded_password", "database_url"}
	for _, expected := range expectedTypes {
		if !foundTypes[expected] {
			t.Errorf("Missing expected pattern type: %s", expected)
		}
	}
	for _, weakType := range []string{"google_api_key", "internal_api", "internal_ip", "debug_mode"} {
		if foundTypes[weakType] {
			t.Errorf("Weak observation should not be reported as a finding: %s", weakType)
		}
	}

	t.Logf("\nTotal findings: %d", len(findings))
	t.Logf("Pattern types found: %v", foundTypes)
}

func TestScanJSWithRegex_FalsePositiveFiltering(t *testing.T) {
	jsFiles := []struct {
		URL     string
		Content string
		Size    int
		Source  string
	}{
		{
			URL: "https://example.com/fp.js",
			Content: `
				// Should be filtered (placeholder email)
				var email = "test@example.com";
				
				// Should be filtered (env var password)
				password = process.env.DB_PASSWORD;
			`,
			Size:   200,
			Source: "katana",
		},
	}

	findings := ScanJSWithRegex(jsFiles)

	for _, f := range findings {
		if meta, ok := f.Metadata["pattern"]; ok {
			if meta == "email" && f.Evidence == "test@example.com" {
				t.Error("Should have filtered out placeholder email test@example.com")
			}
		}
	}
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
