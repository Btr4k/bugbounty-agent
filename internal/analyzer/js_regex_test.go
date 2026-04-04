package analyzer

import (
	"testing"
)

func TestScanJSWithRegex(t *testing.T) {
	jsFiles := []struct {
		URL     string
		Content string
		Size    int
		Source  string
	}{
		{
			URL: "https://example.com/app.js",
			Content: `
				// AWS key leak
				var awsKey = "AKIAIOSFODNN7EXAMPLE";
				var secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
				
				// Google API key
				var googleKey = "AIzaSyA1234567890abcdefghijklmnopqrstuvw";
				
				// JWT token
				var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
				
				// Hardcoded password
				password = "SuperSecret123!";
				
				// Internal API
				fetch("/api/admin/users");
				
				// Private IP
				var server = "10.0.1.50";
				
				// Database URL
				var db = "mongodb://admin:pass123@internal-db.company.com:27017/prod";
				
				// Bearer token  
				headers["Authorization"] = "Bearer sk-live-very-long-token-here-1234567890";
				
				// Debug mode
				DEBUG = true;

				// WebSocket
				var ws = new WebSocket("wss://socket.example.com/live");
			`,
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
	}

	expectedTypes := []string{"aws_key", "google_api_key", "jwt", "hardcoded_password", "internal_api", "database_url", "internal_ip"}
	for _, expected := range expectedTypes {
		if !foundTypes[expected] {
			t.Errorf("Missing expected pattern type: %s", expected)
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
