package scanner

import (
	"slices"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	scopepolicy "github.com/Btr4k/bugbounty-agent/internal/scope"
)

func TestAppendHeaderArgsIncludesConfiguredAuthentication(t *testing.T) {
	engine := &Engine{cfg: &config.Config{
		Authentication: config.AuthenticationConfig{
			AllowedHosts: []string{"app.example.com"},
			Headers:      map[string]string{"Authorization": "Bearer test-token"},
			Cookies:      map[string]string{"session": "test-session"},
		},
	}}
	args := engine.appendHeaderArgs([]string{"-silent"}, "-H", "https://app.example.com")
	if !slices.Contains(args, "Authorization: Bearer test-token") ||
		!slices.Contains(args, "Cookie: session=test-session") {
		t.Fatalf("authentication headers missing from tool args: %#v", args)
	}
	redactionArgs := engine.appendNucleiRedactionArgs(nil)
	if !slices.Contains(redactionArgs, "Authorization") || !slices.Contains(redactionArgs, "Cookie") {
		t.Fatalf("nuclei redaction keys missing from tool args: %#v", redactionArgs)
	}
	blocked := engine.appendHeaderArgs([]string{"-silent"}, "-H", "https://evil.example.com")
	if slices.Contains(blocked, "Authorization: Bearer test-token") {
		t.Fatalf("authentication header leaked to disallowed host: %#v", blocked)
	}
}

func TestFindingInScope(t *testing.T) {
	policy := scopepolicy.New(config.TargetConfig{Domains: []string{"example.com"}})
	if !findingInScope(policy, Finding{URL: "https://api.example.com/path"}) {
		t.Fatal("expected in-scope URL to be accepted")
	}
	if findingInScope(policy, Finding{URL: "https://example.com.evil.test/path"}) {
		t.Fatal("expected out-of-scope URL to be rejected")
	}
}

func TestDeduplicateFindingsKeepsDistinctIssuesOnSameURL(t *testing.T) {
	policy := scopepolicy.New(config.TargetConfig{Domains: []string{"example.com"}})
	findings := []Finding{
		{Title: "SQL Injection", URL: "https://example.com/search?q=1"},
		{Title: "Reflected XSS", URL: "https://example.com/search?q=1"},
		{Title: "SQL Injection", URL: "https://example.com/search?q=1"},
		{Title: "Out of scope", URL: "https://evil.test/"},
	}
	got := deduplicateFindings(policy, findings)
	if len(got) != 2 {
		t.Fatalf("deduplicateFindings returned %d findings, want 2: %#v", len(got), got)
	}
}

func TestClassifyFfufSeverityRejectsWeakDiscoveries(t *testing.T) {
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"admin", 200},
		{".env", 302},
		{"server-status", 403},
		{"api/v1", 200},
		{"anything", 500},
	} {
		if got := classifyFfufSeverity(tc.path, tc.status); got != "" {
			t.Errorf("classifyFfufSeverity(%q, %d) = %q, want empty", tc.path, tc.status, got)
		}
	}
	if got := classifyFfufSeverity(".env", 200); got != "critical" {
		t.Errorf("expected accessible .env candidate to remain critical, got %q", got)
	}
}
