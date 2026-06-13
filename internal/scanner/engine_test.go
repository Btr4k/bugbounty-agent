package scanner

import (
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	scopepolicy "github.com/Btr4k/bugbounty-agent/internal/scope"
)

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
