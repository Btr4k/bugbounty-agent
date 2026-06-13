package scope

import (
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/config"
)

func TestPolicyAllowsOnlyTargetDomain(t *testing.T) {
	policy := New(config.TargetConfig{
		Domains:            []string{"example.com"},
		ExcludedSubdomains: []string{"admin.example.com", "*.legacy.example.com"},
	})

	tests := map[string]bool{
		"example.com":                    true,
		"api.example.com":                true,
		"https://api.example.com/path":   true,
		"admin.example.com":              false,
		"x.admin.example.com":            false,
		"legacy.example.com":             false,
		"x.legacy.example.com":           false,
		"example.com.evil.test":          false,
		"notexample.com":                 false,
		"https://example.com.evil.test/": false,
		"127.0.0.1":                      false,
	}

	for input, want := range tests {
		got := policy.AllowsHost(input)
		if got != want {
			t.Errorf("AllowsHost(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestPolicyFiltersURLs(t *testing.T) {
	policy := New(config.TargetConfig{Domains: []string{"example.com"}})
	got := policy.FilterURLs([]string{
		"https://example.com/a",
		"https://api.example.com/b",
		"https://evil.test/c",
		"https://example.com/a",
	})
	if len(got) != 2 {
		t.Fatalf("FilterURLs returned %d URLs, want 2: %v", len(got), got)
	}
}
