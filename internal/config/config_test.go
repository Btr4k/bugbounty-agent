package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateConfigKeysRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("ai:\n  provider: deepseek\n  typo_field: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateConfigKeys(path); err == nil {
		t.Fatal("expected unknown config field to be rejected")
	}
}

func TestValidateRejectsInvalidValues(t *testing.T) {
	cfg := Config{
		AI:       AIConfig{Provider: "unknown", APIKey: "key"},
		Recon:    ReconConfig{Timeout: 1},
		Scanning: ScanningConfig{Threads: 1, RateLimit: 1},
		Analysis: AnalysisConfig{MinConfidence: 0.7},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unsupported provider to be rejected")
	}
}

func TestAuthenticationHeadersAndSecrets(t *testing.T) {
	t.Setenv("TARGET_TOKEN", "secret-token-value")
	auth := AuthenticationConfig{
		AllowedHosts: []string{"app.example.com", "*.api.example.com"},
		Headers:      map[string]string{"Authorization": "Bearer ${TARGET_TOKEN}"},
		Cookies:      map[string]string{"session": "${TARGET_TOKEN}"},
	}
	auth.expandEnv()

	headers := auth.HeaderValuesForTargets("app.example.com")
	if headers["Authorization"] != "Bearer secret-token-value" ||
		headers["Cookie"] != "session=secret-token-value" {
		t.Fatalf("unexpected authentication headers: %#v", headers)
	}
	if len(auth.HeaderValuesForTargets("https://app.example.com/private")) == 0 ||
		len(auth.HeaderValuesForTargets("v1.api.example.com")) == 0 ||
		len(auth.HeaderValuesForTargets("evil.example.com")) != 0 {
		t.Fatal("authentication host allowlist was not enforced")
	}

	cfg := Config{Authentication: auth}
	redacted := cfg.Redact("Authorization: Bearer secret-token-value; session=secret-token-value")
	if redacted != "Authorization: [REDACTED]; session=[REDACTED]" {
		t.Fatalf("secret was not redacted: %q", redacted)
	}
}

func TestValidateRejectsUnsafeAuthenticationHeaders(t *testing.T) {
	cfg := Config{
		AI:       AIConfig{Provider: "deepseek", APIKey: "key"},
		Recon:    ReconConfig{Timeout: 1},
		Scanning: ScanningConfig{Threads: 1, RateLimit: 1},
		Analysis: AnalysisConfig{MinConfidence: 0.85},
		Authentication: AuthenticationConfig{
			AllowedHosts: []string{"example.com"},
			Headers:      map[string]string{"Host": "evil.example"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unsafe authentication header to be rejected")
	}
}

func TestValidateRequiresAuthenticationAllowedHosts(t *testing.T) {
	cfg := Config{
		AI:             AIConfig{Provider: "deepseek", APIKey: "key"},
		Recon:          ReconConfig{Timeout: 1},
		Scanning:       ScanningConfig{Threads: 1, RateLimit: 1},
		Analysis:       AnalysisConfig{MinConfidence: 0.85},
		Authentication: AuthenticationConfig{Headers: map[string]string{"Authorization": "Bearer token-value"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected authentication without allowed_hosts to be rejected")
	}
}
