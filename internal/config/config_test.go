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
