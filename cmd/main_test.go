package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDomain(t *testing.T) {
	for _, domain := range []string{"example.com", "api.example.com", "xn--bcher-kva.example"} {
		if err := validateDomain(domain); err != nil {
			t.Errorf("validateDomain(%q) unexpected error: %v", domain, err)
		}
	}
	for _, domain := range []string{"example..com", "-api.example.com", "api-.example.com", "localhost", "example.com/path"} {
		if err := validateDomain(domain); err == nil {
			t.Errorf("validateDomain(%q) expected error", domain)
		}
	}
}

func TestCheckConfigAcceptsAuthenticationConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `ai:
  provider: deepseek
  api_key: test-key
authentication:
  allowed_hosts: ["app.example.com"]
  headers:
    Authorization: "Bearer test-token"
recon:
  timeout: 1
scanning:
  threads: 1
  rate_limit: 1
analysis:
  min_confidence: 0.85
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	oldCheck, oldCfg := checkConfig, cfgFile
	checkConfig, cfgFile = true, path
	t.Cleanup(func() {
		checkConfig, cfgFile = oldCheck, oldCfg
	})

	if err := runAgent(nil, nil); err != nil {
		t.Fatalf("check-config rejected compatible config: %v", err)
	}
}
