package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validConfigForTest() Config {
	return Config{
		AI:       AIConfig{Provider: "deepseek", APIKey: "test-key", Model: "test-model", MaxTokens: 1000, Timeout: 30},
		Recon:    ReconConfig{Timeout: 1},
		Scanning: ScanningConfig{Threads: 1, RateLimit: 1, Timeout: 1},
		Analysis: AnalysisConfig{MinConfidence: 0.85},
		Hunter:   HunterConfig{Enabled: true, MaxHypotheses: 40, MaxEndpoints: 120},
	}
}

func TestValidateConfigKeysRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("ai:\n  provider: deepseek\n  typo_field: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateConfigKeys(path); err == nil {
		t.Fatal("expected unknown config field to be rejected")
	}
}

func TestLoadEnvFileRequiresPrivateRegularFile(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile(".env", []byte("AI_API_KEY=test-key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(".env", 0o644); err != nil {
		t.Fatal(err)
	}
	if err := loadEnvFile(map[string]bool{"AI_API_KEY": true}); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("broad .env permissions were not rejected: %v", err)
	}

	if err := os.Remove(".env"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("missing-secret-file", ".env"); err != nil {
		t.Fatal(err)
	}
	if err := loadEnvFile(map[string]bool{"AI_API_KEY": true}); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink .env was not rejected: %v", err)
	}
}

func TestLoadEnvFileIgnoresProcessControlVariables(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("PATH", "/safe/original/path")
	t.Setenv("AI_API_KEY", "")
	contents := "PATH=/attacker/bin\nAI_API_KEY=file-api-key\nUNRELATED=value\n"
	if err := os.WriteFile(".env", []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadEnvFile(map[string]bool{"AI_API_KEY": true}); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("PATH"); got != "/safe/original/path" {
		t.Fatalf(".env replaced PATH: %q", got)
	}
	if got := os.Getenv("AI_API_KEY"); got != "file-api-key" {
		t.Fatalf("allowed credential was not loaded: %q", got)
	}
}

func TestAllowedEnvironmentNamesIncludesConfiguredAuthenticationReferences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	configText := "authentication:\n  headers:\n    Authorization: 'Bearer ${TARGET_TOKEN}'\n  cookies:\n    session: '$TARGET_SESSION'\n"
	if err := os.WriteFile(path, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	allowed, err := allowedEnvironmentNames(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TARGET_TOKEN", "TARGET_SESSION", "AI_API_KEY"} {
		if !allowed[name] {
			t.Errorf("configured environment variable %q was not allowlisted", name)
		}
	}
	if allowed["PATH"] {
		t.Fatal("PATH must never be allowlisted from .env")
	}
}

func TestConfiguredEnvironmentReferencesRejectProcessControlNames(t *testing.T) {
	unsafeNames := []string{
		"PATH", "HTTPS_PROXY", "SSL_CERT_FILE", "LD_PRELOAD", "GIT_ASKPASS",
		"SSH_ASKPASS", "BASH_ENV", "NODE_OPTIONS", "PYTHONPATH", "GODEBUG",
	}
	for _, name := range unsafeNames {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			configText := "authentication:\n  headers:\n    X-Secret: '${" + name + "}'\n"
			if err := os.WriteFile(path, []byte(configText), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := allowedEnvironmentNames(path); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("unsafe environment reference %q was accepted: %v", name, err)
			}
		})
	}
}

func TestCredentialEnvironmentNameConvention(t *testing.T) {
	for _, name := range []string{
		"AI_API_KEY", "TARGET_TOKEN", "TARGET_SESSION", "ACME_CLIENT_SECRET", "SERVICE_PASSWORD",
	} {
		if !isSafeCredentialEnvironmentName(name) {
			t.Errorf("credential environment name %q was rejected", name)
		}
	}
	for _, name := range []string{
		"target_token", "TARGET_VALUE", "HTTPS_PROXY", "SSL_CERT_FILE", "LD_ACCESS_TOKEN",
	} {
		if isSafeCredentialEnvironmentName(name) {
			t.Errorf("unsafe or ambiguous environment name %q was accepted", name)
		}
	}
}

func TestLoadEnvFileCannotBypassImmutableDenylist(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HTTPS_PROXY", "")
	if err := os.WriteFile(".env", []byte("HTTPS_PROXY=https://proxy.attacker.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loadEnvFile(map[string]bool{"HTTPS_PROXY": true}); err != nil {
		t.Fatal(err)
	}
	if value := os.Getenv("HTTPS_PROXY"); value != "" {
		t.Fatalf("process-control variable bypassed immutable denylist: %q", value)
	}
}

func TestExternalToolEnvironmentIsCaseSensitiveAndUsesExactLocaleAllowlist(t *testing.T) {
	t.Setenv("path", "LOWERCASE_SECRET_MUST_NOT_LEAK")
	t.Setenv("home", "LOWERCASE_HOME_SECRET_MUST_NOT_LEAK")
	t.Setenv("LC_API_TOKEN", "LOCALE_PREFIX_SECRET_MUST_NOT_LEAK")
	t.Setenv("LC_ALL", "C")

	environment := ExternalToolEnvironment()
	joined := strings.Join(environment, "\n")
	for _, secret := range []string{
		"LOWERCASE_SECRET_MUST_NOT_LEAK",
		"LOWERCASE_HOME_SECRET_MUST_NOT_LEAK",
		"LOCALE_PREFIX_SECRET_MUST_NOT_LEAK",
	} {
		if strings.Contains(joined, secret) {
			t.Fatalf("external tool inherited non-allowlisted environment secret %q: %v", secret, environment)
		}
	}
	if !strings.Contains(joined, "LC_ALL=C") {
		t.Fatalf("required exact locale variable was omitted: %v", environment)
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

func TestResolveAIConfigRejectsPlaceholderKeys(t *testing.T) {
	for _, envVar := range []string{"ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"} {
		t.Setenv(envVar, "")
	}

	cfg := Config{
		AI:       AIConfig{Provider: "deepseek", APIKey: "your-deepseek-api-key-here"},
		Recon:    ReconConfig{Timeout: 1},
		Scanning: ScanningConfig{Threads: 1, RateLimit: 1},
		Analysis: AnalysisConfig{MinConfidence: 0.85},
	}
	cfg.ResolveAIConfig()

	if cfg.AI.APIKey != "" {
		t.Fatalf("placeholder API key was accepted: %q", cfg.AI.APIKey)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected placeholder API key to fail validation")
	}
}

func TestResolveAIConfigDoesNotSwitchExplicitProvider(t *testing.T) {
	for _, envVar := range []string{"ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"} {
		t.Setenv(envVar, "")
	}
	t.Setenv("ANTHROPIC_API_KEY", "foreign-provider-key")

	cfg := validConfigForTest()
	cfg.AI = AIConfig{Provider: "deepseek"}
	cfg.ResolveAIConfig()

	if cfg.AI.Provider != "deepseek" {
		t.Fatalf("explicit provider changed to %q", cfg.AI.Provider)
	}
	if cfg.AI.APIKey != "" {
		t.Fatal("explicit provider reused a different provider's API key")
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), `provider "deepseek"`) {
		t.Fatalf("expected provider-specific missing key error, got %v", err)
	}
}

func TestResolveAIConfigAutoDetectionIsOptIn(t *testing.T) {
	for _, envVar := range []string{"ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"} {
		t.Setenv(envVar, "")
	}
	t.Setenv("OPENAI_API_KEY", "openai-test-key")

	auto := validConfigForTest()
	auto.AI = AIConfig{Provider: "auto"}
	auto.ResolveAIConfig()
	if auto.AI.Provider != "openai" || auto.AI.APIKey != "openai-test-key" || auto.AI.Model != DefaultAIModel("openai") {
		t.Fatalf("auto provider did not resolve coherently: %#v", auto.AI)
	}

	omitted := validConfigForTest()
	omitted.AI = AIConfig{}
	omitted.ResolveAIConfig()
	if omitted.AI.Provider != "" || omitted.AI.APIKey != "" {
		t.Fatalf("omitted provider unexpectedly auto-detected another provider: %#v", omitted.AI)
	}
	if err := omitted.Validate(); err == nil {
		t.Fatal("omitted provider must fail instead of selecting a vendor implicitly")
	}
}

func TestResolveAIConfigRejectsAmbiguousAutoDetection(t *testing.T) {
	for _, envVar := range []string{"ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"} {
		t.Setenv(envVar, "")
	}
	t.Setenv("ANTHROPIC_API_KEY", "anthropic-test-key")
	t.Setenv("OPENAI_API_KEY", "openai-test-key")
	cfg := validConfigForTest()
	cfg.AI = AIConfig{Provider: "auto"}
	cfg.ResolveAIConfig()
	if cfg.AI.Provider != "auto" || cfg.AI.APIKey != "" {
		t.Fatalf("ambiguous auto detection selected a provider: %#v", cfg.AI)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "could not detect") {
		t.Fatalf("ambiguous auto detection must fail closed, got %v", err)
	}
}

func TestValidateBoundsScannerAndHunterInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "hunter hypotheses", mutate: func(cfg *Config) { cfg.Hunter.MaxHypotheses = 201 }},
		{name: "hunter endpoints", mutate: func(cfg *Config) { cfg.Hunter.MaxEndpoints = 1001 }},
		{name: "dalfox URLs", mutate: func(cfg *Config) { cfg.Scanning.Tools.Dalfox.MaxURLs = 10001 }},
		{name: "nmap port", mutate: func(cfg *Config) { cfg.Scanning.Tools.Nmap.Ports = "443,70000" }},
		{name: "nmap range", mutate: func(cfg *Config) { cfg.Scanning.Tools.Nmap.Ports = "100-10" }},
		{name: "nuclei tag", mutate: func(cfg *Config) { cfg.Scanning.Tools.Nuclei.Tags = []string{"valid", "bad,tag"} }},
		{name: "blind callback query", mutate: func(cfg *Config) { cfg.Scanning.Tools.Dalfox.BlindURL = "https://callback.example/?secret=value" }},
		{name: "blind callback private", mutate: func(cfg *Config) { cfg.Scanning.Tools.Dalfox.BlindURL = "https://127.0.0.1/callback" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfigForTest()
			test.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe or unbounded scanner configuration was accepted")
			}
		})
	}
}

func TestResolveAIConfigRejectsGenericKeyWithAutoProvider(t *testing.T) {
	for _, envVar := range []string{"ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"} {
		t.Setenv(envVar, "")
	}
	t.Setenv("ANTHROPIC_API_KEY", "anthropic-provider-key")

	cfg := validConfigForTest()
	cfg.AI.Provider = "auto"
	cfg.AI.APIKey = "generic-key-that-may-belong-to-openai"
	cfg.ResolveAIConfig()
	if cfg.AI.Provider != "auto" {
		t.Fatalf("auto provider resolved despite ambiguous generic key: %#v", cfg.AI)
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("ambiguous auto provider/key pairing did not fail closed: %v", err)
	}
}

func TestApplyAIOverridesResetsProviderDerivedDefaults(t *testing.T) {
	for _, envVar := range []string{"ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "OPENROUTER_API_KEY"} {
		t.Setenv(envVar, "")
	}
	t.Setenv("OPENAI_API_KEY", "openai-test-key")

	cfg := validConfigForTest()
	cfg.AI.Model = DefaultAIModel("deepseek")
	cfg.AI.BaseURL = "https://api.deepseek.com/v1"
	if err := cfg.ApplyAIOverrides("openai", ""); err != nil {
		t.Fatalf("apply provider override: %v", err)
	}
	if cfg.AI.Provider != "openai" || cfg.AI.APIKey != "openai-test-key" {
		t.Fatalf("provider credentials were not resolved coherently: %#v", cfg.AI)
	}
	if cfg.AI.Model != DefaultAIModel("openai") || cfg.AI.BaseURL != "https://api.openai.com/v1" {
		t.Fatalf("provider defaults were not reset coherently: %#v", cfg.AI)
	}

	if err := cfg.ApplyAIOverrides("", "gpt-explicit-model"); err != nil {
		t.Fatalf("apply model override: %v", err)
	}
	if cfg.AI.Model != "gpt-explicit-model" {
		t.Fatalf("explicit model override was not preserved: %q", cfg.AI.Model)
	}
}

func TestValidateAIBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{name: "public HTTPS", baseURL: "https://ai.example.com/v1"},
		{name: "public HTTPS non-default port", baseURL: "https://ai.example.com:8443/v1"},
		{name: "plaintext", baseURL: "http://ai.example.com/v1", wantErr: true},
		{name: "loopback name", baseURL: "https://localhost/v1", wantErr: true},
		{name: "local suffix", baseURL: "https://model.dev.internal/v1", wantErr: true},
		{name: "IPv4 loopback", baseURL: "https://127.0.0.1/v1", wantErr: true},
		{name: "short IPv4 loopback", baseURL: "https://127.1/v1", wantErr: true},
		{name: "octal IPv4 loopback", baseURL: "https://0177.0.0.1/v1", wantErr: true},
		{name: "integer IPv4 loopback", baseURL: "https://2130706433/v1", wantErr: true},
		{name: "IPv4 private", baseURL: "https://10.10.1.2/v1", wantErr: true},
		{name: "metadata link local", baseURL: "https://169.254.169.254/v1", wantErr: true},
		{name: "IPv6 loopback", baseURL: "https://[::1]/v1", wantErr: true},
		{name: "userinfo", baseURL: "https://user:pass@ai.example.com/v1", wantErr: true},
		{name: "query", baseURL: "https://ai.example.com/v1?token=value", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfigForTest()
			cfg.AI.Provider = "custom"
			cfg.AI.BaseURL = tt.baseURL
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHostedProvidersPinOfficialBaseURLs(t *testing.T) {
	tests := []struct {
		provider string
		official string
	}{
		{provider: "openai", official: "https://api.openai.com/v1"},
		{provider: "deepseek", official: "https://api.deepseek.com/v1"},
		{provider: "openrouter", official: "https://openrouter.ai/api/v1"},
	}

	for _, test := range tests {
		t.Run(test.provider, func(t *testing.T) {
			cfg := validConfigForTest()
			cfg.AI.Provider = test.provider
			cfg.AI.BaseURL = test.official + "/"
			if err := cfg.Validate(); err != nil {
				t.Fatalf("official endpoint rejected: %v", err)
			}
			if cfg.AI.BaseURL != test.official {
				t.Fatalf("official endpoint was not canonicalized: %q", cfg.AI.BaseURL)
			}

			cfg.AI.BaseURL = "https://gateway.attacker.example/v1"
			if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), `provider "custom"`) {
				t.Fatalf("arbitrary hosted-provider endpoint was accepted: %v", err)
			}
		})
	}
}

func TestHostedProviderRejectsEndpointConfusion(t *testing.T) {
	for _, baseURL := range []string{
		"https://api.openai.com.attacker.example/v1",
		"https://api.openai.com:444/v1",
		"https://api.openai.com/v1/../v1",
		"https://api.openai.com/%76%31",
		"https://api.openai.com/v1?",
	} {
		cfg := validConfigForTest()
		cfg.AI.Provider = "openai"
		cfg.AI.BaseURL = baseURL
		if err := cfg.Validate(); err == nil {
			t.Errorf("confusable hosted-provider endpoint %q was accepted", baseURL)
		}
	}

	cfg := validConfigForTest()
	cfg.AI.Provider = "openai"
	cfg.AI.BaseURL = "HTTPS://API.OPENAI.COM:443/v1/"
	if err := cfg.Validate(); err != nil || cfg.AI.BaseURL != "https://api.openai.com/v1" {
		t.Fatalf("equivalent official endpoint was not canonicalized: base_url=%q err=%v", cfg.AI.BaseURL, err)
	}
}

func TestCustomProviderRetainsExplicitPublicEndpoint(t *testing.T) {
	cfg := validConfigForTest()
	cfg.AI.Provider = "custom"
	cfg.AI.BaseURL = "https://gateway.example.com/compatible/v1"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("explicit custom endpoint rejected: %v", err)
	}
}

func TestValidateCustomProviderRequiresModel(t *testing.T) {
	cfg := validConfigForTest()
	cfg.AI = AIConfig{Provider: "custom", APIKey: "test-key", BaseURL: "https://ai.example.com/v1"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "model is required") {
		t.Fatalf("expected missing custom model to be rejected, got %v", err)
	}
}

func TestAuthenticationHeadersAndSecrets(t *testing.T) {
	t.Setenv("TARGET_TOKEN", "secret-token-value")
	auth := AuthenticationConfig{
		AllowedHosts: []string{"https://app.example.com", "https://*.api.example.com"},
		Headers:      map[string]string{"Authorization": "Bearer ${TARGET_TOKEN}"},
		Cookies:      map[string]string{"session": "${TARGET_TOKEN}"},
	}
	auth.expandEnv()

	headers := auth.HeaderValuesForTargets("https://app.example.com/private")
	if headers["Authorization"] != "Bearer secret-token-value" ||
		headers["Cookie"] != "session=secret-token-value" {
		t.Fatalf("unexpected authentication headers: %#v", headers)
	}
	if len(auth.HeaderValuesForTargets("https://v1.api.example.com/private")) == 0 ||
		len(auth.HeaderValuesForTargets("https://api.example.com/private")) != 0 ||
		len(auth.HeaderValuesForTargets("https://evil.example.com/private")) != 0 {
		t.Fatal("authentication host allowlist was not enforced")
	}

	cfg := Config{Authentication: auth}
	redacted := cfg.Redact("Authorization: Bearer secret-token-value; session=secret-token-value")
	if redacted != "Authorization: [REDACTED]; session=[REDACTED]" {
		t.Fatalf("secret was not redacted: %q", redacted)
	}
}

func TestValidateRejectsShortConfiguredSecretsWithoutCorruptingOutput(t *testing.T) {
	cfg := Config{Authentication: AuthenticationConfig{
		Headers: map[string]string{"X-API-Key": "abc"},
		Cookies: map[string]string{"sid": "xy"},
	}}
	if got := cfg.Redact("banana/example"); got != "banana/example" {
		t.Fatalf("invalid short values corrupted unrelated output: %q", got)
	}
	valid := validConfigForTest()
	valid.Authentication = AuthenticationConfig{
		AllowedHosts: []string{"https://app.example.com"},
		Headers:      map[string]string{"X-API-Key": "abc"},
	}
	if err := valid.Validate(); err == nil || !strings.Contains(err.Error(), "at least 4") {
		t.Fatalf("short credential must be rejected, got %v", err)
	}
}

func TestAuthenticationExactOriginRules(t *testing.T) {
	auth := AuthenticationConfig{AllowedHosts: []string{
		"https://app.example.com",
		"https://api.example.com:8443",
		"https://*.svc.example.com",
	}}

	tests := []struct {
		target string
		want   bool
	}{
		{target: "https://app.example.com/private", want: true},
		{target: "https://app.example.com:443/private", want: true},
		{target: "http://app.example.com/private", want: false},
		{target: "https://app.example.com:444/private", want: false},
		{target: "app.example.com", want: false},
		{target: "https://api.example.com:8443/private", want: true},
		{target: "https://api.example.com/private", want: false},
		{target: "https://v1.svc.example.com/private", want: true},
		{target: "http://v1.svc.example.com/private", want: false},
	}
	for _, tt := range tests {
		if got := auth.AllowsTarget(tt.target); got != tt.want {
			t.Errorf("AllowsTarget(%q) = %v, want %v", tt.target, got, tt.want)
		}
	}
}

func TestValidateAuthenticationOriginRules(t *testing.T) {
	valid := []string{
		"https://app.example.com",
		"https://app.example.com:8443/",
		"https://*.api.example.com",
	}
	for _, rule := range valid {
		cfg := validConfigForTest()
		cfg.Authentication = AuthenticationConfig{
			AllowedHosts: []string{rule},
			Headers:      map[string]string{"Authorization": "Bearer test-token"},
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("valid authentication rule %q rejected: %v", rule, err)
		}
	}

	invalid := []string{
		"ftp://app.example.com",
		"http://app.example.com",
		"legacy.example.com",
		"*.legacy.example.com",
		"https://user@app.example.com",
		"https://app.example.com/private",
		"https://app.example.com?token=value",
		"https://app.example.com:99999",
		"https://*.com",
		"https://*.co.uk",
		"https://*.localhost",
		"https://bad..example.com",
	}
	for _, rule := range invalid {
		cfg := validConfigForTest()
		cfg.Authentication = AuthenticationConfig{
			AllowedHosts: []string{rule},
			Headers:      map[string]string{"Authorization": "Bearer test-token"},
		}
		if err := cfg.Validate(); err == nil {
			t.Errorf("invalid authentication rule %q was accepted", rule)
		}
	}
}

func TestValidateRejectsCaseInsensitiveAuthenticationHeaderDuplicates(t *testing.T) {
	cfg := validConfigForTest()
	cfg.Authentication = AuthenticationConfig{
		AllowedHosts: []string{"https://app.example.com"},
		Headers: map[string]string{
			"Authorization": "Bearer first-token",
			"authorization": "Bearer second-token",
		},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("case-insensitive duplicate authentication headers were accepted: %v", err)
	}
}

func TestValidateAuthenticationCredentialComponent(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		value   string
		wantErr bool
	}{
		{name: "valid bearer", header: "Authorization", value: "Bearer opaque-token"},
		{name: "short bearer credential", header: "Authorization", value: "Bearer x", wantErr: true},
		{name: "missing authorization scheme", header: "Authorization", value: "opaque-token", wantErr: true},
		{name: "placeholder bearer", header: "Authorization", value: "Bearer your-token", wantErr: true},
		{name: "valid custom credential", header: "X-API-Key", value: "opaque-key"},
		{name: "placeholder custom credential", header: "X-API-Key", value: "changeme", wantErr: true},
		{name: "proxy credential forbidden", header: "Proxy-Authorization", value: "Basic b3BhcXVl", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfigForTest()
			cfg.Authentication = AuthenticationConfig{
				AllowedHosts: []string{"https://app.example.com"},
				Headers:      map[string]string{test.header: test.value},
			}
			err := cfg.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestValidateRejectsCookieHeaderAndStructuredCookieCollision(t *testing.T) {
	cfg := validConfigForTest()
	cfg.Authentication = AuthenticationConfig{
		AllowedHosts: []string{"https://app.example.com"},
		Headers:      map[string]string{"cookie": "raw=opaque-value"},
		Cookies:      map[string]string{"session": "structured-value"},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("Cookie header/cookie map collision was accepted: %v", err)
	}
}

func TestValidateRejectsUnsafeAuthenticationHeaders(t *testing.T) {
	cfg := Config{
		AI:       AIConfig{Provider: "deepseek", APIKey: "test-key"},
		Recon:    ReconConfig{Timeout: 1},
		Scanning: ScanningConfig{Threads: 1, RateLimit: 1},
		Analysis: AnalysisConfig{MinConfidence: 0.85},
		Authentication: AuthenticationConfig{
			AllowedHosts: []string{"https://example.com"},
			Headers:      map[string]string{"Host": "evil.example"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unsafe authentication header to be rejected")
	}
}

func TestValidateRequiresAuthenticationAllowedHosts(t *testing.T) {
	cfg := Config{
		AI:             AIConfig{Provider: "deepseek", APIKey: "test-key"},
		Recon:          ReconConfig{Timeout: 1},
		Scanning:       ScanningConfig{Threads: 1, RateLimit: 1},
		Analysis:       AnalysisConfig{MinConfidence: 0.85},
		Authentication: AuthenticationConfig{Headers: map[string]string{"Authorization": "Bearer token-value"}},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected authentication without allowed_hosts to be rejected")
	}
}

func TestSaveAtomicallyReplacesExistingFileWithPrivateMode(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(path, []byte("old: data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{AI: AIConfig{Provider: "custom", APIKey: "opaque-api-key"}}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("saved config permissions = %o, want 600", permissions)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "opaque-api-key") || strings.Contains(string(contents), "old: data") {
		t.Fatalf("saved config contents were not replaced: %q", contents)
	}
	leftovers, err := filepath.Glob(filepath.Join(directory, ".config.yaml.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("temporary config files were left behind: %v", leftovers)
	}
}

func TestSaveReplacesSymlinkWithoutOverwritingItsTarget(t *testing.T) {
	directory := t.TempDir()
	victim := filepath.Join(directory, "victim.txt")
	path := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(victim, []byte("do-not-touch"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	cfg := Config{AI: AIConfig{APIKey: "opaque-api-key"}}
	if err := cfg.Save(path); err != nil {
		t.Fatal(err)
	}
	victimContents, err := os.ReadFile(victim)
	if err != nil {
		t.Fatal(err)
	}
	if string(victimContents) != "do-not-touch" {
		t.Fatalf("Save followed and overwrote symlink target: %q", victimContents)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved config did not replace symlink with private regular file: %v", info.Mode())
	}
}
