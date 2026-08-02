package config

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type Config struct {
	AI             AIConfig             `yaml:"ai" mapstructure:"ai"`
	Claude         ClaudeConfig         `yaml:"claude" mapstructure:"claude"`
	C99            C99Config            `yaml:"c99" mapstructure:"c99"`
	Target         TargetConfig         `yaml:"target" mapstructure:"target"`
	Authentication AuthenticationConfig `yaml:"authentication" mapstructure:"authentication"`
	Recon          ReconConfig          `yaml:"recon" mapstructure:"recon"`
	Scanning       ScanningConfig       `yaml:"scanning" mapstructure:"scanning"`
	Analysis       AnalysisConfig       `yaml:"analysis" mapstructure:"analysis"`
	Reporting      ReportingConfig      `yaml:"reporting" mapstructure:"reporting"`
	Hunter         HunterConfig         `yaml:"hunter" mapstructure:"hunter"`
}

// AIConfig unified AI provider configuration
type AIConfig struct {
	Provider  string `yaml:"provider" mapstructure:"provider"` // claude, deepseek, openai, openrouter, custom
	APIKey    string `yaml:"api_key" mapstructure:"api_key"`
	Model     string `yaml:"model" mapstructure:"model"`
	MaxTokens int    `yaml:"max_tokens" mapstructure:"max_tokens"`
	BaseURL   string `yaml:"base_url" mapstructure:"base_url"` // for openrouter/custom
	Timeout   int    `yaml:"timeout" mapstructure:"timeout"`   // per-request HTTP timeout in seconds (default 300)
}

type C99Config struct {
	APIKey  string `yaml:"api_key" mapstructure:"api_key"`
	Enabled bool   `yaml:"enabled" mapstructure:"enabled"`
}

type ClaudeConfig struct {
	APIKey    string `yaml:"api_key" mapstructure:"api_key"`
	Model     string `yaml:"model" mapstructure:"model"`
	MaxTokens int    `yaml:"max_tokens" mapstructure:"max_tokens"`
}

type TargetConfig struct {
	Domains            []string `yaml:"domains" mapstructure:"domains"`
	ExcludedSubdomains []string `yaml:"excluded_subdomains" mapstructure:"excluded_subdomains"`
}

// AuthenticationConfig contains optional credentials for authorized,
// authenticated testing. Values may reference environment variables.
type AuthenticationConfig struct {
	AllowedHosts []string          `yaml:"allowed_hosts" mapstructure:"allowed_hosts"`
	Headers      map[string]string `yaml:"headers" mapstructure:"headers"`
	Cookies      map[string]string `yaml:"cookies" mapstructure:"cookies"`
}

func (a AuthenticationConfig) Configured() bool {
	return len(a.Headers)+len(a.Cookies) > 0
}

type ReconConfig struct {
	Enabled        bool             `yaml:"enabled" mapstructure:"enabled"`
	Timeout        int              `yaml:"timeout" mapstructure:"timeout"`
	MaxSubdomains  int              `yaml:"max_subdomains" mapstructure:"max_subdomains"`
	MaxWaybackURLs int              `yaml:"max_wayback_urls" mapstructure:"max_wayback_urls"`
	Tools          ReconToolsConfig `yaml:"tools" mapstructure:"tools"`
}

type ReconToolsConfig struct {
	Subfinder        bool `yaml:"subfinder" mapstructure:"subfinder"`
	Assetfinder      bool `yaml:"assetfinder" mapstructure:"assetfinder"`
	Wayback          bool `yaml:"wayback" mapstructure:"wayback"`
	Katana           bool `yaml:"katana" mapstructure:"katana"`
	CertTransparency bool `yaml:"cert_transparency" mapstructure:"cert_transparency"`
}

type ScanningConfig struct {
	Enabled   bool                `yaml:"enabled" mapstructure:"enabled"`
	Threads   int                 `yaml:"threads" mapstructure:"threads"`
	Timeout   int                 `yaml:"timeout" mapstructure:"timeout"`
	RateLimit int                 `yaml:"rate_limit" mapstructure:"rate_limit"`
	Tools     ScanningToolsConfig `yaml:"tools" mapstructure:"tools"`
}

type ScanningToolsConfig struct {
	Nuclei NucleiConfig `yaml:"nuclei" mapstructure:"nuclei"`
	Httpx  HttpxConfig  `yaml:"httpx" mapstructure:"httpx"`
	Nmap   NmapConfig   `yaml:"nmap" mapstructure:"nmap"`
	Dalfox DalfoxConfig `yaml:"dalfox" mapstructure:"dalfox"`
}

type NucleiConfig struct {
	Enabled       bool     `yaml:"enabled" mapstructure:"enabled"`
	Severity      []string `yaml:"severity" mapstructure:"severity"`
	Tags          []string `yaml:"tags" mapstructure:"tags"`
	TemplatesPath string   `yaml:"templates_path" mapstructure:"templates_path"`
}

type HttpxConfig struct {
	Enabled         bool `yaml:"enabled" mapstructure:"enabled"`
	FollowRedirects bool `yaml:"follow_redirects" mapstructure:"follow_redirects"`
	StatusCode      bool `yaml:"status_code" mapstructure:"status_code"`
}

type NmapConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	Ports    string `yaml:"ports" mapstructure:"ports"`
	FastScan bool   `yaml:"fast_scan" mapstructure:"fast_scan"`
}

type DalfoxConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	BlindURL string `yaml:"blind_url" mapstructure:"blind_url"`
	MaxURLs  int    `yaml:"max_urls" mapstructure:"max_urls"`
}

type AnalysisConfig struct {
	MinConfidence float64 `yaml:"min_confidence" mapstructure:"min_confidence"`
	JSAnalysis    bool    `yaml:"js_analysis" mapstructure:"js_analysis"`
}

type ReportingConfig struct {
	IncludePOC     bool     `yaml:"include_poc" mapstructure:"include_poc"`
	SeverityFilter []string `yaml:"severity_filter" mapstructure:"severity_filter"`
	OutputDir      string   `yaml:"output_dir" mapstructure:"output_dir"`
}

// HunterConfig controls the Phase-1 AI hypothesis engine. It reasons about the
// recon-derived attack surface to produce ranked attack leads (IDOR, access
// control, business logic, SSRF, injection, ...) that signature scanners miss.
// Phase 1 NEVER sends a request to the target — every hypothesis is a lead only.
type HunterConfig struct {
	Enabled       bool `yaml:"enabled" mapstructure:"enabled"`
	MaxHypotheses int  `yaml:"max_hypotheses" mapstructure:"max_hypotheses"` // cap on ranked leads returned
	MaxEndpoints  int  `yaml:"max_endpoints" mapstructure:"max_endpoints"`   // cap on surface entries sent to the model
}

// loadEnvFile loads environment variables from .env file if it exists.
// Rules: system env vars take precedence over .env; within .env, last value wins.
func loadEnvFile() {
	file, err := os.Open(".env")
	if err != nil {
		return // .env file is optional
	}
	defer file.Close()

	// Collect all values first (last duplicate wins within .env)
	values := make(map[string]string)
	order := []string{}
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if !seen[key] {
				order = append(order, key)
				seen[key] = true
			}
			values[key] = value // last value wins
		}
	}

	// Set env vars — skip if already set by system environment
	for _, key := range order {
		if os.Getenv(key) == "" {
			os.Setenv(key, values[key])
		}
	}
}

// Load loads configuration from file
func Load(filename string) (*Config, error) {
	// Load .env file first
	loadEnvFile()
	if err := validateConfigKeys(filename); err != nil {
		return nil, err
	}

	// Set defaults
	viper.SetDefault("ai.provider", "deepseek")
	viper.SetDefault("ai.max_tokens", 4000)
	viper.SetDefault("claude.model", "claude-sonnet-4-20250514")
	viper.SetDefault("claude.max_tokens", 4000)
	viper.SetDefault("recon.timeout", 300)
	viper.SetDefault("recon.max_subdomains", 1000)
	viper.SetDefault("recon.max_wayback_urls", 10000)
	viper.SetDefault("scanning.threads", 50)
	viper.SetDefault("scanning.rate_limit", 100)
	viper.SetDefault("scanning.timeout", 1200)
	viper.SetDefault("ai.timeout", 300)
	viper.SetDefault("analysis.min_confidence", 0.85)
	viper.SetDefault("c99.enabled", false)
	viper.SetDefault("hunter.enabled", true)
	viper.SetDefault("hunter.max_hypotheses", 40)
	viper.SetDefault("hunter.max_endpoints", 120)

	// Read config file
	viper.SetConfigFile(filename)
	viper.SetConfigType("yaml")

	// Enable environment variable override
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Expand environment variables FIRST (before validation)
	cfg.AI.APIKey = os.ExpandEnv(cfg.AI.APIKey)
	cfg.Claude.APIKey = os.ExpandEnv(cfg.Claude.APIKey)
	cfg.C99.APIKey = os.ExpandEnv(cfg.C99.APIKey)
	cfg.Authentication.expandEnv()
	cfg.AI.APIKey = normalizeSecret(cfg.AI.APIKey)
	cfg.Claude.APIKey = normalizeSecret(cfg.Claude.APIKey)
	cfg.C99.APIKey = normalizeSecret(cfg.C99.APIKey)

	// Also check direct env vars as fallback
	if cfg.Claude.APIKey == "" || cfg.Claude.APIKey == "${ANTHROPIC_API_KEY}" {
		if envKey := os.Getenv("ANTHROPIC_API_KEY"); envKey != "" {
			cfg.Claude.APIKey = envKey
		}
	}
	if cfg.C99.APIKey == "" || cfg.C99.APIKey == "${C99_API_KEY}" {
		if envKey := os.Getenv("C99_API_KEY"); envKey != "" {
			cfg.C99.APIKey = envKey
		}
	}

	// Resolve AI provider config with backward compatibility
	cfg.ResolveAIConfig()

	// Validate AFTER expanding env vars
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func validateConfigKeys(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return fmt.Errorf("config contains an unknown or invalid field: %w", err)
	}
	return nil
}

// autoDetectProvider scans environment variables and returns the first provider
// whose API key is set. Priority: claude → deepseek → openai → openrouter.
// Returns ("", "") if no key is found.
func autoDetectProvider() (provider, apiKey string) {
	candidates := []struct {
		provider string
		envVar   string
	}{
		{"claude", "ANTHROPIC_API_KEY"},
		{"deepseek", "DEEPSEEK_API_KEY"},
		{"openai", "OPENAI_API_KEY"},
		{"openrouter", "OPENROUTER_API_KEY"},
	}
	for _, c := range candidates {
		if key := normalizeSecret(os.Getenv(c.envVar)); key != "" {
			return c.provider, key
		}
	}
	return "", ""
}

func normalizeSecret(value string) string {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "your-") ||
		strings.HasPrefix(lower, "replace-with-") ||
		strings.Contains(lower, "changeme") {
		return ""
	}
	return value
}

// ResolveAIConfig fills in AI config defaults based on provider, with backward compat.
// If provider is "auto" (or empty), it detects the provider from whichever env var is set.
func (c *Config) ResolveAIConfig() {
	// Resolve api_key env var expansion first
	if c.AI.APIKey == "${AI_API_KEY}" {
		c.AI.APIKey = ""
	}
	c.AI.APIKey = normalizeSecret(c.AI.APIKey)
	c.Claude.APIKey = normalizeSecret(c.Claude.APIKey)

	// Auto-detect provider from env vars when:
	//   - provider is "auto" or empty
	//   - OR the configured provider's key is missing
	needsAutoDetect := c.AI.Provider == "auto" || c.AI.Provider == ""
	if !needsAutoDetect && c.AI.APIKey == "" {
		// Provider is set but key is missing — try auto-detect as fallback
		needsAutoDetect = true
	}

	if needsAutoDetect {
		if p, k := autoDetectProvider(); p != "" {
			c.AI.Provider = p
			if c.AI.APIKey == "" {
				c.AI.APIKey = k
			}
		}
	}

	// Final fallback provider (must be before key fallback so switch works)
	if c.AI.Provider == "" || c.AI.Provider == "auto" {
		c.AI.Provider = "deepseek"
	}

	// Backward compatibility: if api_key still empty, try provider-specific fallbacks
	if c.AI.APIKey == "" {
		switch c.AI.Provider {
		case "claude":
			c.AI.APIKey = c.Claude.APIKey
		case "deepseek":
			c.AI.APIKey = normalizeSecret(os.Getenv("DEEPSEEK_API_KEY"))
		case "openai":
			c.AI.APIKey = normalizeSecret(os.Getenv("OPENAI_API_KEY"))
		case "openrouter":
			c.AI.APIKey = normalizeSecret(os.Getenv("OPENROUTER_API_KEY"))
		}
	}

	// Backward compat: if model is empty, use provider default
	if c.AI.Model == "" {
		switch c.AI.Provider {
		case "claude":
			if c.Claude.Model != "" {
				c.AI.Model = c.Claude.Model
			} else {
				c.AI.Model = "claude-sonnet-4-20250514"
			}
		case "deepseek":
			c.AI.Model = "deepseek-v4-flash"
		case "openai":
			c.AI.Model = "gpt-4o-mini"
		case "openrouter":
			c.AI.Model = "deepseek/deepseek-chat"
		}
	}

	if c.AI.MaxTokens == 0 {
		if c.Claude.MaxTokens > 0 {
			c.AI.MaxTokens = c.Claude.MaxTokens
		} else {
			// A validation batch is 5 findings, each returning PoC + impact +
			// remediation + context. 2000 truncated the JSON array mid-object,
			// failing the parse and dropping the whole batch to manual-review.
			c.AI.MaxTokens = 4000
		}
	}

	// Per-request HTTP timeout. Large JS-analysis batches on slower providers
	// (e.g. DeepSeek) can take minutes to generate a full response.
	if c.AI.Timeout <= 0 {
		c.AI.Timeout = 300
	}

	// Auto-set base URL for known providers
	if c.AI.BaseURL == "" {
		switch c.AI.Provider {
		case "deepseek":
			c.AI.BaseURL = "https://api.deepseek.com/v1"
		case "openai":
			c.AI.BaseURL = "https://api.openai.com/v1"
		case "openrouter":
			c.AI.BaseURL = "https://openrouter.ai/api/v1"
		}
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.AI.APIKey == "" {
		return fmt.Errorf("AI API key is required (set api_key in ai: section, or ANTHROPIC_API_KEY / DEEPSEEK_API_KEY / OPENAI_API_KEY env var)")
	}

	if c.AI.Provider == "custom" && c.AI.BaseURL == "" {
		return fmt.Errorf("base_url is required when using custom AI provider")
	}
	switch c.AI.Provider {
	case "claude", "deepseek", "openai", "openrouter", "custom":
	default:
		return fmt.Errorf("unsupported AI provider %q", c.AI.Provider)
	}

	// Note: Target.Domains is NOT validated here because it is set from the CLI
	// flag (--target) in main.go AFTER config.Load() returns.

	if c.Recon.Timeout <= 0 {
		return fmt.Errorf("recon timeout must be positive")
	}

	if c.Scanning.Threads <= 0 {
		return fmt.Errorf("scanning threads must be positive")
	}
	if c.Scanning.RateLimit <= 0 {
		return fmt.Errorf("scanning rate limit must be positive")
	}
	if c.Analysis.MinConfidence < 0.85 || c.Analysis.MinConfidence > 1 {
		return fmt.Errorf("analysis min_confidence must be between 0.85 and 1 for reportable findings")
	}
	for _, severity := range c.Reporting.SeverityFilter {
		switch strings.ToLower(severity) {
		case "critical", "high", "medium", "low":
		default:
			return fmt.Errorf("invalid reporting severity %q", severity)
		}
	}
	for name, value := range c.Authentication.Headers {
		name = strings.TrimSpace(name)
		if name == "" || strings.ContainsAny(name, "\r\n") || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("authentication headers must not contain empty names or newlines")
		}
		switch strings.ToLower(name) {
		case "host", "content-length", "transfer-encoding":
			return fmt.Errorf("authentication header %q is not allowed", name)
		}
	}
	for name, value := range c.Authentication.Cookies {
		if strings.TrimSpace(name) == "" || strings.ContainsAny(name+value, "\r\n;") {
			return fmt.Errorf("authentication cookies must not contain empty names, semicolons, or newlines")
		}
	}
	if len(c.Authentication.Headers)+len(c.Authentication.Cookies) > 0 && len(c.Authentication.AllowedHosts) == 0 {
		return fmt.Errorf("authentication allowed_hosts is required when headers or cookies are configured")
	}
	for _, host := range c.Authentication.AllowedHosts {
		normalized := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(host)), "*.")
		if normalized == "" || strings.ContainsAny(normalized, "* /:@\r\n") {
			return fmt.Errorf("invalid authentication allowed host %q", host)
		}
	}

	return nil
}

func (a *AuthenticationConfig) expandEnv() {
	for name, value := range a.Headers {
		a.Headers[name] = os.ExpandEnv(value)
	}
	for name, value := range a.Cookies {
		a.Cookies[name] = os.ExpandEnv(value)
	}
}

// HeaderValues returns authentication headers suitable for HTTP clients and
// external tools. Cookies are emitted as a single Cookie header.
func (a AuthenticationConfig) headerValues() map[string]string {
	headers := make(map[string]string, len(a.Headers)+1)
	for name, value := range a.Headers {
		if strings.TrimSpace(value) != "" {
			headers[name] = value
		}
	}
	if cookie := a.CookieHeader(); cookie != "" {
		headers["Cookie"] = cookie
	}
	return headers
}

// HeaderValuesForTargets returns credentials only when every target is
// explicitly permitted. This prevents a shared tool invocation from leaking a
// session to an untrusted discovered subdomain.
func (a AuthenticationConfig) HeaderValuesForTargets(targets ...string) map[string]string {
	if len(targets) == 0 {
		return nil
	}
	for _, target := range targets {
		if !a.AllowsTarget(target) {
			return nil
		}
	}
	return a.headerValues()
}

func (a AuthenticationConfig) AllowsTarget(raw string) bool {
	host := strings.TrimSpace(strings.ToLower(raw))
	if parsed, err := url.Parse(host); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	} else if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, ".")
	for _, rule := range a.AllowedHosts {
		rule = strings.TrimSpace(strings.ToLower(rule))
		wildcard := strings.HasPrefix(rule, "*.")
		rule = strings.TrimPrefix(rule, "*.")
		if host == rule || (wildcard && strings.HasSuffix(host, "."+rule)) {
			return true
		}
	}
	return false
}

func (a AuthenticationConfig) CookieHeader() string {
	names := make([]string, 0, len(a.Cookies))
	for name, value := range a.Cookies {
		if strings.TrimSpace(value) != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+a.Cookies[name])
	}
	return strings.Join(parts, "; ")
}

// Redact replaces configured secrets with a stable marker before untrusted
// output is logged, sent to an AI provider, or written to a report.
func (c *Config) Redact(value string) string {
	secrets := []string{c.AI.APIKey, c.Claude.APIKey, c.C99.APIKey}
	for _, secret := range c.Authentication.Headers {
		secrets = append(secrets, secret)
		parts := strings.Fields(secret)
		if len(parts) > 1 {
			secrets = append(secrets, parts[len(parts)-1])
		}
	}
	for _, secret := range c.Authentication.Cookies {
		secrets = append(secrets, secret)
	}
	for _, secret := range secrets {
		if len(secret) >= 6 {
			value = strings.ReplaceAll(value, secret, "[REDACTED]")
		}
	}
	return value
}

// Save saves configuration to file
func (c *Config) Save(filename string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
