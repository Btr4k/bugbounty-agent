package config

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/spf13/viper"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/publicsuffix"
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

// loadEnvFile loads only credential variables explicitly used by HawkEye or
// referenced by secret-bearing config fields. This prevents a repository-local
// .env from replacing PATH, HOME, proxy, certificate, or linker settings before
// external tools start. System variables take precedence; the last duplicate
// inside .env wins.
func loadEnvFile(allowed map[string]bool) error {
	info, err := os.Lstat(".env")
	if err != nil {
		if os.IsNotExist(err) {
			return nil // .env is optional
		}
		return fmt.Errorf("inspect .env: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf(".env must be a regular file, not a symlink or special file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(".env permissions are too broad (%o); run chmod 600 .env", info.Mode().Perm())
	}
	if info.Size() > 1<<20 {
		return fmt.Errorf(".env exceeds the 1 MiB safety limit")
	}

	file, err := os.Open(".env")
	if err != nil {
		return fmt.Errorf("open .env: %w", err)
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
		if len(parts) != 2 {
			return fmt.Errorf(".env contains a malformed assignment")
		}
		key := strings.TrimSpace(parts[0])
		if !validEnvironmentName(key) {
			return fmt.Errorf(".env contains an invalid variable name")
		}
		// The caller-provided allowlist is never authoritative for process-control
		// variables. Keep this second check here so a future caller cannot bypass
		// the config-reference validation by passing a broader map directly.
		if !allowed[key] || !isSafeCredentialEnvironmentName(key) {
			continue
		}
		value := strings.TrimSpace(parts[1])
		if !seen[key] {
			order = append(order, key)
			seen[key] = true
		}
		values[key] = value // last value wins
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read .env: %w", err)
	}

	// Set env vars — skip if already set by system environment
	for _, key := range order {
		if os.Getenv(key) == "" {
			if err := os.Setenv(key, values[key]); err != nil {
				return fmt.Errorf("set .env variable %q: %w", key, err)
			}
		}
	}
	return nil
}

func validEnvironmentName(name string) bool {
	if name == "" || (name[0] != '_' && (name[0] < 'A' || name[0] > 'Z') && (name[0] < 'a' || name[0] > 'z')) {
		return false
	}
	for index := 1; index < len(name); index++ {
		character := name[index]
		if character != '_' && (character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

var builtInCredentialEnvironmentNames = map[string]bool{
	"AI_API_KEY":         true,
	"ANTHROPIC_API_KEY":  true,
	"DEEPSEEK_API_KEY":   true,
	"OPENAI_API_KEY":     true,
	"OPENROUTER_API_KEY": true,
	"C99_API_KEY":        true,
}

var deniedEnvironmentNames = map[string]bool{
	"ALL_PROXY": true, "HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true,
	"PATH": true, "HOME": true, "SHELL": true, "PWD": true, "OLDPWD": true,
	"USER": true, "LOGNAME": true, "HOSTNAME": true,
	"TMPDIR": true, "TMP": true, "TEMP": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "SSLKEYLOGFILE": true,
	"REQUESTS_CA_BUNDLE": true, "CURL_CA_BUNDLE": true, "OPENSSL_CONF": true,
	"HOSTALIASES": true, "LOCALDOMAIN": true, "RES_OPTIONS": true,
	"BASH_ENV": true, "ENV": true, "IFS": true, "CDPATH": true, "PROMPT_COMMAND": true,
	"NODE_OPTIONS": true, "NODE_EXTRA_CA_CERTS": true,
	"JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true,
	"PYTHONHOME": true, "PYTHONPATH": true, "PERL5OPT": true, "RUBYOPT": true,
	"GODEBUG": true, "GOMAXPROCS": true, "GOTRACEBACK": true, "GOTOOLCHAIN": true,
	"GOROOT": true, "GOPATH": true, "GOBIN": true, "GOENV": true, "GOFLAGS": true,
	"GOMODCACHE": true, "GOPROXY": true, "GONOSUMDB": true, "GOPRIVATE": true,
	"GOSUMDB": true, "GOVCS": true, "GOWORK": true,
	"COMSPEC": true, "SYSTEMROOT": true, "WINDIR": true, "PATHEXT": true,
}

var deniedEnvironmentPrefixes = []string{
	"LD_", "DYLD_", "CGO_", "GIT_", "SSH_", "SUDO_ASKPASS",
	"BASH_FUNC_", "PYTHON", "PERL", "RUBY", "NODE_", "NPM_",
}

var credentialEnvironmentSuffixes = []string{
	"_API_KEY", "_ACCESS_KEY", "_PRIVATE_KEY", "_KEY",
	"_API_TOKEN", "_ACCESS_TOKEN", "_AUTH_TOKEN", "_TOKEN",
	"_CLIENT_SECRET", "_API_SECRET", "_SECRET",
	"_PASSWORD", "_PASSPHRASE", "_CREDENTIAL", "_CREDENTIALS",
	"_COOKIE", "_SESSION", "_SESSION_ID",
}

// isSafeCredentialEnvironmentName permits only clearly credential-bearing,
// upper-case names and permanently excludes variables that can alter process
// execution, networking, DNS, TLS trust, toolchains, or dynamic linking.
func isSafeCredentialEnvironmentName(name string) bool {
	if !validEnvironmentName(name) || name != strings.ToUpper(name) || deniedEnvironmentNames[name] {
		return false
	}
	for _, prefix := range deniedEnvironmentPrefixes {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}
	if builtInCredentialEnvironmentNames[name] {
		return true
	}
	for _, suffix := range credentialEnvironmentSuffixes {
		if strings.HasSuffix(name, suffix) && len(name) > len(suffix) {
			return true
		}
	}
	return false
}

func allowedEnvironmentNames(filename string) (map[string]bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config contains an unknown or invalid field: %w", err)
	}

	allowed := make(map[string]bool, len(builtInCredentialEnvironmentNames))
	for name := range builtInCredentialEnvironmentNames {
		allowed[name] = true
	}
	var referenceErr error
	collect := func(value string) {
		_ = os.Expand(value, func(name string) string {
			if referenceErr != nil {
				return ""
			}
			if !isSafeCredentialEnvironmentName(name) {
				referenceErr = fmt.Errorf("config references unsafe or non-credential environment variable %q", name)
				return ""
			}
			allowed[name] = true
			return ""
		})
	}
	collect(cfg.AI.APIKey)
	collect(cfg.Claude.APIKey)
	collect(cfg.C99.APIKey)
	for _, value := range cfg.Authentication.Headers {
		collect(value)
	}
	for _, value := range cfg.Authentication.Cookies {
		collect(value)
	}
	if referenceErr != nil {
		return nil, referenceErr
	}
	return allowed, nil
}

func validateConfigKeys(filename string) error {
	_, err := allowedEnvironmentNames(filename)
	return err
}

// Load loads configuration from file
func Load(filename string) (*Config, error) {
	return LoadWithAIOverrides(filename, "", "")
}

// LoadWithAIOverrides loads, resolves CLI provider/model overrides, and then
// validates once. Applying overrides before final validation allows an operator
// to select a configured provider even when the file's default provider has no
// key in the current environment.
func LoadWithAIOverrides(filename, provider, model string) (*Config, error) {
	allowedEnv, err := allowedEnvironmentNames(filename)
	if err != nil {
		return nil, err
	}
	if err := loadEnvFile(allowedEnv); err != nil {
		return nil, err
	}

	// Set defaults
	viper.SetDefault("ai.provider", "")
	viper.SetDefault("ai.max_tokens", 4000)
	viper.SetDefault("claude.model", "claude-sonnet-5")
	viper.SetDefault("claude.max_tokens", 4000)
	viper.SetDefault("recon.timeout", 300)
	viper.SetDefault("recon.max_subdomains", 1000)
	viper.SetDefault("recon.max_wayback_urls", 10000)
	viper.SetDefault("scanning.threads", 10)
	viper.SetDefault("scanning.rate_limit", 25)
	viper.SetDefault("scanning.timeout", 1200)
	viper.SetDefault("ai.timeout", 300)
	viper.SetDefault("analysis.min_confidence", 0.85)
	viper.SetDefault("c99.enabled", false)
	viper.SetDefault("hunter.enabled", false)
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
	if strings.TrimSpace(provider) != "" || strings.TrimSpace(model) != "" {
		if err := cfg.ApplyAIOverrides(provider, model); err != nil {
			return nil, err
		}
		return &cfg, nil
	}

	// Validate AFTER expanding env vars
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// autoDetectProvider resolves only when exactly one provider-specific key is
// configured. Multiple keys are deliberately ambiguous: silently preferring a
// vendor would be both surprising and a potential cross-provider key mix-up.
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
	foundProvider, foundKey := "", ""
	for _, c := range candidates {
		if key := normalizeSecret(os.Getenv(c.envVar)); key != "" {
			if foundProvider != "" {
				return "", ""
			}
			foundProvider, foundKey = c.provider, key
		}
	}
	return foundProvider, foundKey
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
// Provider discovery is intentionally opt-in: only provider "auto" inspects
// keys belonging to other providers. An empty provider is invalid.
func (c *Config) ResolveAIConfig() {
	// Resolve api_key env var expansion first
	if c.AI.APIKey == "${AI_API_KEY}" {
		c.AI.APIKey = ""
	}
	c.AI.APIKey = normalizeSecret(c.AI.APIKey)
	c.Claude.APIKey = normalizeSecret(c.Claude.APIKey)
	c.AI.Provider = strings.ToLower(strings.TrimSpace(c.AI.Provider))

	// Auto-detection must be explicit. In particular, a missing key for an
	// explicitly selected provider must never redirect prompts to another party.
	if c.AI.Provider == "auto" {
		// A generic key cannot be safely associated with whichever provider wins
		// environment-based detection. Leave the provider unresolved so Validate
		// fails closed instead of sending one vendor's credential to another.
		if c.AI.APIKey != "" {
			return
		}
		if p, k := autoDetectProvider(); p != "" {
			c.AI.Provider = p
			c.AI.APIKey = k
		}
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

	// Backward compat: if model is empty, use provider default.
	if c.AI.Model == "" {
		c.AI.Model = DefaultAIModel(c.AI.Provider)
		if c.AI.Provider == "claude" && c.Claude.Model != "" {
			c.AI.Model = c.Claude.Model
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

	// Auto-set base URL for hosted providers. Validate later rejects any
	// non-equivalent override and directs custom gateways to provider "custom".
	if c.AI.BaseURL == "" {
		c.AI.BaseURL = officialAIBaseURL(c.AI.Provider)
	}
}

func officialAIBaseURL(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "deepseek":
		return "https://api.deepseek.com/v1"
	case "openai":
		return "https://api.openai.com/v1"
	case "openrouter":
		return "https://openrouter.ai/api/v1"
	default:
		return ""
	}
}

// DefaultAIModel returns the built-in model for a resolved provider. Custom
// providers deliberately have no default and must name their model explicitly.
func DefaultAIModel(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude":
		return "claude-sonnet-5"
	case "deepseek":
		return "deepseek-v4-flash"
	case "openai":
		return "gpt-4o-mini"
	case "openrouter":
		return "deepseek/deepseek-v4-flash"
	default:
		return ""
	}
}

// ApplyAIOverrides applies CLI-style provider/model overrides as one coherent
// operation. Changing provider clears provider-derived values before resolving
// the new provider, preventing a model, key, or base URL from the old provider
// from being reused accidentally. A non-empty model is always an explicit
// override and is preserved.
func (c *Config) ApplyAIOverrides(provider, model string) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	model = strings.TrimSpace(model)
	if provider != "" {
		if provider == "custom" && strings.ToLower(strings.TrimSpace(c.AI.Provider)) != "custom" {
			return fmt.Errorf("custom provider must be configured in the YAML file with api_key, model, and base_url")
		}
		if provider != strings.ToLower(strings.TrimSpace(c.AI.Provider)) {
			c.AI.APIKey = ""
			c.AI.Model = ""
			c.AI.BaseURL = ""
		}
		c.AI.Provider = provider
	}
	if model != "" {
		c.AI.Model = model
	}
	c.ResolveAIConfig()
	return c.Validate()
}

// Validate validates the configuration
func (c *Config) Validate() error {
	switch c.AI.Provider {
	case "claude", "deepseek", "openai", "openrouter", "custom":
	case "auto":
		if c.AI.APIKey != "" {
			return fmt.Errorf("ai.api_key must be empty when provider is auto; configure a provider-specific environment key")
		}
		return fmt.Errorf("AI provider auto could not detect a configured provider API key")
	default:
		return fmt.Errorf("unsupported AI provider %q", c.AI.Provider)
	}
	if c.AI.APIKey == "" {
		return fmt.Errorf("AI API key is required for explicit provider %q", c.AI.Provider)
	}
	if len(c.AI.APIKey) < 4 {
		return fmt.Errorf("AI API key is implausibly short")
	}
	if strings.TrimSpace(c.AI.Model) == "" {
		return fmt.Errorf("AI model is required for provider %q", c.AI.Provider)
	}
	if c.AI.MaxTokens <= 0 || c.AI.MaxTokens > 200000 {
		return fmt.Errorf("AI max_tokens must be between 1 and 200000")
	}
	if c.AI.Timeout <= 0 || c.AI.Timeout > 3600 {
		return fmt.Errorf("AI timeout must be between 1 and 3600 seconds")
	}
	if expectedBaseURL := officialAIBaseURL(c.AI.Provider); expectedBaseURL != "" {
		if c.AI.BaseURL == "" {
			c.AI.BaseURL = expectedBaseURL
		} else if err := validateOfficialAIBaseURL(c.AI.Provider, c.AI.BaseURL, expectedBaseURL); err != nil {
			return err
		} else {
			// Avoid double-slash path behavior and make the validated endpoint the
			// exact value consumed by the provider client.
			c.AI.BaseURL = expectedBaseURL
		}
	} else if c.AI.Provider == "custom" {
		if c.AI.BaseURL == "" {
			return fmt.Errorf("base_url is required when using custom AI provider")
		}
		if strings.TrimSpace(c.AI.Model) == "" {
			return fmt.Errorf("model is required when using custom AI provider")
		}
		if err := validateAIBaseURL(c.AI.BaseURL); err != nil {
			return err
		}
	} else if c.AI.BaseURL != "" {
		return fmt.Errorf("provider %q uses a fixed endpoint; use provider %q for a custom base_url", c.AI.Provider, "custom")
	}

	// Note: Target.Domains is NOT validated here because it is set from the CLI
	// flag (--target) in main.go AFTER config.Load() returns.

	if c.C99.Enabled && len(strings.TrimSpace(c.C99.APIKey)) < 4 {
		return fmt.Errorf("c99 api_key is required when c99 is enabled")
	}
	if c.Recon.Timeout <= 0 || c.Recon.Timeout > 86400 {
		return fmt.Errorf("recon timeout must be between 1 and 86400 seconds")
	}
	if c.Recon.MaxSubdomains < 0 || c.Recon.MaxSubdomains > 100000 ||
		c.Recon.MaxWaybackURLs < 0 || c.Recon.MaxWaybackURLs > 1000000 {
		return fmt.Errorf("recon caps exceed the supported bounds")
	}

	if c.Scanning.Threads <= 0 || c.Scanning.Threads > 1000 {
		return fmt.Errorf("scanning threads must be between 1 and 1000")
	}
	if c.Scanning.RateLimit <= 0 || c.Scanning.RateLimit > 10000 {
		return fmt.Errorf("scanning rate limit must be between 1 and 10000")
	}
	if c.Scanning.Timeout <= 0 || c.Scanning.Timeout > 86400 {
		return fmt.Errorf("scanning timeout must be between 1 and 86400 seconds")
	}
	if c.Scanning.Tools.Dalfox.MaxURLs < 0 || c.Scanning.Tools.Dalfox.MaxURLs > 10000 {
		return fmt.Errorf("dalfox max_urls must be between 0 and 10000")
	}
	if c.Scanning.Tools.Dalfox.BlindURL != "" {
		if err := validateBlindCallbackURL(c.Scanning.Tools.Dalfox.BlindURL); err != nil {
			return err
		}
	}
	if err := validateNmapPorts(c.Scanning.Tools.Nmap.Ports); err != nil {
		return err
	}
	if len(c.Scanning.Tools.Nuclei.Severity) > 5 || len(c.Scanning.Tools.Nuclei.Tags) > 100 {
		return fmt.Errorf("nuclei severity or tag list exceeds the supported bound")
	}
	for _, severity := range c.Scanning.Tools.Nuclei.Severity {
		switch strings.ToLower(strings.TrimSpace(severity)) {
		case "critical", "high", "medium", "low", "info":
		default:
			return fmt.Errorf("invalid nuclei severity %q", severity)
		}
	}
	for _, tag := range c.Scanning.Tools.Nuclei.Tags {
		if !validScannerLabel(tag, 80) {
			return fmt.Errorf("invalid nuclei tag %q", tag)
		}
	}
	if path := c.Scanning.Tools.Nuclei.TemplatesPath; len(path) > 4096 || strings.ContainsAny(path, "\r\n\x00") {
		return fmt.Errorf("nuclei templates_path is invalid")
	}
	if c.Hunter.Enabled {
		if c.Hunter.MaxHypotheses <= 0 || c.Hunter.MaxHypotheses > 200 {
			return fmt.Errorf("hunter max_hypotheses must be between 1 and 200")
		}
		if c.Hunter.MaxEndpoints <= 0 || c.Hunter.MaxEndpoints > 1000 {
			return fmt.Errorf("hunter max_endpoints must be between 1 and 1000")
		}
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
	seenHeaderNames := make(map[string]string, len(c.Authentication.Headers))
	for name, value := range c.Authentication.Headers {
		if name == "" || name != strings.TrimSpace(name) ||
			!httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
			return fmt.Errorf("authentication header %q has an invalid HTTP field name or value", name)
		}
		canonicalName := strings.ToLower(name)
		if previous, duplicate := seenHeaderNames[canonicalName]; duplicate {
			return fmt.Errorf("authentication headers %q and %q are duplicate names ignoring case", previous, name)
		}
		seenHeaderNames[canonicalName] = name
		switch canonicalName {
		case "host", "content-length", "transfer-encoding", "connection",
			"proxy-authorization", "proxy-connection", "keep-alive", "te", "trailer", "upgrade":
			return fmt.Errorf("authentication header %q is not allowed", name)
		}
		if canonicalName == "cookie" && len(c.Authentication.Cookies) > 0 {
			return fmt.Errorf("authentication header %q conflicts with authentication cookies", name)
		}
		if err := validateAuthenticationCredential(name, value); err != nil {
			return err
		}
	}
	for name, value := range c.Authentication.Cookies {
		if strings.TrimSpace(name) == "" || !httpguts.ValidHeaderFieldName(name) ||
			strings.ContainsAny(value, "\r\n;\x00") || !utf8.ValidString(value) {
			return fmt.Errorf("authentication cookie %q has an invalid name or value", name)
		}
		if len(strings.TrimSpace(value)) < 4 {
			return fmt.Errorf("authentication cookie %q value must contain at least 4 characters", name)
		}
	}
	if len(c.Authentication.Headers)+len(c.Authentication.Cookies) > 0 && len(c.Authentication.AllowedHosts) == 0 {
		return fmt.Errorf("authentication allowed_hosts is required when headers or cookies are configured")
	}
	for _, host := range c.Authentication.AllowedHosts {
		rule, err := parseAuthenticationRule(host)
		if err != nil {
			return fmt.Errorf("invalid authentication allowed host %q", host)
		}
		if c.Authentication.Configured() && !rule.origin {
			return fmt.Errorf("authentication allowed host %q must be an explicit HTTPS origin", host)
		}
	}

	return nil
}

func validScannerLabel(value string, maxLength int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxLength {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validateNmapPorts(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if len(raw) > 4096 {
		return fmt.Errorf("nmap ports expression is too long")
	}
	for _, item := range strings.Split(raw, ",") {
		bounds := strings.Split(strings.TrimSpace(item), "-")
		if len(bounds) < 1 || len(bounds) > 2 {
			return fmt.Errorf("invalid nmap ports expression")
		}
		values := make([]int, len(bounds))
		for index, bound := range bounds {
			port, err := strconv.Atoi(bound)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid nmap port %q", bound)
			}
			values[index] = port
		}
		if len(values) == 2 && values[0] > values[1] {
			return fmt.Errorf("invalid descending nmap port range")
		}
	}
	return nil
}

func validateBlindCallbackURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return fmt.Errorf("dalfox blind_url must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("dalfox blind_url must not contain credentials, a query, or a fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") {
		return fmt.Errorf("dalfox blind_url must not target a local host")
	}
	if ip := net.ParseIP(host); ip != nil && !isPublicAIEndpointIP(ip) {
		return fmt.Errorf("dalfox blind_url must not target a private or special-use address")
	}
	return nil
}

func validateAIBaseURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("AI base_url must be an absolute HTTPS URL")
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return fmt.Errorf("AI base_url must use HTTPS")
	}
	if parsed.User != nil {
		return fmt.Errorf("AI base_url must not contain user credentials")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("AI base_url must not contain a query or fragment")
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if host == "" {
		return fmt.Errorf("AI base_url must include a host")
	}
	if host == "localhost" || host == "local" ||
		strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".home.arpa") {
		return fmt.Errorf("AI base_url must not target a local host")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ip = parseLegacyIPv4(host)
	}
	if ip != nil && !isPublicAIEndpointIP(ip) {
		return fmt.Errorf("AI base_url must not target a private, loopback, link-local, or unspecified address")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return fmt.Errorf("AI base_url contains an invalid port")
		}
	}
	return nil
}

func validateOfficialAIBaseURL(provider, raw, expected string) error {
	if err := validateAIBaseURL(raw); err != nil {
		return err
	}
	parsed, _ := url.Parse(strings.TrimSpace(raw))
	expectedURL, _ := url.Parse(expected)
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	if !strings.EqualFold(parsed.Scheme, expectedURL.Scheme) ||
		!strings.EqualFold(strings.TrimSuffix(parsed.Hostname(), "."), expectedURL.Hostname()) ||
		port != "443" || parsed.RawPath != "" ||
		strings.TrimRight(parsed.EscapedPath(), "/") != strings.TrimRight(expectedURL.EscapedPath(), "/") {
		return fmt.Errorf("provider %q requires base_url %q; use provider %q for an arbitrary endpoint", provider, expected, "custom")
	}
	return nil
}

func isPublicAIEndpointIP(ip net.IP) bool {
	return ip.IsGlobalUnicast() &&
		!ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsUnspecified() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast()
}

// parseLegacyIPv4 covers numeric forms accepted by common system resolvers but
// rejected by net.ParseIP, such as 127.1, 0177.0.0.1, and 2130706433. Without
// this check those spellings can bypass a loopback/private-address policy.
func parseLegacyIPv4(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return nil
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return nil
		}
		value, err := strconv.ParseUint(part, 0, 32)
		if err != nil {
			return nil
		}
		values[i] = value
	}

	var address uint64
	switch len(values) {
	case 1:
		address = values[0]
	case 2:
		if values[0] > 0xff || values[1] > 0xffffff {
			return nil
		}
		address = values[0]<<24 | values[1]
	case 3:
		if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
			return nil
		}
		address = values[0]<<24 | values[1]<<16 | values[2]
	case 4:
		for _, value := range values {
			if value > 0xff {
				return nil
			}
		}
		address = values[0]<<24 | values[1]<<16 | values[2]<<8 | values[3]
	}
	if address > 0xffffffff {
		return nil
	}
	return net.IPv4(byte(address>>24), byte(address>>16), byte(address>>8), byte(address))
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

type authenticationOrigin struct {
	scheme   string
	host     string
	port     string
	wildcard bool
	origin   bool
}

func parseAuthenticationRule(raw string) (authenticationOrigin, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n") {
		return authenticationOrigin{}, fmt.Errorf("empty or multiline rule")
	}

	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return authenticationOrigin{}, fmt.Errorf("invalid origin")
		}
		if !strings.EqualFold(parsed.Scheme, "https") {
			return authenticationOrigin{}, fmt.Errorf("authentication origins must use HTTPS")
		}
		if parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
			return authenticationOrigin{}, fmt.Errorf("origin must not contain credentials, a path, query, or fragment")
		}
		host := parsed.Hostname()
		wildcard := strings.HasPrefix(host, "*.")
		host = strings.TrimPrefix(host, "*.")
		canonicalHost, hostErr := canonicalAuthenticationHost(host)
		if hostErr != nil {
			return authenticationOrigin{}, fmt.Errorf("invalid origin host")
		}
		host = canonicalHost
		if wildcard {
			if net.ParseIP(host) != nil {
				return authenticationOrigin{}, fmt.Errorf("wildcard origin cannot target an IP address")
			}
			if _, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil {
				return authenticationOrigin{}, fmt.Errorf("wildcard origin must be below a registrable domain")
			}
		}
		port, err := normalizedOriginPort(strings.ToLower(parsed.Scheme), parsed.Port())
		if err != nil {
			return authenticationOrigin{}, err
		}
		return authenticationOrigin{
			scheme: strings.ToLower(parsed.Scheme), host: host, port: port,
			wildcard: wildcard, origin: true,
		}, nil
	}

	wildcard := strings.HasPrefix(raw, "*.")
	host, err := canonicalAuthenticationHost(strings.TrimPrefix(raw, "*."))
	if err != nil {
		return authenticationOrigin{}, fmt.Errorf("invalid host")
	}
	if wildcard {
		if net.ParseIP(host) != nil {
			return authenticationOrigin{}, fmt.Errorf("wildcard host cannot target an IP address")
		}
		if _, err := publicsuffix.EffectiveTLDPlusOne(host); err != nil {
			return authenticationOrigin{}, fmt.Errorf("wildcard host must be below a registrable domain")
		}
	}
	return authenticationOrigin{host: host, wildcard: wildcard}, nil
}

func parseAuthenticationTarget(raw string) (authenticationOrigin, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "\r\n") {
		return authenticationOrigin{}, false
	}

	hasOrigin := strings.Contains(raw, "://")
	toParse := raw
	if !hasOrigin {
		toParse = "//" + raw
	}
	parsed, err := url.Parse(toParse)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return authenticationOrigin{}, false
	}
	host, err := canonicalAuthenticationHost(parsed.Hostname())
	if err != nil {
		return authenticationOrigin{}, false
	}

	target := authenticationOrigin{host: host, origin: hasOrigin}
	if hasOrigin {
		target.scheme = strings.ToLower(parsed.Scheme)
		if target.scheme != "http" && target.scheme != "https" {
			return authenticationOrigin{}, false
		}
		target.port, err = normalizedOriginPort(target.scheme, parsed.Port())
		if err != nil {
			return authenticationOrigin{}, false
		}
	}
	return target, true
}

func normalizedOriginPort(scheme, port string) (string, error) {
	if port == "" {
		if scheme == "https" {
			return "443", nil
		}
		if scheme == "http" {
			return "80", nil
		}
		return "", fmt.Errorf("unsupported origin scheme")
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return "", fmt.Errorf("invalid origin port")
	}
	return strconv.Itoa(value), nil
}

func canonicalAuthenticationHost(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if host == "" || len(host) > 253 {
		return "", fmt.Errorf("invalid host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if strings.ContainsAny(host, "* /:@[]%\r\n") {
		return "", fmt.Errorf("invalid host")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid DNS label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", fmt.Errorf("non-ASCII or invalid DNS label")
			}
		}
	}
	return host, nil
}

func validateAuthenticationCredential(name, value string) error {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 4 {
		return fmt.Errorf("authentication header %q value must contain at least 4 characters", name)
	}
	canonicalName := strings.ToLower(name)
	if canonicalName != "authorization" {
		if normalizeSecret(trimmed) == "" {
			return fmt.Errorf("authentication header %q contains a placeholder credential", name)
		}
		return nil
	}
	separator := strings.IndexAny(trimmed, " \t")
	if separator <= 0 || !httpguts.ValidHeaderFieldName(trimmed[:separator]) {
		return fmt.Errorf("authentication header %q must contain an authentication scheme and credential", name)
	}
	credential := strings.TrimSpace(trimmed[separator+1:])
	if len(credential) < 4 {
		return fmt.Errorf("authentication header %q credential must contain at least 4 characters", name)
	}
	if normalizeSecret(credential) == "" {
		return fmt.Errorf("authentication header %q contains a placeholder credential", name)
	}
	return nil
}

// AllowsTarget matches validated HTTPS origin rules by exact scheme, effective
// port, and host. A wildcard origin matches child hosts only, never its apex.
func (a AuthenticationConfig) AllowsTarget(raw string) bool {
	target, ok := parseAuthenticationTarget(raw)
	if !ok {
		return false
	}
	for _, rawRule := range a.AllowedHosts {
		rule, err := parseAuthenticationRule(rawRule)
		if err != nil {
			continue
		}
		if rule.origin && (!target.origin || target.scheme != rule.scheme || target.port != rule.port) {
			continue
		}
		if (!rule.wildcard && target.host == rule.host) ||
			(rule.wildcard && strings.HasSuffix(target.host, "."+rule.host)) {
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
	secrets := c.secretValues()
	// Validated credentials are at least four characters. Ignore shorter values
	// on defensive direct calls so a one-character misconfiguration cannot
	// corrupt every occurrence of that character in output.
	sort.SliceStable(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	seen := make(map[string]bool, len(secrets))
	for _, secret := range secrets {
		if len(secret) < 4 || seen[secret] {
			continue
		}
		seen[secret] = true
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

func (c *Config) secretValues() []string {
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
	return secrets
}

// ExternalToolEnvironment returns a minimal operational allowlist. Third-party
// recon/scanner binaries do not inherit arbitrary parent or .env variables,
// including credentials whose names HawkEye does not know in advance.
func ExternalToolEnvironment() []string {
	allowed := map[string]bool{
		"PATH": true, "HOME": true, "USER": true, "LOGNAME": true,
		"TMPDIR": true, "TMP": true, "TEMP": true,
		"LANG": true, "LANGUAGE": true, "TERM": true, "COLORTERM": true,
		"TZ": true, "NO_COLOR": true,
		"LC_ALL": true, "LC_COLLATE": true, "LC_CTYPE": true,
		"LC_MESSAGES": true, "LC_MONETARY": true, "LC_NUMERIC": true,
		"LC_TIME": true, "LC_ADDRESS": true, "LC_IDENTIFICATION": true,
		"LC_MEASUREMENT": true, "LC_NAME": true, "LC_PAPER": true,
		"LC_TELEPHONE":    true,
		"XDG_CONFIG_HOME": true, "XDG_CACHE_HOME": true, "XDG_DATA_HOME": true,
		"SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
	}
	environment := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		// Environment names are case-sensitive on Linux. Case-folding here would
		// accidentally pass an unrelated secret named, for example, "path" merely
		// because PATH is operationally allowlisted. Locale variables are explicit
		// too; an arbitrary LC_* prefix is not a safe credential boundary.
		name := parts[0]
		if allowed[name] {
			environment = append(environment, entry)
		}
	}
	return environment
}

// Save saves configuration to file
func (c *Config) Save(filename string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	directory := filepath.Dir(filename)
	temporary, err := os.CreateTemp(directory, "."+filepath.Base(filename)+".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create private temporary config: %w", err)
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("failed to restrict temporary config permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("failed to write temporary config: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary config: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("failed to close temporary config: %w", err)
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("failed to atomically replace config: %w", err)
	}
	removeTemporary = false

	return nil
}
