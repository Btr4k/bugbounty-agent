package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type Config struct {
	AI            AIConfig            `yaml:"ai" mapstructure:"ai"`
	Claude        ClaudeConfig        `yaml:"claude" mapstructure:"claude"`
	C99           C99Config           `yaml:"c99" mapstructure:"c99"`
	Target        TargetConfig        `yaml:"target" mapstructure:"target"`
	Recon         ReconConfig         `yaml:"recon" mapstructure:"recon"`
	Scanning      ScanningConfig      `yaml:"scanning" mapstructure:"scanning"`
	Analysis      AnalysisConfig      `yaml:"analysis" mapstructure:"analysis"`
	Reporting     ReportingConfig     `yaml:"reporting" mapstructure:"reporting"`
	Notifications NotificationsConfig `yaml:"notifications" mapstructure:"notifications"`
	Logging       LoggingConfig       `yaml:"logging" mapstructure:"logging"`
}

// AIConfig unified AI provider configuration
type AIConfig struct {
	Provider  string `yaml:"provider" mapstructure:"provider"`   // claude, deepseek, openai, openrouter, custom
	APIKey    string `yaml:"api_key" mapstructure:"api_key"`
	Model     string `yaml:"model" mapstructure:"model"`
	MaxTokens int    `yaml:"max_tokens" mapstructure:"max_tokens"`
	BaseURL   string `yaml:"base_url" mapstructure:"base_url"`   // for openrouter/custom
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
	Scope              string   `yaml:"scope" mapstructure:"scope"`
}

type ReconConfig struct {
	Enabled        bool             `yaml:"enabled" mapstructure:"enabled"`
	Timeout        int              `yaml:"timeout" mapstructure:"timeout"`
	MaxSubdomains  int              `yaml:"max_subdomains" mapstructure:"max_subdomains"`
	MaxWaybackURLs int              `yaml:"max_wayback_urls" mapstructure:"max_wayback_urls"`
	Tools          ReconToolsConfig `yaml:"tools" mapstructure:"tools"`
}

type ReconToolsConfig struct {
	Subfinder     bool `yaml:"subfinder" mapstructure:"subfinder"`
	Amass         bool `yaml:"amass" mapstructure:"amass"`
	Assetfinder   bool `yaml:"assetfinder" mapstructure:"assetfinder"`
	GitHubDorking bool `yaml:"github_dorking" mapstructure:"github_dorking"`
	Wayback       bool `yaml:"wayback" mapstructure:"wayback"`
	Katana        bool `yaml:"katana" mapstructure:"katana"`
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
	SQLMap SQLMapConfig `yaml:"sqlmap" mapstructure:"sqlmap"`
	Ffuf   FfufConfig   `yaml:"ffuf" mapstructure:"ffuf"`
	CORS   CORSConfig   `yaml:"cors" mapstructure:"cors"`
}

type FfufConfig struct {
	Enabled       bool   `yaml:"enabled" mapstructure:"enabled"`
	WordlistPath  string `yaml:"wordlist_path" mapstructure:"wordlist_path"`
	MaxTargets    int    `yaml:"max_targets" mapstructure:"max_targets"`
}

type SQLMapConfig struct {
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	MaxURLs int  `yaml:"max_urls" mapstructure:"max_urls"`
}

type CORSConfig struct {
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
}

type NucleiConfig struct {
	Enabled       bool     `yaml:"enabled" mapstructure:"enabled"`
	Severity      []string `yaml:"severity" mapstructure:"severity"`
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
	Enabled       bool   `yaml:"enabled" mapstructure:"enabled"`
	BlindURL      string `yaml:"blind_url" mapstructure:"blind_url"`
	MaxURLs       int    `yaml:"max_urls" mapstructure:"max_urls"`
}

type AnalysisConfig struct {
	Enabled             bool    `yaml:"enabled" mapstructure:"enabled"`
	MinConfidence       float64 `yaml:"min_confidence" mapstructure:"min_confidence"`
	AutoValidate        bool    `yaml:"auto_validate" mapstructure:"auto_validate"`
	FalsePositiveFilter bool    `yaml:"false_positive_filter" mapstructure:"false_positive_filter"`
	JSAnalysis          bool    `yaml:"js_analysis" mapstructure:"js_analysis"`
}

type ReportingConfig struct {
	Format         string   `yaml:"format" mapstructure:"format"`
	Language       string   `yaml:"language" mapstructure:"language"`
	IncludePOC     bool     `yaml:"include_poc" mapstructure:"include_poc"`
	SeverityFilter []string `yaml:"severity_filter" mapstructure:"severity_filter"`
	OutputDir      string   `yaml:"output_dir" mapstructure:"output_dir"`
}

type NotificationsConfig struct {
	Enabled        bool   `yaml:"enabled" mapstructure:"enabled"`
	SlackWebhook   string `yaml:"slack_webhook" mapstructure:"slack_webhook"`
	DiscordWebhook string `yaml:"discord_webhook" mapstructure:"discord_webhook"`
}

type LoggingConfig struct {
	Level     string `yaml:"level" mapstructure:"level"`
	File      string `yaml:"file" mapstructure:"file"`
	MaxSizeMB int    `yaml:"max_size_mb" mapstructure:"max_size_mb"`
}

// loadEnvFile loads environment variables from .env file if it exists
func loadEnvFile() {
	file, err := os.Open(".env")
	if err != nil {
		return // .env file is optional
	}
	defer file.Close()

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
			if os.Getenv(key) == "" { // Don't override existing env vars
				os.Setenv(key, value)
			}
		}
	}
}

// Load loads configuration from file
func Load(filename string) (*Config, error) {
	// Load .env file first
	loadEnvFile()

	// Set defaults
	viper.SetDefault("ai.provider", "deepseek")
	viper.SetDefault("ai.max_tokens", 2000)
	viper.SetDefault("claude.model", "claude-sonnet-4-20250514")
	viper.SetDefault("claude.max_tokens", 4000)
	viper.SetDefault("recon.timeout", 300)
	viper.SetDefault("recon.max_subdomains", 1000)
	viper.SetDefault("recon.max_wayback_urls", 10000)
	viper.SetDefault("scanning.threads", 50)
	viper.SetDefault("scanning.rate_limit", 100)
	viper.SetDefault("analysis.min_confidence", 0.7)
	viper.SetDefault("reporting.format", "markdown")
	viper.SetDefault("reporting.language", "ar")
	viper.SetDefault("c99.enabled", false)

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
		if key := os.Getenv(c.envVar); key != "" && !strings.HasPrefix(key, "your-") {
			return c.provider, key
		}
	}
	return "", ""
}

// ResolveAIConfig fills in AI config defaults based on provider, with backward compat.
// If provider is "auto" (or empty), it detects the provider from whichever env var is set.
func (c *Config) ResolveAIConfig() {
	// Resolve api_key env var expansion first
	if c.AI.APIKey == "${AI_API_KEY}" {
		c.AI.APIKey = ""
	}

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
			c.AI.APIKey = os.Getenv("DEEPSEEK_API_KEY")
		case "openai":
			c.AI.APIKey = os.Getenv("OPENAI_API_KEY")
		case "openrouter":
			c.AI.APIKey = os.Getenv("OPENROUTER_API_KEY")
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
			c.AI.Model = "deepseek-chat"
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
			c.AI.MaxTokens = 2000
		}
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

	// Note: Target.Domains is NOT validated here because it is set from the CLI
	// flag (--target) in main.go AFTER config.Load() returns.

	if c.Recon.Timeout <= 0 {
		return fmt.Errorf("recon timeout must be positive")
	}

	if c.Scanning.Threads <= 0 {
		return fmt.Errorf("scanning threads must be positive")
	}

	return nil
}

// Save saves configuration to file
func (c *Config) Save(filename string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}
