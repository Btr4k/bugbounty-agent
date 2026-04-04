package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/A-cyb3r/hawkeye/internal/scanner"
)

// ═══════════════════════════════════════════════════════════
// JS Regex Pre-Scanner — Fast pattern matching before AI
// Catches sensitive data the AI might miss in truncated files
// ═══════════════════════════════════════════════════════════

type regexPattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity string
	Type     string
}

// Compiled patterns for maximum performance
var jsPatterns = []regexPattern{
	// ═══ API Keys & Tokens ═══
	{
		Name:     "AWS Access Key",
		Pattern:  regexp.MustCompile(`(?i)(AKIA|ASIA)[0-9A-Z]{16}`),
		Severity: "critical",
		Type:     "aws_key",
	},
	{
		Name:     "AWS Secret Key",
		Pattern:  regexp.MustCompile(`(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
		Severity: "critical",
		Type:     "aws_secret",
	},
	{
		Name:     "Google API Key",
		Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		Severity: "low",
		Type:     "google_api_key",
	},
	{
		Name:     "Google OAuth Token",
		Pattern:  regexp.MustCompile(`ya29\.[0-9A-Za-z_-]+`),
		Severity: "critical",
		Type:     "google_oauth",
	},
	{
		Name:     "Stripe Secret Key",
		Pattern:  regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
		Severity: "critical",
		Type:     "stripe_key",
	},
	{
		Name:     "Stripe Publishable Key",
		Pattern:  regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`),
		Severity: "medium",
		Type:     "stripe_pub_key",
	},
	{
		Name:     "GitHub Token",
		Pattern:  regexp.MustCompile(`(ghp_[0-9a-zA-Z]{36}|gho_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})`),
		Severity: "critical",
		Type:     "github_token",
	},
	{
		Name:     "Slack Token",
		Pattern:  regexp.MustCompile(`xox[bpsar]-[0-9a-zA-Z-]{10,}`),
		Severity: "critical",
		Type:     "slack_token",
	},
	{
		Name:     "Twilio API Key",
		Pattern:  regexp.MustCompile(`SK[0-9a-fA-F]{32}`),
		Severity: "critical",
		Type:     "twilio_key",
	},
	{
		Name:     "SendGrid API Key",
		Pattern:  regexp.MustCompile(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`),
		Severity: "critical",
		Type:     "sendgrid_key",
	},
	{
		Name:     "Mailgun API Key",
		Pattern:  regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		Severity: "critical",
		Type:     "mailgun_key",
	},
	{
		Name:     "Firebase Config",
		Pattern:  regexp.MustCompile(`(?i)firebase[a-zA-Z]*\.initializeApp\s*\(`),
		Severity: "low",
		Type:     "firebase_config",
	},

	// ═══ JWT & Session Tokens ═══
	{
		Name:     "JWT Token",
		Pattern:  regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+`),
		Severity: "high",
		Type:     "jwt",
	},
	{
		Name:     "Bearer Token (hardcoded)",
		Pattern:  regexp.MustCompile(`(?i)["']Bearer\s+[a-zA-Z0-9_\-.]{20,}["']`),
		Severity: "critical",
		Type:     "bearer_token",
	},
	{
		Name:     "Authorization Header",
		Pattern:  regexp.MustCompile(`(?i)["']authorization["']\s*:\s*["'](Basic|Bearer|Token)\s+[a-zA-Z0-9_\-./+=]+["']`),
		Severity: "critical",
		Type:     "auth_header",
	},

	// ═══ Credentials ═══
	{
		Name:     "Hardcoded Password",
		Pattern:  regexp.MustCompile(`(?i)(password|passwd|pwd|pass)\s*[=:]\s*["'][^"']{4,}["']`),
		Severity: "critical",
		Type:     "hardcoded_password",
	},
	{
		Name:     "Database Connection String",
		Pattern:  regexp.MustCompile(`(?i)(mongodb|mysql|postgres|redis|amqp):\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9._-]+`),
		Severity: "critical",
		Type:     "database_url",
	},
	{
		Name:     "Private Key",
		Pattern:  regexp.MustCompile(`-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----`),
		Severity: "critical",
		Type:     "private_key",
	},
	{
		Name:     "URL with Credentials",
		Pattern:  regexp.MustCompile(`https?://[a-zA-Z0-9_]+:[^@\s"']+@[a-zA-Z0-9._-]+`),
		Severity: "critical",
		Type:     "url_credentials",
	},

	// ═══ Internal Endpoints & APIs ═══
	{
		Name:     "Admin/Internal API Endpoint",
		Pattern:  regexp.MustCompile(`(?i)["'](/api/(admin|internal|debug|private|v[0-9]+/(admin|internal|users|config|settings|delete|upload|reset|token|auth)))[/"']`),
		Severity: "high",
		Type:     "internal_api",
	},
	{
		// Catches ALL /api/vN/... endpoints — for attack surface mapping
		Name:    "API Versioned Endpoint",
		Pattern: regexp.MustCompile(`(?i)["'](/api/v[0-9]+/[a-zA-Z0-9/_-]{3,50})[/"']`),
		Severity: "medium",
		Type:    "api_endpoint",
	},
	{
		// Catches /api/something patterns not caught by above
		Name:    "API Endpoint",
		Pattern: regexp.MustCompile(`(?i)["'](/api/[a-zA-Z0-9/_-]{3,60})[/"']`),
		Severity: "low",
		Type:    "api_endpoint_generic",
	},
	{
		Name:     "GraphQL Endpoint",
		Pattern:  regexp.MustCompile(`(?i)["'](https?://[^"']*/(graphql|graphiql|playground))[/"']`),
		Severity: "medium",
		Type:     "graphql_endpoint",
	},
	{
		Name:     "WebSocket Endpoint",
		Pattern:  regexp.MustCompile(`(?i)["'](wss?://[^"'\s]+)["']`),
		Severity: "medium",
		Type:     "websocket_endpoint",
	},
	{
		// Full external API URLs hardcoded in JS
		Name:    "Hardcoded External API URL",
		Pattern: regexp.MustCompile(`(?i)["'](https?://[a-zA-Z0-9._-]{4,}/[a-zA-Z0-9/_-]{3,})['"]\s*[,;]`),
		Severity: "low",
		Type:    "hardcoded_url",
	},
	{
		Name:     "Hardcoded Internal IP",
		Pattern:  regexp.MustCompile(`["'](10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})["']`),
		Severity: "medium",
		Type:     "internal_ip",
	},
	{
		// S3 bucket names exposed in JS
		Name:    "S3 Bucket URL",
		Pattern: regexp.MustCompile(`(?i)["'](https?://[a-zA-Z0-9._-]+\.s3[.-][a-zA-Z0-9._-]*\.amazonaws\.com[^"']*)['"']`),
		Severity: "high",
		Type:    "s3_bucket",
	},

	// ═══ Security Misconfigurations ═══
	{
		// Only match definite assignments: debug: true  or  debug = true
		// NOT conditional checks like: if(t.debug), settings.debug&&, t&&t.debug
		Name:     "Debug Mode Enabled",
		Pattern:  regexp.MustCompile(`(?i)[^.\w](debug)\s*[=:]\s*(true|1|"true"|'true')`),
		Severity: "medium",
		Type:     "debug_mode",
	},
	{
		Name:     "CORS Wildcard in Code",
		Pattern:  regexp.MustCompile(`(?i)Access-Control-Allow-Origin['":\s]+\*`),
		Severity: "medium",
		Type:     "cors_wildcard",
	},
	{
		Name:     "DOM XSS Sink (innerHTML)",
		Pattern:  regexp.MustCompile(`\.innerHTML\s*=\s*[^"'][a-zA-Z]`),
		Severity: "medium",
		Type:     "dom_xss_sink",
	},
	{
		Name:     "Eval with Variable",
		Pattern:  regexp.MustCompile(`eval\s*\([^)"']+\)`),
		Severity: "medium",
		Type:     "eval_usage",
	},
	{
		Name:     "PostMessage without Origin Check",
		Pattern:  regexp.MustCompile(`(?i)addEventListener\s*\(\s*["']message["']`),
		Severity: "low",
		Type:     "postmessage_listener",
	},

	// ═══ Sensitive Data Exposure ═══
	{
		Name:     "Email Address",
		Pattern:  regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		Severity: "low",
		Type:     "email",
	},
	{
		Name:     "Generic Secret/API Key Pattern",
		Pattern:  regexp.MustCompile(`(?i)(api[_\-]?key|api[_\-]?secret|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)\s*[=:]\s*["'][a-zA-Z0-9_\-./+=]{16,}["']`),
		Severity: "high",
		Type:     "generic_secret",
	},
}

// ExtractCoreSecret strips surrounding context (e.g. apiKey:"AIza...") from a
// matched string and returns the bare token/key for deduplication purposes.
// This prevents the same key matched by two patterns from appearing twice.
var coreSecretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),                          // AWS
	regexp.MustCompile(`(AIza[0-9A-Za-z_-]{35})`),                     // Google
	regexp.MustCompile(`(ya29\.[0-9A-Za-z_-]+)`),                      // Google OAuth
	regexp.MustCompile(`(sk_live_[0-9a-zA-Z]{24,})`),                  // Stripe secret
	regexp.MustCompile(`(pk_live_[0-9a-zA-Z]{24,})`),                  // Stripe pub
	regexp.MustCompile(`(ghp_[0-9a-zA-Z]{36})`),                       // GitHub
	regexp.MustCompile(`(xox[bpsar]-[0-9a-zA-Z-]{10,})`),              // Slack
	regexp.MustCompile(`(SK[0-9a-fA-F]{32})`),                         // Twilio
	regexp.MustCompile(`(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})`), // SendGrid
	regexp.MustCompile(`(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+)`),    // JWT
}

func ExtractCoreSecret(value string) string {
	for _, p := range coreSecretPatterns {
		if m := p.FindString(value); m != "" {
			return m
		}
	}
	return value
}

// ScanJSWithRegex performs fast regex-based scanning on JS file contents.
// Returns findings that complement the AI analysis.
func ScanJSWithRegex(jsFiles []struct {
	URL     string
	Content string
	Size    int
	Source  string
}) []scanner.Finding {
	var findings []scanner.Finding
	seen := make(map[string]bool) // Dedup: type+value
	seenSecrets := make(map[string]bool) // Cross-pattern dedup: core secret value

	for _, js := range jsFiles {
		for _, pattern := range jsPatterns {
			matches := pattern.Pattern.FindAllString(js.Content, 5) // Max 5 matches per pattern per file
			for _, match := range matches {
				// Truncate very long matches
				value := match
				if len(value) > 200 {
					value = value[:200] + "..."
				}

				// Deduplicate by type + value (same pattern, same value)
				dedupeKey := pattern.Type + "|" + value
				if seen[dedupeKey] {
					continue
				}
				seen[dedupeKey] = true

				// Cross-pattern dedup: if the core secret (e.g. the API key itself)
				// was already reported by another pattern, skip this duplicate.
				// E.g. Google API Key pattern matches "AIza..." and Generic Secret
				// matches 'apiKey:"AIza..."' — both contain the same key.
				coreSecret := ExtractCoreSecret(value)
				if seenSecrets[coreSecret] {
					continue
				}
				seenSecrets[coreSecret] = true

				// Skip common false positives
				if shouldSkipMatch(pattern.Type, match) {
					continue
				}

				// Context-aware severity adjustment:
				// Google API keys found in Firebase config context are public by design
				severity := pattern.Severity
				if pattern.Type == "google_api_key" {
					// Check surrounding context for Firebase indicators
					idx := strings.Index(js.Content, match)
					if idx >= 0 {
						start := idx - 200
						if start < 0 {
							start = 0
						}
						end := idx + len(match) + 200
						if end > len(js.Content) {
							end = len(js.Content)
						}
						context := strings.ToLower(js.Content[start:end])
						if strings.Contains(context, "firebase") ||
							strings.Contains(context, "firebaseconfig") ||
							strings.Contains(context, "initializeapp") ||
							strings.Contains(context, "authdomain") ||
							strings.Contains(context, "storagebucket") ||
							strings.Contains(context, "messagingsenderid") {
							severity = "info"
						}
					}
				}

				findings = append(findings, scanner.Finding{
					ID:          fmt.Sprintf("js-regex-%s", pattern.Type),
					Title:       fmt.Sprintf("JS: %s", pattern.Name),
					Description: fmt.Sprintf("Regex scanner found %s in %s", pattern.Name, js.URL),
					Severity:    severity,
					Type:        "js-analysis",
					URL:         js.URL,
					Evidence:    value,
					Tags:        []string{"js", "regex-scan", pattern.Type},
					Metadata: map[string]string{
						"source":     "regex-js-scanner",
						"tool":       "regex",
						"pattern":    pattern.Type,
						"file_url":   js.URL,
						"file_size":  fmt.Sprintf("%d", js.Size),
					},
				})
			}
		}
	}

	return findings
}

// shouldSkipMatch filters out common false positives
func shouldSkipMatch(patternType, match string) bool {
	lower := strings.ToLower(match)

	switch patternType {
	case "email":
		// Skip example/placeholder emails and developer emails in copyright headers
		if strings.Contains(lower, "example.com") ||
			strings.Contains(lower, "placeholder") ||
			strings.Contains(lower, "test@") ||
			strings.Contains(lower, "noreply") ||
			strings.Contains(lower, "user@") ||
			strings.Contains(lower, "email@") ||
			// Skip well-known framework/library author emails
			strings.Contains(lower, "@gmail.com") ||
			strings.Contains(lower, "@yahoo.com") ||
			strings.Contains(lower, "@hotmail.com") ||
			// Skip emails from common framework domains
			strings.Contains(lower, "jquery.com") ||
			strings.Contains(lower, "yiiframework.com") ||
			strings.Contains(lower, "symfony.com") ||
			strings.Contains(lower, "laravel.com") ||
			strings.Contains(lower, "mailwizz.com") {
			return true
		}
	case "hardcoded_password":
		// Skip common placeholder/env-var patterns
		if strings.Contains(lower, "process.env") ||
			strings.Contains(lower, "${") ||
			strings.Contains(lower, "password123") ||
			strings.Contains(lower, "your-password") ||
			strings.Contains(lower, "change_me") ||
			strings.Contains(lower, "placeholder") {
			return true
		}
	case "debug_mode":
		// Skip if inside a comment (very rough heuristic)
		if strings.HasPrefix(strings.TrimSpace(match), "//") ||
			strings.HasPrefix(strings.TrimSpace(match), "*") {
			return true
		}
	case "eval_usage":
		// Skip common safe eval patterns
		if strings.Contains(lower, "json.parse") {
			return true
		}
	case "generic_secret":
		// Skip if the value is a Google API key (already caught by google_api_key pattern)
		if strings.Contains(match, "AIza") {
			return false // Let the cross-pattern dedup handle it
		}
		// Skip CSRF tokens — these are expected in client-side code
		if strings.Contains(lower, "csrf") {
			return true
		}
	}

	return false
}
