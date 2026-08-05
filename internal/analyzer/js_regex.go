package analyzer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Btr4k/bugbounty-agent/internal/redaction"
	"github.com/Btr4k/bugbounty-agent/internal/scanner"
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
	regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),                         // AWS
	regexp.MustCompile(`(ya29\.[0-9A-Za-z_-]+)`),                     // Google OAuth
	regexp.MustCompile(`(sk_live_[0-9a-zA-Z]{24,})`),                 // Stripe secret
	regexp.MustCompile(`(ghp_[0-9a-zA-Z]{36})`),                      // GitHub
	regexp.MustCompile(`(xox[bpsar]-[0-9a-zA-Z-]{10,})`),             // Slack
	regexp.MustCompile(`(SK[0-9a-fA-F]{32})`),                        // Twilio
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
	seen := make(map[string]bool)        // Dedup: type+value
	seenSecrets := make(map[string]bool) // Cross-pattern dedup: core secret value

	for _, js := range jsFiles {
		safeURL := redaction.SanitizeURL(js.URL)
		for _, pattern := range jsPatterns {
			if !isStrongJSFindingType(pattern.Type) {
				continue
			}
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

				safeEvidence := redaction.MaskDetectorEvidence(value, pattern.Type).Text
				findings = append(findings, scanner.Finding{
					ID:          fmt.Sprintf("js-regex-%s", pattern.Type),
					Title:       fmt.Sprintf("JS: %s", pattern.Name),
					Description: fmt.Sprintf("Regex scanner found %s in %s", pattern.Name, safeURL),
					Severity:    pattern.Severity,
					Type:        "js-analysis",
					URL:         safeURL,
					Evidence:    safeEvidence,
					Tags:        []string{"js", "regex-scan", pattern.Type},
					Metadata: map[string]string{
						"source":    "regex-js-scanner",
						"tool":      "regex",
						"pattern":   pattern.Type,
						"file_url":  safeURL,
						"file_size": fmt.Sprintf("%d", js.Size),
					},
				})
			}
		}
	}

	return findings
}

func isStrongJSFindingType(patternType string) bool {
	switch patternType {
	case "aws_key", "aws_secret", "google_oauth", "stripe_key",
		"github_token", "slack_token", "twilio_key", "sendgrid_key",
		"mailgun_key", "jwt", "bearer_token", "auth_header",
		"hardcoded_password", "database_url", "private_key",
		"url_credentials", "generic_secret":
		return true
	default:
		return false
	}
}

// shouldSkipMatch filters out common false positives
func shouldSkipMatch(patternType, match string) bool {
	lower := strings.ToLower(match)
	if containsPlaceholder(lower) {
		return true
	}

	switch patternType {
	case "hardcoded_password":
		// Skip common placeholder/env-var patterns
		if strings.Contains(lower, "process.env") ||
			strings.Contains(lower, "${") ||
			strings.Contains(lower, "password123") ||
			strings.Contains(lower, `"password"`) ||
			strings.Contains(lower, `"admin"`) ||
			strings.Contains(lower, `"secret"`) ||
			strings.Contains(lower, `"changeme"`) ||
			strings.Contains(lower, "your-password") ||
			strings.Contains(lower, "change_me") ||
			strings.Contains(lower, "placeholder") {
			return true
		}
		// Skip SVG/HTML content — value contains markup, not a credential
		if strings.Contains(match, "<") || strings.Contains(match, "/>") ||
			strings.Contains(lower, "svg") || strings.Contains(lower, "circle") ||
			strings.Contains(lower, "path") || strings.Contains(lower, "rect") {
			return true
		}
	case "generic_secret":
		// Public client-side Google keys require separate restriction testing.
		if strings.Contains(match, "AIza") {
			return true
		}
		// Skip CSRF tokens — these are expected in client-side code
		if strings.Contains(lower, "csrf") {
			return true
		}
	}

	return false
}

func containsPlaceholder(value string) bool {
	placeholders := []string{
		"example", "placeholder", "dummy", "sample", "changeme",
		"change_me", "your-", "your_", "xxxxx", "<token>", "<secret>",
	}
	for _, placeholder := range placeholders {
		if strings.Contains(value, placeholder) {
			return true
		}
	}
	return false
}
