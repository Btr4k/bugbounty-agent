// Package redaction removes discovered credentials from untrusted evidence
// before it is logged, reported, or sent to an AI provider.
//
// Masking is deliberately value-scoped: labels, URLs, usernames, hosts, and
// other surrounding evidence are preserved. Replacement markers contain only
// the detector type and never contain characters copied from the secret.
package redaction

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// SecretType identifies the credential format that caused a value to be
// masked. It is safe to include in logs and reports.
type SecretType string

const (
	SecretJWT                SecretType = "jwt"
	SecretAWSAccessKey       SecretType = "aws_access_key"
	SecretAWSSecretKey       SecretType = "aws_secret_key"
	SecretAWSSessionToken    SecretType = "aws_session_token"
	SecretGitHubToken        SecretType = "github_token"
	SecretStripeKey          SecretType = "stripe_key"
	SecretGoogleOAuthToken   SecretType = "google_oauth_token"
	SecretSlackToken         SecretType = "slack_token"
	SecretTwilioKey          SecretType = "twilio_key"
	SecretSendGridKey        SecretType = "sendgrid_key"
	SecretMailgunKey         SecretType = "mailgun_key"
	SecretPrivateKey         SecretType = "private_key"
	SecretBearerToken        SecretType = "bearer_token"
	SecretAuthorization      SecretType = "authorization_credential"
	SecretCookie             SecretType = "cookie_value"
	SecretPassword           SecretType = "password"
	SecretDatabaseCredential SecretType = "database_credential"
	SecretURLCredential      SecretType = "url_credential"
	SecretGeneric            SecretType = "generic_secret"
)

// Match is the non-sensitive metadata for one masked occurrence. It never
// contains the original credential or any value-derived correlation metadata.
type Match struct {
	Type SecretType `json:"type"`
}

// Result contains sanitized evidence and safe metadata for each masked
// occurrence, in source order.
type Result struct {
	Text    string  `json:"text"`
	Matches []Match `json:"matches,omitempty"`
}

type rule struct {
	typeName    SecretType
	pattern     *regexp.Regexp
	secretGroup int
	priority    int
}

// Rules with the most specific token formats have the lowest priority. This
// ensures, for example, that a JWT in a Bearer header is described as a JWT and
// that a Stripe key assigned to "password" is described as a Stripe key.
var rules = []rule{
	{
		typeName:    SecretJWT,
		pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`),
		secretGroup: 0,
		priority:    10,
	},
	{
		typeName:    SecretAWSAccessKey,
		pattern:     regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b`),
		secretGroup: 0,
		priority:    10,
	},
	{
		typeName:    SecretGitHubToken,
		pattern:     regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`),
		secretGroup: 0,
		priority:    10,
	},
	{
		typeName:    SecretStripeKey,
		pattern:     regexp.MustCompile(`\b(?:(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,})\b`),
		secretGroup: 0,
		priority:    10,
	},
	{
		typeName:    SecretGoogleOAuthToken,
		pattern:     regexp.MustCompile(`\bya29\.[A-Za-z0-9_-]{16,}\b`),
		secretGroup: 0,
		priority:    10,
	},
	{
		typeName:    SecretSlackToken,
		pattern:     regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`),
		secretGroup: 0,
		priority:    10,
	},
	{
		typeName:    SecretTwilioKey,
		pattern:     regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
		secretGroup: 0,
		priority:    10,
	},
	{
		typeName:    SecretSendGridKey,
		pattern:     regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`),
		secretGroup: 0,
		priority:    10,
	},
	{
		typeName:    SecretMailgunKey,
		pattern:     regexp.MustCompile(`\bkey-[A-Za-z0-9]{32}\b`),
		secretGroup: 0,
		priority:    10,
	},
	{
		typeName:    SecretPrivateKey,
		pattern:     regexp.MustCompile(`(?i)(-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----[ \t\r\n]+)([A-Za-z0-9+/= \t\r\n]+?)([ \t\r\n]+-----END(?: [A-Z0-9]+)* PRIVATE KEY-----)`),
		secretGroup: 0,
		priority:    10,
	},
	{
		typeName:    SecretAWSSecretKey,
		pattern:     regexp.MustCompile(`(?i)(\baws[_-]?secret[_-]?access[_-]?key\b\s*[:=]\s*["']?)([A-Za-z0-9/+=]{40})(?:$|["'\s,;}])`),
		secretGroup: 2,
		priority:    20,
	},
	{
		typeName:    SecretAWSSessionToken,
		pattern:     regexp.MustCompile(`(?i)(\b(?:aws[_-]?(?:session|security)[_-]?token|x-amz-security-token)\b\s*[:=]\s*["']?)([A-Za-z0-9/+=_-]{16,})`),
		secretGroup: 2,
		priority:    20,
	},
	{
		typeName:    SecretDatabaseCredential,
		pattern:     regexp.MustCompile(`(?i)(\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|mssql|sqlserver)://[^:/@\s]+:)([^@\s/?#]+)(@)`),
		secretGroup: 2,
		priority:    30,
	},
	{
		typeName:    SecretURLCredential,
		pattern:     regexp.MustCompile(`(?i)(\b(?:https?|ftp|sftp)://[^:/@\s]+:)([^@\s/?#]+)(@)`),
		secretGroup: 2,
		priority:    30,
	},
	{
		typeName:    SecretPassword,
		pattern:     regexp.MustCompile(`(?i)(["']?\b(?:password|passwd|pwd|pass|passphrase|db[_-]?password)\b["']?\s*[:=]\s*")([^"\r\n]+)(")`),
		secretGroup: 2,
		priority:    40,
	},
	{
		typeName:    SecretPassword,
		pattern:     regexp.MustCompile(`(?i)(["']?\b(?:password|passwd|pwd|pass|passphrase|db[_-]?password)\b["']?\s*[:=]\s*')([^'\r\n]+)(')`),
		secretGroup: 2,
		priority:    40,
	},
	{
		typeName:    SecretPassword,
		pattern:     regexp.MustCompile(`(?i)(["']?\b(?:password|passwd|pwd|pass|passphrase|db[_-]?password)\b["']?\s*[:=]\s*)([^\s,;&}\]'"<>]+)`),
		secretGroup: 2,
		priority:    50,
	},
	{
		typeName:    SecretGeneric,
		pattern:     regexp.MustCompile(`(?i)(["']?\b(?:api[_-]?(?:key|secret)|secret[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|session[_-]?id|token)\b["']?\s*[:=]\s*")([^"\r\n]+)(")`),
		secretGroup: 2,
		priority:    50,
	},
	{
		typeName:    SecretGeneric,
		pattern:     regexp.MustCompile(`(?i)(["']?\b(?:api[_-]?(?:key|secret)|secret[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|session[_-]?id|token)\b["']?\s*[:=]\s*')([^'\r\n]+)(')`),
		secretGroup: 2,
		priority:    50,
	},
	{
		typeName:    SecretGeneric,
		pattern:     regexp.MustCompile(`(?i)(["']?\b(?:api[_-]?(?:key|secret)|secret[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|session[_-]?id|token)\b["']?\s*[:=]\s*)([^\s,;&}\]'"<>]+)`),
		secretGroup: 2,
		priority:    60,
	},
	{
		typeName:    SecretAuthorization,
		pattern:     regexp.MustCompile(`(?i)(\b(?:Proxy-)?Authorization\b["']?\s*:\s*["']?(?:Basic|Token)[ \t]+)([A-Za-z0-9._~+/\-]+=*)`),
		secretGroup: 2,
		priority:    60,
	},
	{
		typeName:    SecretBearerToken,
		pattern:     regexp.MustCompile(`(?i)(\bBearer[ \t]+)([A-Za-z0-9._~+/\-]+=*)`),
		secretGroup: 2,
		priority:    60,
	},
}

type candidate struct {
	start    int
	end      int
	typeName SecretType
	priority int
}

// Mask sanitizes controls and replaces discovered credential values with
// non-sensitive markers. It is the convenience API for AI prompts, reports,
// and log messages that do not need separate match metadata.
func Mask(input string) string {
	return MaskWithMetadata(input).Text
}

// MaskMultiline is the report-oriented variant of Mask. It preserves line
// feeds as structural separators while removing every other control or Unicode
// formatting rune. Use Mask for single-line logs and AI fields; use this
// function when Markdown or HTTP evidence must keep its line structure.
func MaskMultiline(input string) string {
	return mask(input, true).Text
}

// MaskWithMetadata sanitizes controls and replaces discovered credential
// values while also returning safe metadata. The returned Match values never
// contain the original credential.
func MaskWithMetadata(input string) Result {
	return mask(input, false)
}

// MaskMultilineWithMetadata is MaskWithMetadata with line-feed preservation
// for structured report evidence.
func MaskMultilineWithMetadata(input string) Result {
	return mask(input, true)
}

// MaskKnownSecret masks an entire value that the caller has already
// deterministically classified as a credential. It is intended for detector
// outputs whose Evidence field contains only an opaque value and therefore has
// no surrounding label for Mask to recognize. Passing an empty type uses
// SecretGeneric. No original value is retained in the returned metadata.
func MaskKnownSecret(value string, typeName SecretType) Result {
	clean := sanitizeControls(value, false)
	if clean == "" {
		return Result{Text: clean}
	}
	if typeName == "" {
		typeName = SecretGeneric
	}
	metadata := safeMetadata(typeName, clean)
	return Result{
		Text:    marker(metadata),
		Matches: []Match{metadata},
	}
}

// MaskKnownSecretOccurrences removes an already-classified sensitive value
// from a related model/tool-controlled field before applying the general
// pattern redactor. This prevents a model from echoing an opaque value in its
// description even when the value has no recognizable format.
func MaskKnownSecretOccurrences(input, secret string, typeName SecretType) string {
	cleanInput := sanitizeControls(input, false)
	cleanSecret := sanitizeControls(secret, false)
	if cleanSecret == "" {
		return Mask(cleanInput)
	}
	if typeName == "" {
		typeName = SecretGeneric
	}
	cleanInput = strings.ReplaceAll(cleanInput, cleanSecret, marker(Match{Type: typeName}))
	return Mask(cleanInput)
}

// TypeForDetector maps analyzer detector labels to their safe redaction type.
// The boolean is false for an unknown label so callers can distinguish a new
// detector from a recognized one without ever handling the credential value.
func TypeForDetector(detectorType string) (SecretType, bool) {
	switch strings.ToLower(strings.TrimSpace(detectorType)) {
	case "aws_key":
		return SecretAWSAccessKey, true
	case "aws_secret":
		return SecretAWSSecretKey, true
	case "google_oauth":
		return SecretGoogleOAuthToken, true
	case "stripe_key":
		return SecretStripeKey, true
	case "github_token":
		return SecretGitHubToken, true
	case "slack_token":
		return SecretSlackToken, true
	case "twilio_key":
		return SecretTwilioKey, true
	case "sendgrid_key":
		return SecretSendGridKey, true
	case "mailgun_key":
		return SecretMailgunKey, true
	case "jwt":
		return SecretJWT, true
	case "bearer_token":
		return SecretBearerToken, true
	case "auth_header":
		return SecretAuthorization, true
	case "cookie", "set_cookie", "session_cookie":
		return SecretCookie, true
	case "hardcoded_password", "password":
		return SecretPassword, true
	case "database_url":
		return SecretDatabaseCredential, true
	case "private_key":
		return SecretPrivateKey, true
	case "url_credentials":
		return SecretURLCredential, true
	case "generic_secret", "api_key", "secret", "credential", "token":
		return SecretGeneric, true
	default:
		return "", false
	}
}

// MaskDetectorEvidence masks evidence emitted by a named analyzer detector.
// It first applies value-scoped structural masking so a connection string can
// retain its non-secret host and username. If the evidence is an opaque value,
// or if the detector label is new or unknown, it fails closed by masking the
// complete value as SecretGeneric.
func MaskDetectorEvidence(value, detectorType string) Result {
	structured := MaskWithMetadata(value)
	if len(structured.Matches) > 0 || structured.Text == "" {
		return structured
	}

	typeName, ok := TypeForDetector(detectorType)
	if !ok {
		typeName = SecretGeneric
	}
	return MaskKnownSecret(value, typeName)
}

func mask(input string, preserveLineFeeds bool) Result {
	// Discover header-scoped cookie values while line boundaries still exist.
	// After replacements are selected, the single-line API can collapse those
	// boundaries without risking a Cookie matcher consuming the next header.
	clean := sanitizeControls(input, true)
	candidates := findCandidates(clean)
	if len(candidates) == 0 {
		return Result{Text: sanitizeControls(clean, preserveLineFeeds)}
	}

	var output strings.Builder
	output.Grow(len(clean))
	matches := make([]Match, 0, len(candidates))
	cursor := 0
	for _, item := range candidates {
		secret := clean[item.start:item.end]
		metadata := safeMetadata(item.typeName, secret)

		output.WriteString(clean[cursor:item.start])
		output.WriteString(marker(metadata))
		matches = append(matches, metadata)
		cursor = item.end
	}
	output.WriteString(clean[cursor:])

	return Result{Text: sanitizeControls(output.String(), preserveLineFeeds), Matches: matches}
}

func findCandidates(input string) []candidate {
	all := findHTTPCookieCandidates(input)
	for _, currentRule := range rules {
		indexes := currentRule.pattern.FindAllStringSubmatchIndex(input, -1)
		for _, index := range indexes {
			group := currentRule.secretGroup
			if group*2+1 >= len(index) {
				continue
			}
			start, end := index[group*2], index[group*2+1]
			if start < 0 || end <= start {
				continue
			}
			if strings.HasPrefix(input[start:end], "[REDACTED") {
				continue
			}
			all = append(all, candidate{
				start:    start,
				end:      end,
				typeName: currentRule.typeName,
				priority: currentRule.priority,
			})
		}
	}

	sort.SliceStable(all, func(i, j int) bool {
		if all[i].start != all[j].start {
			return all[i].start < all[j].start
		}
		if all[i].priority != all[j].priority {
			return all[i].priority < all[j].priority
		}
		return all[i].end > all[j].end
	})

	selected := make([]candidate, 0, len(all))
	for _, item := range all {
		if len(selected) > 0 && item.start < selected[len(selected)-1].end {
			continue
		}
		selected = append(selected, item)
	}
	return selected
}

// findHTTPCookieCandidates masks only cookie values while preserving cookie
// names and Set-Cookie attributes such as Path, SameSite, Secure, and HttpOnly.
// It is deliberately line-scoped so malformed input cannot make a value consume
// unrelated headers or body evidence.
func findHTTPCookieCandidates(input string) []candidate {
	var candidates []candidate
	for lineStart := 0; lineStart <= len(input); {
		lineEnd := strings.IndexByte(input[lineStart:], '\n')
		if lineEnd < 0 {
			lineEnd = len(input)
		} else {
			lineEnd += lineStart
		}
		line := input[lineStart:lineEnd]
		colon := strings.IndexByte(line, ':')
		if colon > 0 {
			headerName := strings.TrimSpace(line[:colon])
			valueStart := lineStart + colon + 1
			switch {
			case strings.EqualFold(headerName, "Set-Cookie"):
				segmentEnd := lineEnd
				if semicolon := strings.IndexByte(input[valueStart:lineEnd], ';'); semicolon >= 0 {
					segmentEnd = valueStart + semicolon
				}
				if item, ok := cookiePairCandidate(input, valueStart, segmentEnd); ok {
					candidates = append(candidates, item)
				}
			case strings.EqualFold(headerName, "Cookie"):
				segmentStart := valueStart
				for segmentStart <= lineEnd {
					segmentEnd := lineEnd
					if semicolon := strings.IndexByte(input[segmentStart:lineEnd], ';'); semicolon >= 0 {
						segmentEnd = segmentStart + semicolon
					}
					if item, ok := cookiePairCandidate(input, segmentStart, segmentEnd); ok {
						candidates = append(candidates, item)
					}
					if segmentEnd == lineEnd {
						break
					}
					segmentStart = segmentEnd + 1
				}
			}
		}
		if lineEnd == len(input) {
			break
		}
		lineStart = lineEnd + 1
	}
	return candidates
}

func cookiePairCandidate(input string, start, end int) (candidate, bool) {
	if start < 0 || end > len(input) || start >= end {
		return candidate{}, false
	}
	segment := input[start:end]
	equals := strings.IndexByte(segment, '=')
	if equals <= 0 {
		return candidate{}, false
	}
	valueStart := start + equals + 1
	for valueStart < end && (input[valueStart] == ' ' || input[valueStart] == '\t') {
		valueStart++
	}
	valueEnd := end
	for valueEnd > valueStart && (input[valueEnd-1] == ' ' || input[valueEnd-1] == '\t') {
		valueEnd--
	}
	if valueEnd-valueStart >= 2 && input[valueStart] == '"' && input[valueEnd-1] == '"' {
		valueStart++
		valueEnd--
	}
	if valueStart >= valueEnd || strings.HasPrefix(input[valueStart:valueEnd], "[REDACTED") {
		return candidate{}, false
	}
	return candidate{start: valueStart, end: valueEnd, typeName: SecretCookie, priority: 70}, true
}

func safeMetadata(typeName SecretType, _ string) Match {
	return Match{Type: typeName}
}

func marker(metadata Match) string {
	var output strings.Builder
	output.WriteString("[REDACTED type=")
	output.WriteString(string(metadata.Type))
	output.WriteByte(']')
	return output.String()
}

// sanitizeControls removes invisible control and formatting runes before
// evidence leaves the process. Whitespace controls become ordinary spaces so
// unrelated fields cannot be joined together; other controls are dropped.
func sanitizeControls(input string, preserveLineFeeds bool) string {
	if preserveLineFeeds {
		input = strings.ReplaceAll(input, "\r\n", "\n")
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n':
			if preserveLineFeeds {
				return '\n'
			}
			return ' '
		case '\r':
			if preserveLineFeeds {
				return '\n'
			}
			return ' '
		case '\t', '\v', '\f':
			return ' '
		}
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return -1
		}
		return r
	}, input)
}
