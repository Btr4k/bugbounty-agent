package redaction

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const invalidURLMarker = "[REDACTED invalid_url]"

const redactedQueryToken = "redacted_query_token"

var (
	// Deliberately stop at common prose/markup delimiters. Any remaining
	// trailing punctuation is split from the URL before it is parsed so it can
	// be preserved verbatim without being mistaken for part of a query value.
	absoluteHTTPURLPattern    = regexp.MustCompile(`(?i)https?://[^\s<>"'\x60]+`)
	relativeHTTPURLPattern    = regexp.MustCompile(`/[A-Za-z0-9._~!$&()*+,;=:@%/\-]*(?:\?|#)[^\s<>"'\x60]+`)
	schemeRelativeAuthPattern = regexp.MustCompile(`//[^/@\s<>"'\x60]+@[^\s<>"'\x60]+`)
	quotedRelativeURLPattern  = regexp.MustCompile(`(["'])([^"'\s<>\x60]*\?[^"'\s<>\x60]*)(["'])`)
	bareRelativeURLPattern    = regexp.MustCompile(`(?m)(^|[ \t\r\n(=\[,;:])([A-Za-z0-9._~!$&()*+,;=@%\-]+\?[^\s<>"'\x60]+)`)
	queryOnlyURLPattern       = regexp.MustCompile(`(?m)(^|[ \t\r\n(=\[,;:])(\?[^\s<>"'\x60]+)`)
	httpRequestTargetPattern  = regexp.MustCompile(`(?i)(\b(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|TRACE|CONNECT)[ \t]+)([^ \t\r\n]+)([ \t]+HTTP/[0-9]+(?:\.[0-9]+)?)`)
	hexQueryTokenPattern      = regexp.MustCompile(`(?i)^[0-9a-f]{20,}$`)
	uuidQueryTokenPattern     = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// SanitizeURL returns a representation of rawURL that is safe to place in an
// AI prompt, log, or report. It removes URL user information and fragments and
// blanks every query value while preserving query parameter names, order, and
// repetition. It accepts absolute, scheme-relative, and relative URLs.
//
// A malformed URL is replaced in full instead of returning attacker-controlled
// input that may contain an opaque credential. Path components are preserved;
// callers must separately redact any application-specific path secrets.
func SanitizeURL(rawURL string) string {
	clean := strings.TrimSpace(sanitizeControls(rawURL, false))
	if clean == "" {
		return ""
	}

	parsed, err := url.Parse(clean)
	if err != nil || parsed.Opaque != "" ||
		((strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https")) && parsed.Host == "") ||
		(strings.HasPrefix(clean, "//") && parsed.Host == "") {
		return invalidURLMarker
	}

	parsed.User = nil
	parsed.Fragment = ""
	parsed.RawFragment = ""
	parsed.RawQuery = blankQueryValues(parsed.RawQuery)
	return parsed.String()
}

// SanitizeURLsInText removes user information, fragments, and query values
// from absolute HTTP(S) URLs, relative URL tokens, and HTTP request targets
// embedded in arbitrary single- or multi-line text. It recognizes quoted curl
// arguments and common JSON escaping of URL structural characters. Surrounding
// prose and punctuation are preserved. This function only addresses URL-borne
// secrets; compose it with Mask or MaskMultiline to redact credentials in
// headers and other fields.
func SanitizeURLsInText(input string) string {
	result := normalizeJSONURLStructuralEscapes(input)
	result = absoluteHTTPURLPattern.ReplaceAllStringFunc(result, func(token string) string {
		core, suffix := splitTrailingURLPunctuation(token)
		return SanitizeURL(core) + suffix
	})
	result = schemeRelativeAuthPattern.ReplaceAllStringFunc(result, func(token string) string {
		core, suffix := splitTrailingURLPunctuation(token)
		return SanitizeURL(core) + suffix
	})
	result = relativeHTTPURLPattern.ReplaceAllStringFunc(result, func(token string) string {
		core, suffix := splitTrailingURLPunctuation(token)
		return SanitizeURL(core) + suffix
	})
	result = replaceCapturedRelativeURLs(result, bareRelativeURLPattern)
	result = replaceCapturedRelativeURLs(result, queryOnlyURLPattern)
	result = quotedRelativeURLPattern.ReplaceAllStringFunc(result, func(quoted string) string {
		parts := quotedRelativeURLPattern.FindStringSubmatch(quoted)
		if len(parts) != 4 || parts[1] != parts[3] {
			return quoted
		}
		core, suffix := splitTrailingURLPunctuation(parts[2])
		return parts[1] + SanitizeURL(core) + suffix + parts[3]
	})

	return httpRequestTargetPattern.ReplaceAllStringFunc(result, func(requestLine string) string {
		parts := httpRequestTargetPattern.FindStringSubmatch(requestLine)
		if len(parts) != 4 {
			return requestLine
		}
		target := parts[2]
		if !strings.ContainsAny(target, "?#@") &&
			!strings.HasPrefix(target, "//") &&
			!strings.HasPrefix(strings.ToLower(target), "http://") &&
			!strings.HasPrefix(strings.ToLower(target), "https://") {
			return requestLine
		}
		return parts[1] + SanitizeURL(target) + parts[3]
	})
}

func replaceCapturedRelativeURLs(input string, pattern *regexp.Regexp) string {
	return pattern.ReplaceAllStringFunc(input, func(match string) string {
		parts := pattern.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		core, suffix := splitTrailingURLPunctuation(parts[2])
		return parts[1] + SanitizeURL(core) + suffix
	})
}

func blankQueryValues(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	var output strings.Builder
	output.Grow(len(rawQuery))
	segmentStart := 0
	for index := 0; index <= len(rawQuery); index++ {
		if index < len(rawQuery) && rawQuery[index] != '&' && rawQuery[index] != ';' {
			continue
		}

		segment := rawQuery[segmentStart:index]
		if equals := strings.IndexByte(segment, '='); equals >= 0 {
			output.WriteString(sanitizeQueryKey(segment[:equals]))
			output.WriteByte('=')
		} else {
			output.WriteString(sanitizeQueryKey(segment))
		}
		if index < len(rawQuery) {
			output.WriteByte(rawQuery[index])
		}
		segmentStart = index + 1
	}
	return output.String()
}

func sanitizeQueryKey(rawKey string) string {
	if rawKey == "" || rawKey == redactedQueryToken {
		return rawKey
	}
	decoded, err := url.QueryUnescape(rawKey)
	if err != nil || !utf8.ValidString(decoded) || likelyOpaqueQueryToken(decoded) {
		return redactedQueryToken
	}
	return rawKey
}

func likelyOpaqueQueryToken(value string) bool {
	if value == "" {
		return false
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) >= 0 {
		return true
	}
	if len(findCandidates(value)) > 0 || hexQueryTokenPattern.MatchString(value) || uuidQueryTokenPattern.MatchString(value) {
		return true
	}
	if strings.ContainsAny(value, "/+= \t\r\n") {
		return true
	}
	if len(value) < 20 {
		return false
	}

	var hasLower, hasUpper, hasDigit bool
	for _, char := range value {
		switch {
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= '0' && char <= '9':
			hasDigit = true
		}
	}
	classes := 0
	for _, present := range []bool{hasLower, hasUpper, hasDigit} {
		if present {
			classes++
		}
	}
	if classes == 3 {
		return true
	}
	if len(value) >= 32 && !strings.ContainsAny(value, "_.-") {
		return true
	}
	return len(value) >= 48
}

func normalizeJSONURLStructuralEscapes(input string) string {
	if !strings.Contains(input, `\`) {
		return input
	}

	var output strings.Builder
	output.Grow(len(input))
	for index := 0; index < len(input); {
		if input[index] != '\\' {
			output.WriteByte(input[index])
			index++
			continue
		}

		escapeStart := index
		for index < len(input) && input[index] == '\\' {
			index++
		}
		if index < len(input) && input[index] == '/' {
			output.WriteByte('/')
			index++
			continue
		}
		if replacement, consumed, ok := jsonURLStructuralEscape(input[index:]); ok {
			output.WriteByte(replacement)
			index += consumed
			continue
		}

		output.WriteString(input[escapeStart:index])
	}
	return output.String()
}

func jsonURLStructuralEscape(input string) (byte, int, bool) {
	if len(input) < 5 || (input[0] != 'u' && input[0] != 'U') {
		return 0, 0, false
	}
	switch strings.ToLower(input[1:5]) {
	case "0023":
		return '#', 5, true
	case "0025":
		return '%', 5, true
	case "0026":
		return '&', 5, true
	case "002f":
		return '/', 5, true
	case "003a":
		return ':', 5, true
	case "003d":
		return '=', 5, true
	case "003f":
		return '?', 5, true
	case "0040":
		return '@', 5, true
	default:
		return 0, 0, false
	}
}

func splitTrailingURLPunctuation(token string) (string, string) {
	core := token
	suffix := ""
	for core != "" {
		last := core[len(core)-1]
		strip := strings.ContainsRune(".,;:!?", rune(last))
		switch last {
		case ')':
			strip = strings.Count(core, ")") > strings.Count(core, "(")
		case ']':
			strip = strings.Count(core, "]") > strings.Count(core, "[")
		case '}':
			strip = strings.Count(core, "}") > strings.Count(core, "{")
		}
		if !strip {
			break
		}
		core = core[:len(core)-1]
		suffix = string(last) + suffix
	}
	return core, suffix
}
