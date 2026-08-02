package recon

import (
	"net/url"
	"regexp"
	"strings"
)

// JS endpoint mining — extracts API paths and parameterized URLs from the JS
// bundles recon already downloaded. This turns a subdomain-only surface into one
// with real, observed endpoints and parameters, which (a) lets dalfox run and
// (b) lets the hunter mark leads "observed" instead of guessing. No external
// tool is required — it reads content already in memory.

var (
	// Absolute URLs embedded in JS (API bases, callbacks, etc.).
	jsAbsoluteURLRe = regexp.MustCompile(`https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-./%~+]*)?(?:\?[A-Za-z0-9_\-=&%.]+)?`)
	// Quoted root-relative paths, optionally with a query string. The query
	// char-class deliberately excludes ${ and { so template literals terminate
	// the match cleanly (e.g. "/api/user?id=${x}" captures "/api/user?id=").
	jsQuotedPathRe = regexp.MustCompile("[\"'`](/[A-Za-z0-9_\\-./]{1,100}(?:\\?[A-Za-z0-9_\\-=&%.]+)?)")
)

// staticAssetExt paths ending in these are noise, not endpoints.
var staticAssetExt = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
	".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webm", ".pdf",
}

// mineJSEndpoints returns fully-qualified, in-host URLs discovered inside JS
// content. Relative paths are resolved against the host that served the JS file
// (same-origin is the overwhelmingly common case for an app's own API calls).
func mineJSEndpoints(files []JSFile) []string {
	const (
		maxPerFile = 150
		maxTotal   = 600
	)
	seen := make(map[string]bool)
	var out []string

	add := func(raw string) bool {
		raw = strings.TrimSpace(strings.Trim(raw, "\"'`"))
		if raw == "" || seen[raw] {
			return true
		}
		seen[raw] = true
		out = append(out, raw)
		return len(out) < maxTotal
	}

	for _, f := range files {
		base, err := url.Parse(f.URL)
		if err != nil || base.Host == "" {
			continue
		}
		perFile := 0
		emit := func(u string) bool {
			perFile++
			if perFile > maxPerFile {
				return false
			}
			return add(u)
		}

		for _, m := range jsAbsoluteURLRe.FindAllString(f.Content, -1) {
			if !looksLikeEndpoint(pathAndQuery(m)) && !strings.Contains(m, "?") {
				continue
			}
			if !emit(m) {
				break
			}
		}
		for _, m := range jsQuotedPathRe.FindAllStringSubmatch(f.Content, -1) {
			path := m[1]
			if !looksLikeEndpoint(path) {
				continue
			}
			full := base.Scheme + "://" + base.Host + path
			if !emit(full) {
				break
			}
		}
		if len(out) >= maxTotal {
			break
		}
	}
	return out
}

// pathAndQuery returns the path+query portion of an absolute URL for filtering.
func pathAndQuery(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if u.RawQuery != "" {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path
}

// looksLikeEndpoint keeps high-signal paths and rejects asset/noise strings.
// A path carrying a query parameter is always kept (highest hunting value).
func looksLikeEndpoint(path string) bool {
	if path == "" || !strings.HasPrefix(path, "/") {
		return false
	}
	pathOnly := path
	hasQuery := false
	if i := strings.IndexByte(path, '?'); i >= 0 {
		pathOnly = path[:i]
		hasQuery = strings.Contains(path[i:], "=")
	}
	lower := strings.ToLower(pathOnly)
	for _, ext := range staticAssetExt {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	// A parameterized request is worth keeping even on a short path.
	if hasQuery {
		return true
	}
	// Otherwise require an API-ish shape: /api/... or >= 2 path segments.
	if strings.Contains(lower, "/api/") || strings.Contains(lower, "/v1/") || strings.Contains(lower, "/v2/") || strings.Contains(lower, "/graphql") {
		return true
	}
	segments := 0
	for _, seg := range strings.Split(strings.Trim(pathOnly, "/"), "/") {
		if seg != "" {
			segments++
		}
	}
	return segments >= 2
}
