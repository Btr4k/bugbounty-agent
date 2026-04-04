package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// ArjunResult represents a single arjun discovery result
type ArjunResult struct {
	URL        string
	Parameters []string
	Method     string
}

// runArjun discovers hidden GET/POST parameters on live endpoints.
// Hidden parameters are a major source of SQLi, XSS, SSRF, and IDOR bugs
// that standard tools miss because they don't know the parameter exists.
//
// Strategy:
//  1. Run arjun on the top live hosts to find hidden parameters
//  2. Build new URLs with discovered parameters for dalfox XSS testing
//  3. Pass parameter URLs to nuclei fuzzing for broader coverage
func (e *Engine) runArjun(ctx context.Context, liveHosts []string) ([]Finding, []string, error) {
	var findings []Finding
	var newParamURLs []string

	if len(liveHosts) == 0 {
		return findings, newParamURLs, nil
	}

	if _, err := exec.LookPath("arjun"); err != nil {
		e.log.Warnf("arjun not installed — skipping hidden parameter discovery (install: pip3 install arjun)")
		return findings, newParamURLs, nil
	}

	// Select best targets for arjun — prioritize API endpoints and dynamic pages
	targets := selectArjunTargets(liveHosts)
	if len(targets) == 0 {
		return findings, newParamURLs, nil
	}

	e.log.Debugf("arjun: testing %d endpoints for hidden parameters", len(targets))

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return findings, newParamURLs, ctx.Err()
		default:
		}

		results, err := e.runArjunOnTarget(ctx, target)
		if err != nil {
			e.log.Debugf("arjun failed on %s: %v", target, err)
			continue
		}

		for _, result := range results {
			if len(result.Parameters) == 0 {
				continue
			}

			// Build URL with discovered parameters for further testing
			paramURL := buildParamURL(result.URL, result.Parameters)
			if paramURL != "" {
				newParamURLs = append(newParamURLs, paramURL)
			}

			// Create finding for each discovered hidden parameter set
			findings = append(findings, Finding{
				ID:    fmt.Sprintf("arjun-%s", sanitizeID(result.URL)),
				Title: fmt.Sprintf("Hidden Parameters Discovered (%s)", result.Method),
				Description: fmt.Sprintf(
					"Arjun discovered %d hidden %s parameter(s) on %s. "+
						"Hidden parameters can indicate functionality not intended for end-users, "+
						"which may be exploitable via injection, IDOR, or unauthorized access.",
					len(result.Parameters), result.Method, result.URL,
				),
				Severity: classifyArjunSeverity(result.Parameters),
				Type:     "hidden-parameters",
				Target:   extractHostname(result.URL),
				URL:      result.URL,
				Evidence: fmt.Sprintf("Method: %s | Parameters: %s", result.Method, strings.Join(result.Parameters, ", ")),
				Tags:     []string{"arjun", "hidden-parameters", "recon", strings.ToLower(result.Method)},
				Metadata: map[string]string{
					"tool":       "arjun",
					"method":     result.Method,
					"parameters": strings.Join(result.Parameters, ","),
					"param_url":  paramURL,
				},
				Timestamp: time.Now().Format(time.RFC3339),
			})
		}
	}

	e.log.Debugf("arjun: found %d endpoints with hidden params → %d new URLs for fuzzing",
		len(findings), len(newParamURLs))

	return findings, newParamURLs, nil
}

// runArjunOnTarget runs arjun on a single URL and returns discovered parameters.
func (e *Engine) runArjunOnTarget(ctx context.Context, target string) ([]ArjunResult, error) {
	tmpOut, err := os.CreateTemp("", "arjun-out-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpOut.Close()
	defer os.Remove(tmpOut.Name())

	targetCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	args := []string{
		"-u", target,
		"--get",              // Test GET parameters
		"--post",             // Test POST parameters
		"-oJ", tmpOut.Name(), // JSON output
		"-t", "5",            // Threads (balanced — arjun is already slow)
		"--stable",           // More accurate detection (fewer false positives)
		"-q",                 // Quiet mode
		// Note: no -d delay flag — default is fine; explicit 3s would be far too slow
	}

	cmd := exec.CommandContext(targetCtx, "arjun", args...)
	if err := cmd.Run(); err != nil {
		// arjun exits non-zero when no params found — normal
	}

	data, err := os.ReadFile(tmpOut.Name())
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	// Arjun JSON format: {"GET": {"param1": "value", ...}, "POST": {...}}
	var rawResult map[string]map[string]interface{}
	if err := json.Unmarshal(data, &rawResult); err != nil {
		// Try array format used by some arjun versions
		var arrayResult []map[string]interface{}
		if err2 := json.Unmarshal(data, &arrayResult); err2 != nil {
			return nil, nil
		}
		return parseArjunArray(target, arrayResult), nil
	}

	var results []ArjunResult

	for method, params := range rawResult {
		method = strings.ToUpper(method)
		if method != "GET" && method != "POST" {
			continue
		}

		var paramNames []string
		for k := range params {
			paramNames = append(paramNames, k)
		}

		if len(paramNames) > 0 {
			results = append(results, ArjunResult{
				URL:        target,
				Parameters: paramNames,
				Method:     method,
			})
		}
	}

	return results, nil
}

func parseArjunArray(target string, results []map[string]interface{}) []ArjunResult {
	var arjunResults []ArjunResult

	for _, r := range results {
		method := "GET"
		if m, ok := r["method"].(string); ok {
			method = strings.ToUpper(m)
		}

		var params []string
		if paramsRaw, ok := r["params"]; ok {
			switch v := paramsRaw.(type) {
			case []interface{}:
				for _, p := range v {
					if s, ok := p.(string); ok {
						params = append(params, s)
					}
				}
			case map[string]interface{}:
				for k := range v {
					params = append(params, k)
				}
			}
		}

		if len(params) > 0 {
			arjunResults = append(arjunResults, ArjunResult{
				URL:        target,
				Parameters: params,
				Method:     method,
			})
		}
	}

	return arjunResults
}

// selectArjunTargets picks the best endpoints for arjun parameter discovery.
// Prioritizes API endpoints and paths that are likely to have parameters.
func selectArjunTargets(hosts []string) []string {
	const maxTargets = 15

	interestingPaths := []string{
		"/api", "/api/v1", "/api/v2", "/api/v3",
		"/search", "/query", "/find",
		"/user", "/users", "/account", "/profile",
		"/product", "/products", "/item", "/items",
		"/order", "/orders",
		"/admin", "/dashboard", "/panel",
		"/data", "/export", "/download",
		"/report", "/reports",
		"/news", "/articles", "/post", "/posts",
		"/category", "/categories",
	}

	var scored []struct {
		url   string
		score int
	}

	for _, h := range hosts {
		score := 0
		hostname := strings.ToLower(extractHostname(h))

		// API and dynamic endpoints are most valuable
		for _, prefix := range []string{"api", "app", "backend", "portal"} {
			if strings.HasPrefix(hostname, prefix) {
				score += 20
			}
		}

		// Check if URL already has path indicators
		path := strings.ToLower(h)
		for _, p := range interestingPaths {
			if strings.Contains(path, p) {
				score += 10
				break
			}
		}

		// Prefer HTTPS
		if strings.HasPrefix(h, "https://") {
			score += 5
		}

		scored = append(scored, struct {
			url   string
			score int
		}{h, score})
	}

	// Sort by score descending
	sort.SliceStable(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	result := make([]string, 0, maxTargets)
	for i, s := range scored {
		if i >= maxTargets {
			break
		}
		result = append(result, s.url)
	}

	return result
}

// buildParamURL builds a test URL with discovered parameters set to a probe value.
// Used to feed discovered parameters into dalfox and nuclei for vulnerability testing.
func buildParamURL(rawURL string, params []string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	q := parsed.Query()
	for _, p := range params {
		q.Set(p, "HAWKEYE_TEST")
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// classifyArjunSeverity assesses how dangerous the discovered parameters might be
// based on their names and typical patterns seen in bug bounty findings.
func classifyArjunSeverity(params []string) string {
	highRiskParams := []string{
		"redirect", "url", "next", "return", "returnurl", "return_url",
		"callback", "target", "dest", "destination", "goto",
		"file", "path", "dir", "folder", "document", "include",
		"cmd", "exec", "command", "shell", "ping",
		"debug", "test", "admin", "root",
		"token", "secret", "key", "password", "pass", "pwd",
		"ssrf", "proxy", "host", "hostname",
		"xml", "soap", "wsdl", "dtd",
		"template", "view", "page", "layout",
	}

	mediumRiskParams := []string{
		"id", "user_id", "uid", "account_id", "member_id",
		"order_id", "product_id", "item_id", "cat_id",
		"search", "query", "q", "keyword",
		"email", "username", "login",
	}

	for _, param := range params {
		lower := strings.ToLower(param)
		for _, h := range highRiskParams {
			if lower == h || strings.Contains(lower, h) {
				return "high"
			}
		}
	}

	for _, param := range params {
		lower := strings.ToLower(param)
		for _, m := range mediumRiskParams {
			if lower == m || strings.Contains(lower, m) {
				return "medium"
			}
		}
	}

	return "low"
}

// sanitizeID creates a safe ID from a URL string
func sanitizeID(rawURL string) string {
	r := strings.NewReplacer(
		"https://", "", "http://", "",
		"/", "-", ".", "-", ":", "-",
		"?", "-", "&", "-", "=", "-",
	)
	id := r.Replace(rawURL)
	if len(id) > 60 {
		id = id[:60]
	}
	return id
}
