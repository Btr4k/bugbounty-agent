package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

// SQLi-prone parameter names — inspired by gf sqli pattern
// These are parameters that historically correlate with SQL injection
var sqliParamPatterns = []string{
	"id", "user", "userid", "user_id", "uid", "account", "account_id",
	"cat", "category", "catid", "cat_id", "item", "item_id", "itemid",
	"news", "news_id", "newsid", "article", "article_id", "page", "pageid",
	"report", "report_id", "order", "order_id", "orderid",
	"product", "product_id", "productid", "prod", "prod_id",
	"member", "member_id", "memberid", "profile", "profile_id",
	"search", "query", "q", "keyword", "s", "term",
	"type", "action", "tab", "view", "mode", "sort", "sortby", "orderby",
	"filter", "where", "condition", "from", "to", "start", "end",
	"ref", "refid", "ref_id", "source", "src", "origin",
	"name", "username", "email", "login", "password",
	"file", "filename", "path", "dir", "folder",
	"lang", "language", "locale", "country", "region",
	"pid", "sid", "tid", "rid", "vid", "bid", "gid",
	"cid", "eid", "lid", "mid", "nid", "oid", "qid",
	"select", "update", "delete", "insert", "drop", "table", "column",
	"tag", "tags", "label", "group", "department", "class",
	"postid", "post_id", "thread", "thread_id", "forum", "forum_id",
	"parent", "parent_id", "child", "child_id",
	"price", "amount", "quantity", "qty", "total",
}

// filterSQLiProneURLs filters parameterized URLs that contain SQL-injection-prone parameters.
// This is equivalent to what `gf sqli` does — narrows the attack surface to high-value targets.
func filterSQLiProneURLs(urls []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, rawURL := range urls {
		if !strings.Contains(rawURL, "?") {
			continue
		}

		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		params := parsed.Query()
		for paramName := range params {
			lower := strings.ToLower(paramName)
			for _, pattern := range sqliParamPatterns {
				if lower == pattern || strings.HasSuffix(lower, "_"+pattern) || strings.HasPrefix(lower, pattern+"_") {
					// Normalize URL: replace param values with placeholder for dedup
					normalized := normalizeURLForDedup(parsed)
					if !seen[normalized] {
						seen[normalized] = true
						result = append(result, rawURL)
					}
					goto nextURL
				}
			}
		}
	nextURL:
	}

	return result
}

// normalizeURLForDedup replaces all param values with "1" for deduplication.
// e.g. /items?id=5 and /items?id=9 → same key = deduplicated.
// Creates a copy to avoid mutating the original parsed URL.
func normalizeURLForDedup(parsed *url.URL) string {
	// Work on a shallow copy so the caller's *url.URL is not mutated
	u := *parsed // u is a value copy, not a pointer copy
	q := u.Query()
	normalized := url.Values{}
	for k := range q {
		normalized.Set(k, "1")
	}
	u.RawQuery = normalized.Encode()
	return u.String()
}

// runSQLiScan performs SQL injection detection using two strategies:
//  1. Nuclei with sqli/injection tags on live hosts (fast, template-based)
//  2. Targeted nuclei fuzzing on gf-filtered parameterized URLs (precise)
//
// SQLMap is NOT run automatically — it's too slow and gets blocked by WAFs.
// Users who want SQLMap can run it manually on the nuclei-confirmed targets.
func (e *Engine) runSQLiScan(ctx context.Context, liveHosts []string, allURLs []string) ([]Finding, error) {
	var findings []Finding

	// ── Strategy 1: Nuclei SQLi templates on live hosts ──
	nucleiFindings, err := e.runNucleiSQLi(ctx, liveHosts)
	if err != nil {
		e.log.Warnf("Nuclei SQLi scan error: %v", err)
	} else {
		findings = append(findings, nucleiFindings...)
	}

	// ── Strategy 2: Parameter-targeted nuclei fuzzing ──
	sqliURLs := filterSQLiProneURLs(allURLs)
	if len(sqliURLs) > 0 {
		// Cap at 50 — nuclei fuzzing is fast enough
		if len(sqliURLs) > 50 {
			sqliURLs = sqliURLs[:50]
		}
		e.log.Debugf("SQLi: found %d gf-filtered param URLs to fuzz", len(sqliURLs))
		paramFindings, err := e.runNucleiSQLiFuzz(ctx, sqliURLs)
		if err != nil {
			e.log.Warnf("Nuclei SQLi fuzz error: %v", err)
		} else {
			findings = append(findings, paramFindings...)
		}
	} else {
		e.log.Debugf("SQLi: no SQL-prone parameter URLs found — skipping param fuzzing")
	}

	return findings, nil
}

// runNucleiSQLi runs nuclei with SQL injection detection templates on live hosts.
// Uses sqli, injection, and database error-based tags.
func (e *Engine) runNucleiSQLi(ctx context.Context, hosts []string) ([]Finding, error) {
	if len(hosts) == 0 {
		return nil, nil
	}

	if _, err := exec.LookPath("nuclei"); err != nil {
		return nil, fmt.Errorf("nuclei not installed")
	}

	tmpFile, err := os.CreateTemp("", "nuclei-sqli-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, h := range hosts {
		if !strings.HasPrefix(h, "http") {
			h = "https://" + h
		}
		fmt.Fprintln(tmpFile, h)
	}
	tmpFile.Close()

	args := []string{
		"-l", tmpFile.Name(),
		"-jsonl",
		"-silent",
		"-tags", "sqli,injection,sql",
		"-severity", "critical,high,medium",
		"-c", "25",
		"-rl", "50",
		"-timeout", "15",
		"-retries", "2",
	}

	// Add template path if configured
	if e.cfg.Scanning.Tools.Nuclei.TemplatesPath != "" {
		tp := e.cfg.Scanning.Tools.Nuclei.TemplatesPath
		args = append(args,
			"-t", tp+"/http/vulnerabilities/",
			"-t", tp+"/http/injection/",
		)
	}

	nucleiCtx, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(nucleiCtx, "nuclei", args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	output, err := cmd.Output()
	if err != nil && len(output) == 0 {
		return nil, nil
	}

	return parseNucleiOutput(output), nil
}

// runNucleiSQLiFuzz runs nuclei fuzzing templates on gf-filtered parameterized URLs.
// This is more targeted and effective than blind sqlmap on Wayback URLs.
func (e *Engine) runNucleiSQLiFuzz(ctx context.Context, paramURLs []string) ([]Finding, error) {
	if len(paramURLs) == 0 {
		return nil, nil
	}

	if _, err := exec.LookPath("nuclei"); err != nil {
		return nil, nil
	}

	tmpFile, err := os.CreateTemp("", "nuclei-sqli-fuzz-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, u := range paramURLs {
		fmt.Fprintln(tmpFile, u)
	}
	tmpFile.Close()

	args := []string{
		"-l", tmpFile.Name(),
		"-jsonl",
		"-silent",
		"-tags", "sqli,injection,fuzz",
		"-severity", "critical,high,medium",
		"-c", "10",
		"-rl", "30",
		"-timeout", "20",
		"-retries", "1",
	}

	if e.cfg.Scanning.Tools.Nuclei.TemplatesPath != "" {
		tp := e.cfg.Scanning.Tools.Nuclei.TemplatesPath
		args = append(args, "-t", tp+"/http/fuzzing/")
	}

	fuzzCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(fuzzCtx, "nuclei", args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	output, err := cmd.Output()
	if err != nil && len(output) == 0 {
		return nil, nil
	}

	return parseNucleiOutput(output), nil
}

// parseNucleiOutput parses nuclei JSONL output into Finding structs.
// Shared by both SQLi strategies.
func parseNucleiOutput(output []byte) []Finding {
	var findings []Finding
	sc := bufio.NewScanner(strings.NewReader(string(output)))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}

		var r struct {
			TemplateID       string                 `json:"template-id"`
			Info             map[string]interface{} `json:"info"`
			MatcherName      string                 `json:"matcher-name"`
			Type             string                 `json:"type"`
			Host             string                 `json:"host"`
			MatchedAt        string                 `json:"matched-at"`
			ExtractedResults []string               `json:"extracted-results"`
			Request          string                 `json:"request"`
			Response         string                 `json:"response"`
			CURLCommand      string                 `json:"curl-command"`
			Timestamp        string                 `json:"timestamp"`
		}

		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}

		severity := "medium"
		title := r.TemplateID
		description := ""

		if s, ok := r.Info["severity"].(string); ok {
			severity = strings.ToLower(s)
		}
		if n, ok := r.Info["name"].(string); ok {
			title = n
		}
		if d, ok := r.Info["description"].(string); ok {
			description = d
		}

		var tags []string
		if tagsRaw, ok := r.Info["tags"]; ok {
			switch v := tagsRaw.(type) {
			case []interface{}:
				for _, t := range v {
					if s, ok := t.(string); ok {
						tags = append(tags, s)
					}
				}
			case string:
				tags = strings.Split(v, ",")
			}
		}

		cve := ""
		if cls, ok := r.Info["classification"].(map[string]interface{}); ok {
			if cveID, ok := cls["cve-id"]; ok {
				switch v := cveID.(type) {
				case []interface{}:
					if len(v) > 0 {
						if s, ok := v[0].(string); ok {
							cve = s
						}
					}
				case string:
					cve = v
				}
			}
		}

		findings = append(findings, Finding{
			ID:          r.TemplateID,
			Title:       title,
			Description: description,
			Severity:    severity,
			Type:        "sqli",
			Target:      r.Host,
			URL:         r.MatchedAt,
			Evidence:    strings.Join(r.ExtractedResults, "\n"),
			Request:     r.Request,
			Response:    r.Response,
			CVE:         cve,
			Tags:        tags,
			Timestamp:   time.Now().Format(time.RFC3339),
			Metadata: map[string]string{
				"tool":    "nuclei-sqli",
				"matcher": r.MatcherName,
				"curl":    r.CURLCommand,
			},
		})
	}

	return findings
}
