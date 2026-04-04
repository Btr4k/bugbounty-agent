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
	"sort"
	"strings"
	"time"
)

// runFfuf performs two phases:
//  1. Directory/file brute-forcing on prioritized live hosts
//  2. Virtual-host (vhost) fuzzing to discover hidden internal apps
func (e *Engine) runFfuf(ctx context.Context, liveHosts []string) ([]Finding, error) {
	var findings []Finding

	if len(liveHosts) == 0 {
		return findings, nil
	}

	if _, err := exec.LookPath("ffuf"); err != nil {
		e.log.Warnf("ffuf not installed - skipping (install: go install github.com/ffuf/ffuf/v2@latest)")
		return findings, nil
	}

	// ── Phase 1: Directory/file brute-force ──
	pathFindings, err := e.runFfufPaths(ctx, liveHosts)
	if err != nil {
		e.log.Debugf("ffuf path scan error: %v", err)
	}
	findings = append(findings, pathFindings...)

	// ── Phase 2: Virtual-host discovery ──
	vhostFindings, err := e.runFfufVhost(ctx, liveHosts)
	if err != nil {
		e.log.Debugf("ffuf vhost scan error: %v", err)
	}
	findings = append(findings, vhostFindings...)

	return findings, nil
}

// runFfufPaths does directory/file brute-forcing on prioritized hosts.
// Hosts are scored by importance (admin, api, dev > random subdomains)
// and the top N are scanned.
func (e *Engine) runFfufPaths(ctx context.Context, liveHosts []string) ([]Finding, error) {
	var findings []Finding

	wordlistPath := e.cfg.Scanning.Tools.Ffuf.WordlistPath
	if wordlistPath == "" {
		commonPaths := []string{
			"/usr/share/wordlists/dirb/common.txt",
			"/usr/share/seclists/Discovery/Web-Content/common.txt",
			"/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
			"/opt/SecLists/Discovery/Web-Content/common.txt",
		}
		for _, p := range commonPaths {
			if _, err := os.Stat(p); err == nil {
				wordlistPath = p
				break
			}
		}
	}

	if wordlistPath == "" {
		e.log.Debugf("ffuf: no wordlist found, building built-in high-value list")
		tmpWordlist, err := os.CreateTemp("", "ffuf-wordlist-*.txt")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp wordlist: %w", err)
		}
		defer os.Remove(tmpWordlist.Name())

		highValuePaths := []string{
			// Secrets & credentials
			".env", ".env.bak", ".env.local", ".env.production", ".env.staging", ".env.example",
			".git/config", ".git/HEAD", ".gitignore",
			".svn/entries", ".svn/wc.db",
			".htaccess", ".htpasswd",
			".aws/credentials", "aws.yml",
			".npmrc", ".docker", ".kube/config",
			// Backup files
			"backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "database.sql",
			"site.zip", "www.zip", "public.zip", "dump.sql",
			"backup", "bak", "old", "temp", "tmp",
			// Admin panels
			"admin", "administrator", "admin.php", "admin.html",
			"wp-admin", "wp-login.php", "wp-config.php", "wp-config.php.bak",
			"login", "signin", "dashboard", "panel", "cpanel",
			"phpmyadmin", "pma", "adminer", "adminer.php",
			// API & docs
			"api", "api/v1", "api/v2", "api/v3",
			"graphql", "graphiql", "playground",
			"swagger", "swagger.json", "swagger.yaml", "swagger-ui",
			"api-docs", "openapi.json", "openapi.yaml",
			"v1", "v2", "v3",
			// Debug / dev
			"debug", "debug.php", "test", "test.php", "info.php", "phpinfo.php",
			"server-status", "server-info",
			"console", "shell", "cmd",
			"trace.axd", "elmah.axd",
			"_debug", "_profiler", "_debugbar",
			// Spring Boot actuators (high-value)
			"actuator", "actuator/health", "actuator/env", "actuator/configprops",
			"actuator/mappings", "actuator/beans", "actuator/heapdump", "actuator/loggers",
			"jolokia", "jolokia/list",
			// Config exposure
			"config", "config.php", "config.yml", "config.yaml", "config.json",
			"settings", "settings.php", "settings.json",
			"application.yml", "application.properties",
			"composer.json", "package.json", "Gemfile", "requirements.txt",
			"Dockerfile", "docker-compose.yml", ".gitlab-ci.yml", ".circleci/config.yml",
			// Uploads / logs
			"uploads", "upload", "files", "documents",
			"private", "internal", "secret", "secrets",
			"logs", "log", "error.log", "access.log", "debug.log",
			// Status/health
			"status", "health", "healthcheck", "health-check",
			"metrics", "prometheus", "ready", "live",
			// WordPress
			"wp-json", "wp-json/wp/v2/users",
			// Misc
			"robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt",
			"crossdomain.xml", "clientaccesspolicy.xml",
			"web.config", "cgi-bin",
		}

		for _, p := range highValuePaths {
			fmt.Fprintln(tmpWordlist, p)
		}
		tmpWordlist.Close()
		wordlistPath = tmpWordlist.Name()
	}

	// Prioritize hosts: score by name importance, scan top N
	maxHosts := e.cfg.Scanning.Tools.Ffuf.MaxTargets
	if maxHosts <= 0 {
		maxHosts = 20
	}
	prioritized := prioritizeFfufHosts(liveHosts, maxHosts)

	e.log.Debugf("ffuf: scanning %d prioritized hosts (of %d total)", len(prioritized), len(liveHosts))

	for _, host := range prioritized {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			host = "https://" + host
		}
		host = strings.TrimRight(host, "/")

		hostFindings, err := e.runFfufOnHost(ctx, host, wordlistPath)
		if err != nil {
			e.log.Debugf("ffuf failed for %s: %v", host, err)
			continue
		}
		findings = append(findings, hostFindings...)
	}

	return findings, nil
}

// prioritizeFfufHosts scores hosts by name importance and returns top N.
// High-value prefixes (admin, api, dev, staging) get higher priority.
func prioritizeFfufHosts(hosts []string, limit int) []string {
	highValuePrefixes := []string{
		"admin", "api", "dev", "staging", "test", "beta", "internal",
		"app", "portal", "dashboard", "manage", "manager", "control",
		"backend", "console", "panel", "vpn", "remote", "secure",
		"auth", "login", "account", "user", "member",
		"corp", "intranet", "staff", "hr", "finance", "git",
		"jenkins", "ci", "cd", "build", "deploy",
		"mail", "smtp", "webmail",
	}

	type scored struct {
		host  string
		score int
	}

	var items []scored
	for _, h := range hosts {
		hostname := extractHostname(h)
		parts := strings.SplitN(hostname, ".", 2)
		sub := strings.ToLower(parts[0])
		score := 0

		for _, prefix := range highValuePrefixes {
			if sub == prefix || strings.HasPrefix(sub, prefix) || strings.Contains(sub, prefix) {
				score += 20
				break
			}
		}
		// Shorter = more important (main domain vs random sub)
		if len(strings.Split(hostname, ".")) <= 2 {
			score += 15
		} else if len(strings.Split(hostname, ".")) == 3 {
			score += 5
		}
		// Penalize random-looking long subdomains
		if len(sub) > 20 {
			score -= 10
		}

		items = append(items, scored{host: h, score: score})
	}

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].score > items[j].score
	})

	if len(items) > limit {
		items = items[:limit]
	}

	result := make([]string, len(items))
	for i, item := range items {
		result[i] = item.host
	}
	return result
}

func (e *Engine) runFfufOnHost(ctx context.Context, host, wordlistPath string) ([]Finding, error) {
	var findings []Finding

	hostCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	tmpOut, err := os.CreateTemp("", "ffuf-out-*.json")
	if err != nil {
		return nil, err
	}
	tmpOut.Close()
	defer os.Remove(tmpOut.Name())

	args := []string{
		"-u", host + "/FUZZ",
		"-w", wordlistPath,
		"-mc", "200,201,204,301,302,307,401,403,405,500",
		"-fc", "404",
		"-ac",                          // Auto-calibrate
		"-s",                           // Silent
		"-json",
		"-timeout", "10",
		"-rate", "80",                  // Increased from 50
		"-t", "15",                     // More threads per host
		"-recursion", "-recursion-depth", "2", // Deeper recursion
		"-o", tmpOut.Name(),
	}

	cmd := exec.CommandContext(hostCtx, "ffuf", args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		// ffuf exits non-zero when no results — read output anyway
		if _, statErr := os.Stat(tmpOut.Name()); statErr != nil {
			return findings, nil
		}
	}

	data, err := os.ReadFile(tmpOut.Name())
	if err != nil || len(data) == 0 {
		return findings, nil
	}

	var ffufOutput struct {
		Results []struct {
			Input struct {
				FUZZ string `json:"FUZZ"`
			} `json:"input"`
			Status      int    `json:"status"`
			Length      int    `json:"length"`
			Words       int    `json:"words"`
			ContentType string `json:"content-type"`
			URL         string `json:"url"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &ffufOutput); err != nil {
		// Try line-by-line (some ffuf versions)
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			if err := json.Unmarshal(sc.Bytes(), &ffufOutput); err == nil {
				break
			}
		}
	}

	for _, result := range ffufOutput.Results {
		severity := classifyFfufSeverity(result.Input.FUZZ, result.Status)
		if severity == "" {
			continue
		}

		title := classifyFfufTitle(result.Input.FUZZ, result.Status)

		findings = append(findings, Finding{
			ID:          fmt.Sprintf("ffuf-%s", result.Input.FUZZ),
			Title:       title,
			Description: fmt.Sprintf("Discovered path '%s' (HTTP %d, %d bytes)", result.Input.FUZZ, result.Status, result.Length),
			Severity:    severity,
			Type:        "directory-bruteforce",
			URL:         result.URL,
			Target:      host,
			Evidence:    fmt.Sprintf("HTTP %d | Size: %d bytes | Words: %d | Path: /%s", result.Status, result.Length, result.Words, result.Input.FUZZ),
			Tags:        []string{"ffuf", "directory", "exposure"},
			Metadata: map[string]string{
				"tool":         "ffuf",
				"status_code":  fmt.Sprintf("%d", result.Status),
				"content_type": result.ContentType,
				"path":         result.Input.FUZZ,
			},
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}

	return findings, nil
}

// runFfufVhost discovers virtual hosts by fuzzing the Host header.
// Many internal apps are accessible only via specific vhost names that don't
// appear in standard subdomain enumeration.
func (e *Engine) runFfufVhost(ctx context.Context, liveHosts []string) ([]Finding, error) {
	var findings []Finding

	if len(liveHosts) == 0 {
		return findings, nil
	}

	// Build vhost wordlist from common internal naming patterns
	tmpWordlist, err := os.CreateTemp("", "ffuf-vhost-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create vhost wordlist: %w", err)
	}
	defer os.Remove(tmpWordlist.Name())

	vhostNames := []string{
		"admin", "administrator", "internal", "intranet", "corp",
		"api", "api2", "api3", "api-internal", "api-dev",
		"dev", "development", "staging", "stage", "test", "testing",
		"beta", "alpha", "demo", "sandbox", "qa",
		"app", "application", "portal", "dashboard",
		"backend", "backoffice", "back", "manage", "management",
		"console", "panel", "control", "controlpanel",
		"vpn", "remote", "secure", "ssl",
		"mail", "webmail", "smtp", "imap", "pop3",
		"git", "gitlab", "github", "bitbucket", "svn",
		"jenkins", "ci", "cd", "build", "deploy", "devops",
		"monitor", "monitoring", "grafana", "prometheus", "kibana",
		"jira", "confluence", "wiki", "docs", "documentation",
		"shop", "store", "pay", "payment", "checkout",
		"cdn", "static", "assets", "media",
		"db", "database", "mysql", "postgres", "redis", "mongo",
		"ftp", "sftp", "ssh",
		"old", "legacy", "backup", "archive",
		"support", "help", "helpdesk", "ticket",
		"auth", "login", "sso", "oauth", "oidc",
		"staff", "hr", "employee", "people",
		"finance", "billing", "invoice", "accounting",
		"crm", "erp", "cms",
		"report", "reports", "analytics", "metrics", "stats",
		"partner", "vendor", "supplier", "client",
		"mobile", "m", "ios", "android", "app",
		"socket", "ws", "websocket",
		"proxy", "gateway", "edge", "fw", "firewall",
		"ns", "ns1", "ns2", "dns",
		"mx", "mx1", "mx2",
		"fw", "vpn1", "vpn2",
		"office", "extranet",
		"search", "elastic", "solr",
		"cache", "memcache",
		"queue", "mq", "rabbitmq", "kafka",
		"upload", "uploads", "files", "storage",
		"secret", "secrets", "vault",
	}

	for _, v := range vhostNames {
		fmt.Fprintln(tmpWordlist, v)
	}
	tmpWordlist.Close()

	// Run vhost fuzzing on the primary host (main domain)
	// Use the first live host as the base — it represents the main IP
	var baseTarget string
	for _, h := range liveHosts {
		hostname := extractHostname(h)
		parts := strings.Split(hostname, ".")
		if len(parts) >= 2 {
			// Prefer the root domain (fewest subdomain labels)
			if baseTarget == "" || len(strings.Split(extractHostname(baseTarget), ".")) > len(parts) {
				baseTarget = h
			}
		}
	}

	if baseTarget == "" {
		return findings, nil
	}

	baseDomain := extractRootDomain(extractHostname(baseTarget))
	if baseDomain == "" {
		return findings, nil
	}

	if !strings.HasPrefix(baseTarget, "http") {
		baseTarget = "https://" + baseTarget
	}
	// Use url.Parse to cleanly extract scheme+host (strips path, query, fragment)
	if parsed, err := url.Parse(baseTarget); err == nil && parsed.Host != "" {
		baseTarget = parsed.Scheme + "://" + parsed.Host
	}

	e.log.Debugf("ffuf vhost: fuzzing against %s with domain %s", baseTarget, baseDomain)

	vhostCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	tmpOut, err := os.CreateTemp("", "ffuf-vhost-out-*.json")
	if err != nil {
		return nil, err
	}
	tmpOut.Close()
	defer os.Remove(tmpOut.Name())

	args := []string{
		"-u", baseTarget,
		"-H", fmt.Sprintf("Host: FUZZ.%s", baseDomain),
		"-w", tmpWordlist.Name(),
		"-ac",
		"-s",
		"-json",
		"-timeout", "10",
		"-rate", "50",
		"-t", "10",
		"-o", tmpOut.Name(),
	}

	cmd := exec.CommandContext(vhostCtx, "ffuf", args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		// Non-zero exit is normal when no results
	}

	data, err := os.ReadFile(tmpOut.Name())
	if err != nil || len(data) == 0 {
		return findings, nil
	}

	var ffufOutput struct {
		Results []struct {
			Input struct {
				FUZZ string `json:"FUZZ"`
			} `json:"input"`
			Status int    `json:"status"`
			Length int    `json:"length"`
			Words  int    `json:"words"`
			URL    string `json:"url"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &ffufOutput); err != nil {
		return findings, nil
	}

	if len(ffufOutput.Results) == 0 {
		return findings, nil
	}

	// ── Catch-all false positive filter ──
	// If the server returns the same response body size for ALL results,
	// it's a catch-all (CDN/WAF returning identical 403/200 for any Host header).
	// Real vhosts have distinct response sizes — filter out homogeneous results.
	sizeFreq := make(map[int]int)
	for _, r := range ffufOutput.Results {
		sizeFreq[r.Length]++
	}
	// Find the most common size
	maxCount := 0
	dominantSize := -1
	for size, count := range sizeFreq {
		if count > maxCount {
			maxCount = count
			dominantSize = size
		}
	}
	// If >70% of results share the same response size → catch-all, discard all
	if len(ffufOutput.Results) > 3 && maxCount*10 > len(ffufOutput.Results)*7 {
		e.log.Debugf("ffuf vhost: catch-all detected (dominant size %d bytes, %d/%d results) — discarding as false positives",
			dominantSize, maxCount, len(ffufOutput.Results))
		return findings, nil
	}

	for _, result := range ffufOutput.Results {
		// Skip results that match the dominant catch-all size
		if result.Length == dominantSize && maxCount > 1 {
			continue
		}

		vhostName := fmt.Sprintf("%s.%s", result.Input.FUZZ, baseDomain)

		severity := "high"
		if result.Status == 401 || result.Status == 403 {
			severity = "medium"
		}

		findings = append(findings, Finding{
			ID:    fmt.Sprintf("ffuf-vhost-%s", result.Input.FUZZ),
			Title: fmt.Sprintf("Virtual Host Discovered: %s", vhostName),
			Description: fmt.Sprintf(
				"Virtual host '%s' discovered via Host header fuzzing with a unique response (HTTP %d, %d bytes). "+
					"This host may expose internal or admin functionality not accessible via standard subdomain enumeration.",
				vhostName, result.Status, result.Length,
			),
			Severity: severity,
			Type:     "vhost-discovery",
			Target:   baseTarget,
			URL:      fmt.Sprintf("https://%s", vhostName),
			Evidence: fmt.Sprintf("Host: %s → HTTP %d | Size: %d bytes | Words: %d", vhostName, result.Status, result.Length, result.Words),
			Tags:     []string{"ffuf", "vhost", "recon", "host-header"},
			Metadata: map[string]string{
				"tool":        "ffuf-vhost",
				"vhost":       vhostName,
				"base_target": baseTarget,
				"status_code": fmt.Sprintf("%d", result.Status),
			},
			Timestamp: time.Now().Format(time.RFC3339),
		})
	}

	e.log.Debugf("ffuf vhost: found %d real virtual hosts (after catch-all filter) for %s",
		len(findings), baseDomain)
	return findings, nil
}

// extractRootDomain returns the root domain (last 2 labels) from a hostname.
// e.g. "admin.example.com" → "example.com"
func extractRootDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return ""
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

// classifyFfufSeverity determines severity based on what was found
func classifyFfufSeverity(path string, status int) string {
	lower := strings.ToLower(path)

	criticalPaths := []string{
		".env", ".git/config", ".git/head", ".aws/credentials",
		".htpasswd", "wp-config.php", "backup.sql", "db.sql", "database.sql",
		".kube/config", ".npmrc",
		"actuator/heapdump", "actuator/env", "actuator/configprops",
	}
	for _, p := range criticalPaths {
		if lower == p || strings.HasPrefix(lower, p) {
			if status == 200 || status == 301 || status == 302 {
				return "critical"
			}
		}
	}

	highPaths := []string{
		"admin", "administrator", "phpmyadmin", "adminer",
		"debug", "console", "shell", "phpinfo",
		"graphql", "graphiql", "swagger", "api-docs",
		"actuator", "jolokia", "trace.axd", "elmah.axd",
		"server-status", "server-info",
		"_debug", "_profiler", "_debugbar",
	}
	for _, p := range highPaths {
		if lower == p || strings.HasPrefix(lower, p+"/") || strings.HasPrefix(lower, p+".") {
			if status == 200 || status == 301 || status == 302 {
				return "high"
			}
			if status == 401 || status == 403 {
				return "medium"
			}
		}
	}

	mediumPaths := []string{
		"backup", "config", "settings", "uploads", "private",
		"internal", "secret", "logs", "log",
		"composer.json", "package.json", "requirements.txt",
		"Dockerfile", "docker-compose", ".gitlab-ci",
		".github", ".circleci",
	}
	for _, p := range mediumPaths {
		if lower == p || strings.HasPrefix(lower, p) {
			if status == 200 || status == 301 || status == 302 {
				return "medium"
			}
		}
	}

	if status == 200 {
		lowPaths := []string{"robots.txt", "sitemap.xml", "security.txt", "crossdomain.xml"}
		for _, p := range lowPaths {
			if lower == p {
				return "low"
			}
		}
	}

	if status == 200 && (strings.Contains(lower, "api") || strings.Contains(lower, "v1") || strings.Contains(lower, "v2")) {
		return "medium"
	}

	if status == 500 {
		return "low"
	}

	return ""
}

// classifyFfufTitle generates descriptive title based on finding type
func classifyFfufTitle(path string, status int) string {
	lower := strings.ToLower(path)

	if strings.HasPrefix(lower, ".env") {
		return "Environment File Exposed (.env)"
	}
	if strings.HasPrefix(lower, ".git") {
		return "Git Repository Exposed (.git)"
	}
	if strings.HasPrefix(lower, ".svn") {
		return "SVN Repository Exposed (.svn)"
	}
	if strings.HasPrefix(lower, ".aws") || strings.HasPrefix(lower, "aws") {
		return "AWS Credentials File Exposed"
	}
	if lower == ".htpasswd" {
		return "htpasswd File Exposed"
	}
	if strings.Contains(lower, "backup") || strings.HasSuffix(lower, ".sql") || strings.HasSuffix(lower, ".zip") {
		return "Backup File/Directory Discovered"
	}
	if strings.Contains(lower, "admin") || strings.Contains(lower, "phpmyadmin") || strings.Contains(lower, "adminer") {
		if status == 401 || status == 403 {
			return "Admin Panel Found (Protected)"
		}
		return "Admin Panel Exposed"
	}
	if strings.Contains(lower, "graphql") || strings.Contains(lower, "graphiql") {
		return "GraphQL Endpoint Discovered"
	}
	if strings.Contains(lower, "swagger") || strings.Contains(lower, "api-docs") || strings.Contains(lower, "openapi") {
		return "API Documentation Exposed (Swagger/OpenAPI)"
	}
	if strings.Contains(lower, "actuator") || strings.Contains(lower, "jolokia") {
		return "Spring Actuator/Management Endpoint Exposed"
	}
	if strings.Contains(lower, "debug") || strings.Contains(lower, "profiler") || strings.Contains(lower, "phpinfo") {
		return "Debug/Profiling Endpoint Exposed"
	}
	if strings.Contains(lower, "config") || strings.Contains(lower, "settings") {
		return "Configuration File Exposed"
	}
	if strings.Contains(lower, "wp-") {
		return "WordPress Sensitive File Exposed"
	}
	if strings.Contains(lower, "docker") || strings.Contains(lower, "kube") {
		return "Container/Orchestration Config Exposed"
	}
	if status == 500 {
		return fmt.Sprintf("Server Error on Path /%s", path)
	}
	if status == 401 || status == 403 {
		return fmt.Sprintf("Protected Path Discovered (/%s)", path)
	}

	return fmt.Sprintf("Sensitive Path Discovered (/%s)", path)
}
