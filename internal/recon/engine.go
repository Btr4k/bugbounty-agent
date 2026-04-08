package recon

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
)

type Engine struct {
	cfg *config.Config
	log *logger.Logger
}

type Results struct {
	Subdomains   []string
	URLs         []string
	Endpoints    []string
	IPs          []string
	Technologies []Technology
	Secrets      []Secret
	JSFiles      []JSFile
}

type JSFile struct {
	URL     string `json:"url"`
	Content string `json:"content"`
	Size    int    `json:"size"`
	Source  string `json:"source"` // "katana" or "wayback"
}

type Technology struct {
	Name     string
	Version  string
	Category string
}

type Secret struct {
	Type       string
	Value      string
	Source     string
	Confidence float64
}

func NewEngine(cfg *config.Config, log *logger.Logger) *Engine {
	return &Engine{
		cfg: cfg,
		log: log,
	}
}

func (e *Engine) Run(ctx context.Context) (*Results, error) {
	// Apply timeout from config
	ctx, cancel := context.WithTimeout(ctx, time.Duration(e.cfg.Recon.Timeout)*time.Second)
	defer cancel()

	results := &Results{
		Subdomains:   make([]string, 0),
		URLs:         make([]string, 0),
		Endpoints:    make([]string, 0),
		IPs:          make([]string, 0),
		Technologies: make([]Technology, 0),
		Secrets:      make([]Secret, 0),
		JSFiles:      make([]JSFile, 0),
	}

	var wg sync.WaitGroup
	mu := &sync.Mutex{}

	e.log.PhaseNote(fmt.Sprintf("Target: %s (timeout: %ds)", e.cfg.Target.Domains[0], e.cfg.Recon.Timeout))

	// Subfinder
	if e.cfg.Recon.Tools.Subfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.log.ToolStart("Subfinder", "enumerating subdomains...")
			start := time.Now()
			subs, err := e.runSubfinder(ctx)
			if err != nil {
				e.log.ToolFail("Subfinder", err)
				return
			}
			e.log.ToolDone("Subfinder", len(subs), time.Since(start))
			mu.Lock()
			results.Subdomains = append(results.Subdomains, subs...)
			mu.Unlock()
		}()
	} else {
		e.log.ToolSkip("Subfinder", "disabled in config")
	}

	// Assetfinder
	if e.cfg.Recon.Tools.Assetfinder {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.log.ToolStart("Assetfinder", "discovering assets...")
			start := time.Now()
			subs, err := e.runAssetfinder(ctx)
			if err != nil {
				e.log.ToolFail("Assetfinder", err)
				return
			}
			e.log.ToolDone("Assetfinder", len(subs), time.Since(start))
			mu.Lock()
			results.Subdomains = append(results.Subdomains, subs...)
			mu.Unlock()
		}()
	} else {
		e.log.ToolSkip("Assetfinder", "disabled in config")
	}

	// Wayback URLs
	if e.cfg.Recon.Tools.Wayback {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.log.ToolStart("WaybackURLs", "fetching historical URLs...")
			start := time.Now()
			urls, err := e.runWaybackURLs(ctx)
			if err != nil {
				e.log.ToolFail("WaybackURLs", err)
				return
			}
			e.log.ToolDone("WaybackURLs", len(urls), time.Since(start))
			mu.Lock()
			results.URLs = append(results.URLs, urls...)
			mu.Unlock()
		}()
	} else {
		e.log.ToolSkip("WaybackURLs", "disabled in config")
	}

	// GitHub Secrets
	if e.cfg.Recon.Tools.GitHubDorking {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.log.ToolStart("GitHub Dorking", "searching for exposed secrets...")
			start := time.Now()
			secrets, err := e.searchGitHubSecrets(ctx)
			if err != nil {
				e.log.ToolFail("GitHub Dorking", err)
				return
			}
			e.log.ToolDone("GitHub Dorking", len(secrets), time.Since(start))
			mu.Lock()
			results.Secrets = append(results.Secrets, secrets...)
			mu.Unlock()
		}()
	} else {
		e.log.ToolSkip("GitHub Dorking", "disabled in config")
	}

	// C99 API Intelligence
	if e.cfg.C99.Enabled && e.cfg.C99.APIKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.log.ToolStart("C99 API", "querying subdomain intelligence...")
			start := time.Now()
			subs, err := e.runC99Subdomains(ctx)
			if err != nil {
				e.log.ToolFail("C99 API", err)
				return
			}
			e.log.ToolDone("C99 API", len(subs), time.Since(start))
			mu.Lock()
			results.Subdomains = append(results.Subdomains, subs...)
			mu.Unlock()
		}()
	} else {
		e.log.ToolSkip("C99 API", "disabled or no API key")
	}

	// Certificate Transparency
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.log.ToolStart("CertTransparency", "querying CT logs...")
		start := time.Now()
		subs, err := e.runCertTransparency(ctx)
		if err != nil {
			e.log.ToolFail("CertTransparency", err)
			return
		}
		e.log.ToolDone("CertTransparency", len(subs), time.Since(start))
		mu.Lock()
		results.Subdomains = append(results.Subdomains, subs...)
		mu.Unlock()
	}()

	// Wait for all goroutines
	wg.Wait()

	// Deduplicate
	results.Subdomains = e.deduplicate(results.Subdomains)
	results.URLs = e.deduplicate(results.URLs)

	// Sanitize subdomains: strip wildcards, remove invalid entries
	results.Subdomains = e.sanitizeSubdomains(results.Subdomains)

	// Apply limits (guard against MaxSubdomains=0 to avoid wiping results)
	if e.cfg.Recon.MaxSubdomains > 0 && len(results.Subdomains) > e.cfg.Recon.MaxSubdomains {
		results.Subdomains = results.Subdomains[:e.cfg.Recon.MaxSubdomains]
	}

	// ═══════════════════════════════════════
	// JS File Extraction (after subdomains are ready)
	// ═══════════════════════════════════════
	var jsURLs []string

	// Katana JS crawling
	if e.cfg.Recon.Tools.Katana {
		e.log.ToolStart("Katana", "crawling for JS files...")
		start := time.Now()
		kURLs, err := e.runKatana(ctx, results.Subdomains)
		if err != nil {
			e.log.ToolFail("Katana", err)
		} else {
			e.log.ToolDone("Katana", len(kURLs), time.Since(start))
			jsURLs = append(jsURLs, kURLs...)
		}
	} else {
		e.log.ToolSkip("Katana", "disabled in config")
	}

	// Extract JS from Wayback URLs (fallback/supplement)
	if len(results.URLs) > 0 {
		waybackJS := e.extractJSFromURLs(results.URLs)
		if len(waybackJS) > 0 {
			e.log.PhaseNote(fmt.Sprintf("Found %d additional JS URLs from Wayback", len(waybackJS)))
			jsURLs = append(jsURLs, waybackJS...)
		}
	}

	// Deduplicate JS URLs
	jsURLs = e.deduplicate(jsURLs)

	// Download JS content
	if len(jsURLs) > 0 {
		e.log.ToolStart("JS Download", fmt.Sprintf("fetching %d JS files...", len(jsURLs)))
		start := time.Now()
		results.JSFiles = e.downloadJSFiles(ctx, jsURLs)
		e.log.ToolDone("JS Download", len(results.JSFiles), time.Since(start))
	}

	return results, nil
}

func (e *Engine) runSubfinder(ctx context.Context) ([]string, error) {
	e.log.Debug("Running subfinder...")

	var results []string
	for _, domain := range e.cfg.Target.Domains {
		cmd := exec.CommandContext(ctx, "subfinder",
			"-d", domain,
			"-silent",
			"-all",
		)

		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("subfinder error: %w", err)
		}

		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			subdomain := strings.TrimSpace(scanner.Text())
			if subdomain != "" {
				results = append(results, subdomain)
			}
		}
	}

	return results, nil
}

func (e *Engine) runAssetfinder(ctx context.Context) ([]string, error) {
	e.log.Debug("Running assetfinder...")

	var results []string
	for _, domain := range e.cfg.Target.Domains {
		cmd := exec.CommandContext(ctx, "assetfinder",
			"--subs-only",
			domain,
		)

		output, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("assetfinder error: %w", err)
		}

		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			subdomain := strings.TrimSpace(scanner.Text())
			if subdomain != "" {
				results = append(results, subdomain)
			}
		}
	}

	return results, nil
}

func (e *Engine) runWaybackURLs(ctx context.Context) ([]string, error) {
	e.log.Debug("Running waybackurls...")

	// Configurable limit to prevent OOM on large domains
	maxURLs := e.cfg.Recon.MaxWaybackURLs
	if maxURLs <= 0 {
		maxURLs = 10000
	}

	var results []string
	for _, domain := range e.cfg.Target.Domains {
		cmd := exec.CommandContext(ctx, "waybackurls", domain)

		// Stream stdout instead of buffering all output in memory
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("waybackurls pipe error: %w", err)
		}

		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("waybackurls start error: %w", err)
		}

		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64*1024), 256*1024) // handle long URLs

		for sc.Scan() {
			if len(results) >= maxURLs {
				e.log.Infof("WaybackURLs: reached %d URL limit, stopping", maxURLs)
				break
			}
			url := strings.TrimSpace(sc.Text())
			if url != "" {
				results = append(results, url)
			}
		}

		// Kill process if limit reached (it may still be producing output)
		if len(results) >= maxURLs {
			cmd.Process.Kill()
		}

		// Wait to reap the process
		cmd.Wait()
	}

	return results, nil
}

func (e *Engine) searchGitHubSecrets(ctx context.Context) ([]Secret, error) {
	e.log.Debug("Searching GitHub for secrets...")

	var secrets []Secret

	// GitHub dorking patterns
	patterns := []string{
		"api_key",
		"secret_key",
		"password",
		"token",
		"aws_access_key",
		"private_key",
	}

	for _, domain := range e.cfg.Target.Domains {
		for _, pattern := range patterns {
			// Using github-search or manual API calls
			// This is a placeholder - implement actual GitHub API integration
			query := fmt.Sprintf("%s %s", domain, pattern)

			cmd := exec.CommandContext(ctx, "github-search",
				"-q", query,
				"-r", "10",
			)

			output, err := cmd.Output()
			if err != nil {
				continue // Skip if tool not available
			}

			// Parse results and extract secrets
			scanner := bufio.NewScanner(strings.NewReader(string(output)))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, pattern) {
					secrets = append(secrets, Secret{
						Type:       pattern,
						Value:      line,
						Source:     "github",
						Confidence: 0.7,
					})
				}
			}
		}
	}

	return secrets, nil
}

func (e *Engine) deduplicate(items []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, item := range items {
		lower := strings.ToLower(strings.TrimSpace(item))
		if lower != "" && !seen[lower] {
			seen[lower] = true
			result = append(result, item)
		}
	}

	return result
}

// sanitizeSubdomains cleans up subdomain entries from recon sources
func (e *Engine) sanitizeSubdomains(subdomains []string) []string {
	var clean []string
	for _, s := range subdomains {
		s = strings.TrimSpace(s)

		// Strip wildcard prefix
		s = strings.TrimPrefix(s, "*.")

		// Skip empty or dot-prefixed entries
		if s == "" || strings.HasPrefix(s, ".") || s == "*" {
			continue
		}

		// Must contain at least one dot (valid FQDN)
		if !strings.Contains(s, ".") {
			continue
		}

		// Max DNS name length
		if len(s) > 253 {
			continue
		}

		clean = append(clean, s)
	}
	return clean
}

// C99 API Integration
func (e *Engine) runC99Subdomains(ctx context.Context) ([]string, error) {
	e.log.Debug("Running C99 subdomain enumeration...")

	var results []string
	for _, domain := range e.cfg.Target.Domains {
		url := fmt.Sprintf("https://api.c99.nl/subdomainfinder?key=%s&domain=%s&json",
			e.cfg.C99.APIKey, domain)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("C99 request creation failed: %w", err)
		}

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("C99 API request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("C99 API returned status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read C99 response: %w", err)
		}

		// Parse C99 JSON response
		var c99Response struct {
			Success    bool `json:"success"`
			Subdomains []struct {
				Subdomain string `json:"subdomain"`
			} `json:"subdomains"`
		}

		if err := json.Unmarshal(body, &c99Response); err != nil {
			// Try alternate format (array of strings)
			var altResponse []string
			if err2 := json.Unmarshal(body, &altResponse); err2 != nil {
				return nil, fmt.Errorf("failed to parse C99 response: %w", err)
			}
			results = append(results, altResponse...)
			continue
		}

		if c99Response.Success {
			for _, sub := range c99Response.Subdomains {
				if sub.Subdomain != "" {
					results = append(results, sub.Subdomain)
				}
			}
		}
	}

	e.log.Infof("C99 found %d subdomains", len(results))
	return results, nil
}

// runCertTransparency queries Certificate Transparency logs with retry
func (e *Engine) runCertTransparency(ctx context.Context) ([]string, error) {
	e.log.Debug("Querying Certificate Transparency logs...")

	var results []string
	for _, domain := range e.cfg.Target.Domains {
		crtURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

		// Retry logic: up to 3 attempts with backoff
		var body []byte
		var lastErr error

		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				backoff := time.Duration(attempt*15) * time.Second
				e.log.Debugf("crt.sh: retry %d after %s", attempt+1, backoff)
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return results, ctx.Err()
				}
			}

			req, err := http.NewRequestWithContext(ctx, "GET", crtURL, nil)
			if err != nil {
				lastErr = err
				continue
			}

			client := &http.Client{Timeout: 90 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				lastErr = err
				e.log.Warnf("crt.sh attempt %d failed: %v", attempt+1, err)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				lastErr = fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
				continue
			}

			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				lastErr = err
				continue
			}

			lastErr = nil
			break // Success
		}

		if lastErr != nil {
			e.log.Warnf("crt.sh all attempts failed for %s: %v", domain, lastErr)
			continue
		}

		var crtEntries []struct {
			NameValue string `json:"name_value"`
		}

		if err := json.Unmarshal(body, &crtEntries); err != nil {
			continue
		}

		for _, entry := range crtEntries {
			names := strings.Split(entry.NameValue, "\n")
			for _, name := range names {
				name = strings.TrimSpace(name)
				name = strings.TrimPrefix(name, "*.")
				if name != "" {
					results = append(results, name)
				}
			}
		}
	}

	e.log.Infof("Certificate Transparency found %d entries", len(results))
	return results, nil
}

// ═══════════════════════════════════════════════════════════
// JS File Extraction Functions
// ═══════════════════════════════════════════════════════════

// runKatana crawls subdomains to discover JavaScript file URLs
func (e *Engine) runKatana(ctx context.Context, subdomains []string) ([]string, error) {
	if !isToolInstalled("katana") {
		return nil, fmt.Errorf("katana not installed (run: go install github.com/projectdiscovery/katana/cmd/katana@latest)")
	}

	var jsURLs []string

	// Limit subdomains for katana (it crawls each one)
	targets := subdomains
	if len(targets) > 30 {
		targets = targets[:30]
	}

	// Write targets to temp file
	tmpFile, err := os.CreateTemp("", "katana-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, target := range targets {
		// Ensure targets have a scheme — katana requires https:// or http://
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}
		fmt.Fprintln(tmpFile, target)
	}
	tmpFile.Close()

	// Adaptive timeout: scale based on number of targets, cap at 10 minutes
	katanaTimeout := 2*time.Minute + time.Duration(len(targets))*15*time.Second
	if katanaTimeout > 10*time.Minute {
		katanaTimeout = 10 * time.Minute
	}
	e.log.Debugf("Katana: %d targets, timeout: %s", len(targets), katanaTimeout)
	katanaCtx, cancel := context.WithTimeout(ctx, katanaTimeout)
	defer cancel()

	args := []string{
		"-list", tmpFile.Name(),
		"-jsluice",          // extract JS file URLs and inline JS endpoints (v1.1+)
		"-silent",
		"-d", "2",           // crawl depth
		"-c", "10",          // concurrency
		"-timeout", "10",
		// No -em filter: Go-side filter handles .js suffix check,
		// preserving URLs with query strings like app.js?v=123
	}

	cmd := exec.CommandContext(katanaCtx, "katana", args...)
	output, err := cmd.Output()
	if err != nil {
		// Katana might timeout but still produce results
		if len(output) == 0 {
			return nil, fmt.Errorf("katana error: %w", err)
		}
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" && strings.HasSuffix(strings.ToLower(strings.Split(url, "?")[0]), ".js") && !isNoiseJS(url) {
			jsURLs = append(jsURLs, url)
		}
	}

	return jsURLs, nil
}

// extractJSFromURLs filters JavaScript URLs from a list of discovered URLs
func (e *Engine) extractJSFromURLs(urls []string) []string {
	var jsURLs []string
	for _, u := range urls {
		lower := strings.ToLower(u)
		// Remove query params for extension check
		path := strings.Split(lower, "?")[0]
		if strings.HasSuffix(path, ".js") && !isNoiseJS(u) {
			jsURLs = append(jsURLs, u)
		}
	}
	return jsURLs
}

// isNoiseJS returns true for JS URLs that belong to CDN infrastructure,
// browser challenge scripts, or third-party analytics — files that are
// not part of the target application and will only produce false positives.
func isNoiseJS(u string) bool {
	lower := strings.ToLower(u)
	noisePatterns := []string{
		"/cdn-cgi/",           // Cloudflare challenge & analytics scripts
		"/challenge-platform/", // Cloudflare bot-management JS
		"challenges.cloudflare.com",
		"/wp-includes/js/",    // WordPress core (not app code)
		"/wp-content/plugins/", // WordPress plugins — noisy, rarely interesting
		"googletagmanager.com",
		"google-analytics.com",
		"/gtag/js",
		"facebook.net/",
		"connect.facebook.net/",
		"analytics.js",
		"gtm.js",
	}
	for _, pattern := range noisePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// downloadJSFiles downloads JS file content for AI analysis
func (e *Engine) downloadJSFiles(ctx context.Context, jsURLs []string) []JSFile {
	var jsFiles []JSFile
	mu := &sync.Mutex{}

	// Prioritize JS files: prefer app bundles over vendor/polyfill files,
	// and larger files (more code = more secrets/endpoints).
	// Sort URLs: score down vendor/polyfill/chunk, score up app/main/index/bundle.
	sort.SliceStable(jsURLs, func(i, j int) bool {
		score := func(u string) int {
			lower := strings.ToLower(u)
			s := 0
			if strings.Contains(lower, "vendor") || strings.Contains(lower, "polyfill") ||
				strings.Contains(lower, "chunk") || strings.Contains(lower, "runtime") {
				s -= 10
			}
			if strings.Contains(lower, "app") || strings.Contains(lower, "main") ||
				strings.Contains(lower, "index") || strings.Contains(lower, "bundle") ||
				strings.Contains(lower, "config") || strings.Contains(lower, "api") {
				s += 10
			}
			return s
		}
		return score(jsURLs[i]) > score(jsURLs[j])
	})
	maxFiles := 30
	if len(jsURLs) > maxFiles {
		jsURLs = jsURLs[:maxFiles]
	}

	// Max content size per file (50KB)
	const maxContentSize = 50 * 1024

	// HTTP client with TLS skip for self-signed certs
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Download concurrently (semaphore of 5)
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup

	for _, jsURL := range jsURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Determine source
			source := "katana"
			if strings.Contains(url, "web.archive.org") {
				source = "wayback"
			}

			// Ensure URL has scheme
			if !strings.HasPrefix(url, "http") {
				url = "https://" + url
			}

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BugBountyAgent/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return
			}

			// Read limited content
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxContentSize))
			if err != nil {
				return
			}

			content := string(body)
			// Skip if too small (likely error page) or is HTML
			if len(content) < 100 || strings.Contains(content[:min(200, len(content))], "<!DOCTYPE") {
				return
			}

			mu.Lock()
			jsFiles = append(jsFiles, JSFile{
				URL:     url,
				Content: content,
				Size:    len(content),
				Source:  source,
			})
			mu.Unlock()
		}(jsURL)
	}

	wg.Wait()
	return jsFiles
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isToolInstalled checks if a command-line tool is available
func isToolInstalled(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}


