package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/A-cyb3r/hawkeye/internal/config"
	"github.com/A-cyb3r/hawkeye/internal/logger"
	"github.com/A-cyb3r/hawkeye/internal/recon"
)

type Engine struct {
	cfg *config.Config
	log *logger.Logger
}

type Results struct {
	Findings []Finding
	Stats    ScanStats
}

type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Type        string            `json:"type"`
	Target      string            `json:"target"`
	URL         string            `json:"url"`
	Evidence    string            `json:"evidence"`
	Request     string            `json:"request,omitempty"`
	Response    string            `json:"response,omitempty"`
	CVE         string            `json:"cve,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	CWE         string            `json:"cwe,omitempty"`
	References  []string          `json:"references,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Timestamp   string            `json:"timestamp"`
}

type ScanStats struct {
	TotalScanned  int
	TotalFindings int
	Critical      int
	High          int
	Medium        int
	Low           int
	Info          int
}

func NewEngine(cfg *config.Config, log *logger.Logger) *Engine {
	return &Engine{
		cfg: cfg,
		log: log,
	}
}

func (e *Engine) Run(ctx context.Context, reconResults *recon.Results) (*Results, error) {
	results := &Results{
		Findings: make([]Finding, 0),
	}

	mu := &sync.Mutex{}

	// Show what tools will run
	totalTargets := len(reconResults.Subdomains)
	e.log.PhaseNote(fmt.Sprintf("Scanning %d subdomains with enabled tools...", totalTargets))

	// Per-tool timeout (default: scanning timeout from config)
	toolTimeout := time.Duration(e.cfg.Scanning.Timeout) * time.Second
	if toolTimeout == 0 {
		toolTimeout = 5 * time.Minute
	}

	// ════════════════════════════════════════════════
	// STAGE 1: Httpx live-host probe (runs FIRST)
	// ════════════════════════════════════════════════
	var liveHosts []string
	if e.cfg.Scanning.Tools.Httpx.Enabled {
		e.log.ToolStart("Httpx", fmt.Sprintf("probing %d targets for live hosts...", len(reconResults.Subdomains)))
		start := time.Now()

		httpxCtx, httpxCancel := context.WithTimeout(ctx, 7*time.Minute)
		var hosts []string
		var findings []Finding
		var err error

		// Retry httpx up to 2 times — it sometimes fails on first attempt
		for attempt := 1; attempt <= 2; attempt++ {
			findings, hosts, err = e.runHttpx(httpxCtx, reconResults.Subdomains)
			if err == nil && len(hosts) > 0 {
				break
			}
			if attempt < 2 {
				e.log.Warnf("Httpx attempt %d/2 returned no hosts — retrying in 3s", attempt)
				time.Sleep(3 * time.Second)
			}
		}
		httpxCancel()

		if err != nil {
			e.log.ToolFail("Httpx", err)
		} else {
			e.log.ToolDone("Httpx", len(hosts), time.Since(start))
			e.log.PhaseNote(fmt.Sprintf("Live hosts: %d / %d subdomains respond", len(hosts), totalTargets))
			liveHosts = hosts
			mu.Lock()
			results.Findings = append(results.Findings, findings...)
			mu.Unlock()
		}
	} else {
		e.log.ToolSkip("Httpx", "disabled in config")
	}

	// Fallback: if httpx returned no live hosts, use raw subdomains with https:// prefix
	if len(liveHosts) == 0 {
		for _, sub := range reconResults.Subdomains {
			if strings.HasPrefix(sub, "http://") || strings.HasPrefix(sub, "https://") {
				liveHosts = append(liveHosts, sub)
			} else {
				liveHosts = append(liveHosts, "https://"+sub)
			}
		}
		e.log.PhaseNote("No live hosts from httpx, falling back to raw subdomains")
	}

	// ════════════════════════════════════════════════
	// STAGE 2: Nuclei, Nmap, Dalfox (parallel, using live hosts)
	// ════════════════════════════════════════════════
	var wg sync.WaitGroup

	// Nuclei Scanning — uses full URLs from httpx (preserves ports like :8080, :8443)
	if e.cfg.Scanning.Tools.Nuclei.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Deduplicate live hosts (full URLs from httpx)
			nucleiTargets := deduplicateURLs(liveHosts)
			if len(nucleiTargets) > 100 {
				// Prioritize by hostname importance
				hostnames := validateSubdomains(nucleiTargets)
				hostnames = prioritizeTargets(hostnames)
				// Map back to full URLs
				prioritized := make([]string, 0, len(nucleiTargets))
				hostnameOrder := make(map[string]int)
				for i, h := range hostnames {
					hostnameOrder[strings.ToLower(h)] = i
				}
				type scored struct {
					url   string
					score int
				}
				var items []scored
				for _, u := range nucleiTargets {
					h := extractHostname(u)
					s, ok := hostnameOrder[strings.ToLower(h)]
					if !ok {
						s = 999
					}
					items = append(items, scored{u, s})
				}
				sort.SliceStable(items, func(i, j int) bool {
					return items[i].score < items[j].score
				})
				for _, item := range items {
					prioritized = append(prioritized, item.url)
				}
				nucleiTargets = prioritized[:100]
			}

			e.log.Debugf("Nuclei targets: %d full URLs", len(nucleiTargets))
			if len(nucleiTargets) > 0 {
				limit := 5
				if len(nucleiTargets) < limit {
					limit = len(nucleiTargets)
				}
				e.log.Debugf("Sample targets: %v", nucleiTargets[:limit])
			}

			e.log.ToolStart("Nuclei", fmt.Sprintf("scanning %d live targets with high-value templates...", len(nucleiTargets)))
			start := time.Now()

			nucleiCtx, nucleiCancel := context.WithTimeout(ctx, toolTimeout)
			defer nucleiCancel()

			// Retry nuclei up to 3 times — network/template issues are transient
			findings, err := runWithRetry(nucleiCtx, e.log, "Nuclei", 3, func(rctx context.Context) ([]Finding, error) {
				return e.runNucleiDirect(rctx, nucleiTargets)
			})
			if err != nil {
				e.log.ToolFail("Nuclei", err)
				return
			}

			e.log.ToolDone("Nuclei", len(findings), time.Since(start))
			if len(findings) > 0 {
				e.log.Debugf("Nuclei: found %d total findings (all severities included)", len(findings))
			}
			mu.Lock()
			results.Findings = append(results.Findings, findings...)
			mu.Unlock()
		}()
	} else {
		e.log.ToolSkip("Nuclei", "disabled in config")
	}

	// Nmap Port Scanning — uses live hosts
	if e.cfg.Scanning.Tools.Nmap.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			nmapCount := len(liveHosts)
			if nmapCount > 25 {
				nmapCount = 25
			}
			e.log.ToolStart("Nmap", fmt.Sprintf("port scanning %d live targets (ports: %s)...",
				nmapCount, e.cfg.Scanning.Tools.Nmap.Ports))
			start := time.Now()

			findings, err := e.runNmap(ctx, liveHosts)
			if err != nil {
				e.log.ToolFail("Nmap", err)
				return
			}

			e.log.ToolDone("Nmap", len(findings), time.Since(start))
			mu.Lock()
			results.Findings = append(results.Findings, findings...)
			mu.Unlock()
		}()
	} else {
		e.log.ToolSkip("Nmap", "disabled in config")
	}

	// SQL Injection — nuclei-based (fast, WAF-aware) + gf-style param filtering
	// Replaces blind sqlmap: nuclei sqli templates on live hosts + targeted param fuzzing
	if e.cfg.Scanning.Tools.SQLMap.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()

			sqliURLCount := len(filterSQLiProneURLs(reconResults.URLs))
			e.log.ToolStart("SQLi-Scan",
				fmt.Sprintf("nuclei sqli templates on %d hosts + %d gf-filtered param URLs...",
					len(liveHosts), sqliURLCount))
			start := time.Now()

			sqliCtx, sqliCancel := context.WithTimeout(ctx, 12*time.Minute)
			defer sqliCancel()

			findings, err := e.runSQLiScan(sqliCtx, liveHosts, reconResults.URLs)
			if err != nil {
				e.log.ToolFail("SQLi-Scan", err)
				return
			}

			e.log.ToolDone("SQLi-Scan", len(findings), time.Since(start))
			mu.Lock()
			results.Findings = append(results.Findings, findings...)
			mu.Unlock()
		}()
	}

	// ffuf Directory/File Bruteforce + Vhost — independent of Arjun, start early in parallel
	if e.cfg.Scanning.Tools.Ffuf.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()

			e.log.ToolStart("Ffuf", fmt.Sprintf("path bruteforce + vhost fuzzing on %d live targets...", len(liveHosts)))
			start := time.Now()

			ffufCtx, ffufCancel := context.WithTimeout(ctx, toolTimeout)
			defer ffufCancel()

			findings, err := e.runFfuf(ffufCtx, liveHosts)
			if err != nil {
				e.log.ToolFail("Ffuf", err)
				return
			}

			e.log.ToolDone("Ffuf", len(findings), time.Since(start))
			mu.Lock()
			results.Findings = append(results.Findings, findings...)
			mu.Unlock()
		}()
	} else {
		e.log.ToolSkip("Ffuf", "disabled in config")
	}

	// CORS Misconfiguration Check — independent of Arjun, start early in parallel
	if e.cfg.Scanning.Tools.CORS.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()

			e.log.ToolStart("CORS Check", fmt.Sprintf("testing %d live hosts for CORS misconfigurations...", len(liveHosts)))
			start := time.Now()

			corsCtx, corsCancel := context.WithTimeout(ctx, 3*time.Minute)
			defer corsCancel()

			findings, err := e.runCORSCheck(corsCtx, liveHosts)
			if err != nil {
				e.log.ToolFail("CORS Check", err)
				return
			}

			e.log.ToolDone("CORS Check", len(findings), time.Since(start))
			mu.Lock()
			results.Findings = append(results.Findings, findings...)
			mu.Unlock()
		}()
	} else {
		e.log.ToolSkip("CORS Check", "disabled in config")
	}

	// Arjun Hidden Parameter Discovery — runs sequentially so results feed into Dalfox below.
	// FFUF and CORS are already launched above and run in parallel while Arjun works.
	var arjunParamURLs []string
	{
		arjunCtx, arjunCancel := context.WithTimeout(ctx, 5*time.Minute)
		e.log.ToolStart("Arjun", fmt.Sprintf("discovering hidden parameters on %d live hosts...", len(liveHosts)))
		arjunStart := time.Now()
		aFindings, newURLs, arjunErr := e.runArjun(arjunCtx, liveHosts)
		arjunCancel()
		if arjunErr != nil {
			e.log.ToolFail("Arjun", arjunErr)
		} else if len(aFindings) > 0 || len(newURLs) > 0 {
			e.log.ToolDone("Arjun", len(aFindings), time.Since(arjunStart))
			e.log.Debugf("Arjun: +%d param URLs added to Dalfox queue", len(newURLs))
			mu.Lock()
			results.Findings = append(results.Findings, aFindings...)
			mu.Unlock()
			arjunParamURLs = newURLs
		} else {
			e.log.Debugf("Arjun: no hidden parameters found")
		}
	}

	// Dalfox XSS Parameter Fuzzing — uses Wayback URLs + Arjun-discovered params
	if e.cfg.Scanning.Tools.Dalfox.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Merge Wayback URLs + arjun-discovered parameter URLs, then deduplicate
			allParamURLs := extractParameterizedURLs(reconResults.URLs)
			allParamURLs = append(allParamURLs, arjunParamURLs...)
			allParamURLs = deduplicateURLs(allParamURLs)

			if len(allParamURLs) == 0 {
				e.log.ToolSkip("Dalfox", "no parameterized URLs found")
				return
			}

			maxURLs := e.cfg.Scanning.Tools.Dalfox.MaxURLs
			if maxURLs <= 0 {
				maxURLs = 100
			}
			if len(allParamURLs) > maxURLs {
				allParamURLs = allParamURLs[:maxURLs]
			}

			e.log.ToolStart("Dalfox", fmt.Sprintf("XSS fuzzing %d parameterized URLs...", len(allParamURLs)))
			start := time.Now()

			dalfoxCtx, dalfoxCancel := context.WithTimeout(ctx, 5*time.Minute)
			defer dalfoxCancel()

			findings, err := e.runDalfox(dalfoxCtx, allParamURLs)
			if err != nil {
				e.log.ToolFail("Dalfox", err)
				return
			}

			e.log.ToolDone("Dalfox", len(findings), time.Since(start))
			mu.Lock()
			results.Findings = append(results.Findings, findings...)
			mu.Unlock()
		}()
	} else {
		e.log.ToolSkip("Dalfox", "disabled in config")
	}

	wg.Wait()

	// Deduplicate findings across all tools.
	//
	// Two-pass strategy:
	//   Pass 1 — exact dedup: same title + same URL from the same tool (fast path).
	//   Pass 2 — cross-tool dedup: different tools that flagged the same URL for the
	//            same vulnerability class (e.g. nuclei "Codeigniter .env" AND ffuf
	//            "Environment File Exposed" both pointing at the same /.env URL).
	//            Keep whichever finding has the higher severity; ties keep the first.

	severityRank := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}

	// Pass 1: exact dedup (title + URL)
	exactSeen := make(map[string]bool)
	pass1 := make([]Finding, 0, len(results.Findings))
	for _, f := range results.Findings {
		key := strings.ToLower(f.Title + "|" + f.URL)
		if !exactSeen[key] {
			exactSeen[key] = true
			pass1 = append(pass1, f)
		}
	}

	// Pass 2: cross-tool dedup by URL — keep highest-severity finding per URL.
	// Findings from JS analysis are intentionally excluded from this pass because
	// a single JS file can legitimately contain multiple distinct issue types
	// (e.g. eval() AND a hardcoded API key are different findings on the same URL).
	urlBest := make(map[string]Finding) // key: normalised URL
	var jsFindings []Finding
	for _, f := range pass1 {
		if f.Type == "js-analysis" {
			jsFindings = append(jsFindings, f)
			continue
		}
		key := strings.ToLower(f.URL)
		existing, exists := urlBest[key]
		if !exists {
			urlBest[key] = f
			continue
		}
		// Replace if this finding has strictly higher severity
		if severityRank[strings.ToLower(f.Severity)] > severityRank[strings.ToLower(existing.Severity)] {
			urlBest[key] = f
		}
	}

	deduped := make([]Finding, 0, len(urlBest)+len(jsFindings))
	for _, f := range urlBest {
		deduped = append(deduped, f)
	}
	deduped = append(deduped, jsFindings...)
	results.Findings = deduped

	// Calculate statistics
	e.calculateStats(results)

	return results, nil
}

// runNucleiDirect runs Nuclei with full URLs directly (preserves ports from httpx)
func (e *Engine) runNucleiDirect(ctx context.Context, targets []string) ([]Finding, error) {
	if len(targets) == 0 {
		e.log.Debug("Nuclei: no targets")
		return nil, nil
	}

	// Write full URLs to temp file (already have protocol from httpx)
	tmpFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, target := range targets {
		// Ensure protocol prefix
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}
		fmt.Fprintln(tmpFile, target)
	}
	tmpFile.Close()

	// Reuse existing Nuclei command builder logic
	args := []string{
		"-l", tmpFile.Name(),
		"-jsonl",
		"-silent",
		"-stats",
		"-si", "30",
	}

	templatesBase := e.cfg.Scanning.Tools.Nuclei.TemplatesPath
	if templatesBase != "" {
		if _, err := os.Stat(templatesBase); err != nil {
			e.log.Warnf("Nuclei templates path not found: %s — using default templates", templatesBase)
			templatesBase = ""
		}
	}
	if templatesBase != "" {
		targetCount := len(targets)
		if targetCount > 50 {
			args = append(args, "-t", templatesBase+"/http/exposures/")
			args = append(args, "-t", templatesBase+"/http/takeovers/")
			args = append(args, "-t", templatesBase+"/http/default-logins/")
			args = append(args, "-t", templatesBase+"/http/cves/")
			args = append(args, "-t", templatesBase+"/http/vulnerabilities/")
		} else {
			args = append(args, "-t", templatesBase+"/http/exposures/")
			args = append(args, "-t", templatesBase+"/http/cves/")
			args = append(args, "-t", templatesBase+"/http/vulnerabilities/")
			args = append(args, "-t", templatesBase+"/http/misconfiguration/")
			args = append(args, "-t", templatesBase+"/http/takeovers/")
			args = append(args, "-t", templatesBase+"/http/default-logins/")
			args = append(args, "-t", templatesBase+"/http/exposed-panels/")
			args = append(args, "-t", templatesBase+"/ssl/")
			args = append(args, "-t", templatesBase+"/dns/")
		}
	}

	args = append(args, "-etags", "dos,fuzz,intrusive,iot")

	concurrency := e.cfg.Scanning.Threads
	if concurrency < 25 {
		concurrency = 25
	}
	if concurrency > 100 {
		concurrency = 100
	}
	args = append(args, "-c", fmt.Sprintf("%d", concurrency))
	args = append(args, "-rl", fmt.Sprintf("%d", e.cfg.Scanning.RateLimit))
	args = append(args, "-timeout", "10")
	args = append(args, "-retries", "2")
	args = append(args, "-bulk-size", "25")

	e.log.Debugf("Nuclei: scanning %d full URLs", len(targets))

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	output, err := cmd.Output()
	if err != nil {
		e.log.Debugf("Nuclei finished with error (might be normal): %v", err)
	}

	// Parse JSON output (same parsing as runNuclei)
	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var nucleiResult struct {
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

		if err := json.Unmarshal([]byte(line), &nucleiResult); err != nil {
			continue
		}

		severity := "info"
		title := nucleiResult.TemplateID
		description := ""
		var tags []string
		var references []string

		if info, ok := nucleiResult.Info["severity"].(string); ok {
			severity = strings.ToLower(info)
		}
		if name, ok := nucleiResult.Info["name"].(string); ok {
			title = name
		}
		if desc, ok := nucleiResult.Info["description"].(string); ok {
			description = desc
		}
		if tagsRaw, ok := nucleiResult.Info["tags"]; ok {
			switch v := tagsRaw.(type) {
			case []interface{}:
				for _, tag := range v {
					if tagStr, ok := tag.(string); ok {
						tags = append(tags, tagStr)
					}
				}
			case string:
				tags = strings.Split(v, ",")
			}
		}
		if refsRaw, ok := nucleiResult.Info["reference"]; ok {
			switch v := refsRaw.(type) {
			case []interface{}:
				for _, ref := range v {
					if refStr, ok := ref.(string); ok {
						references = append(references, refStr)
					}
				}
			case string:
				references = []string{v}
			}
		}

		cve := ""
		if classification, ok := nucleiResult.Info["classification"].(map[string]interface{}); ok {
			if cveID, ok := classification["cve-id"]; ok {
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
			ID:          nucleiResult.TemplateID,
			Title:       title,
			Description: description,
			Severity:    severity,
			Type:        nucleiResult.Type,
			Target:      nucleiResult.Host,
			URL:         nucleiResult.MatchedAt,
			Evidence:    strings.Join(nucleiResult.ExtractedResults, ", "),
			Request:     nucleiResult.Request,
			Response:    nucleiResult.Response,
			CVE:         cve,
			Tags:        tags,
			References:  references,
			Timestamp:   nucleiResult.Timestamp,
			Metadata: map[string]string{
				"matcher": nucleiResult.MatcherName,
				"curl":    nucleiResult.CURLCommand,
				"tool":    "nuclei",
			},
		})
	}

	e.log.Debugf("Nuclei parsed %d findings", len(findings))
	return findings, nil
}

// runWithRetry executes a tool function with exponential backoff retry.
// Handles transient failures (network blips, temporary timeouts) without
// requiring the entire scan to be restarted.
//
// Usage:
//
//	findings, err := runWithRetry(ctx, log, "nuclei", 3, func(ctx context.Context) ([]Finding, error) {
//	    return e.runNucleiDirect(ctx, targets)
//	})
func runWithRetry(
	ctx context.Context,
	log interface{ Warnf(string, ...interface{}) },
	toolName string,
	maxRetries int,
	fn func(context.Context) ([]Finding, error),
) ([]Finding, error) {
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		findings, err := fn(ctx)
		if err == nil {
			return findings, nil
		}

		lastErr = err

		if attempt < maxRetries {
			// Exponential backoff: 2s, 4s, 8s...
			wait := time.Duration(1<<uint(attempt)) * time.Second
			if wait > 30*time.Second {
				wait = 30 * time.Second
			}
			log.Warnf("%s attempt %d/%d failed (%v) — retrying in %s", toolName, attempt, maxRetries, err, wait)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
		}
	}

	return nil, fmt.Errorf("%s failed after %d attempts: %w", toolName, maxRetries, lastErr)
}

// deduplicateURLs deduplicates URLs (case-insensitive)
func deduplicateURLs(urls []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(urls))
	for _, u := range urls {
		lower := strings.ToLower(u)
		if !seen[lower] {
			seen[lower] = true
			result = append(result, u)
		}
	}
	return result
}

// extractHostname extracts hostname from a URL
func extractHostname(rawURL string) string {
	host := rawURL
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	if idx := strings.IndexAny(host, "/:?#"); idx != -1 {
		host = host[:idx]
	}
	return host
}

// resolveHttpxBinary finds the ProjectDiscovery httpx binary.
// The system may have a Python-based `httpx` CLI at /usr/local/bin/httpx that
// conflicts with ProjectDiscovery's httpx. We detect the correct one by
// preferring Go bin paths, then falling back to PATH resolution.
func resolveHttpxBinary() string {
	// Prefer Go bin locations where projectdiscovery tools are installed
	candidates := []string{
		os.Getenv("GOPATH") + "/bin/httpx",
		os.Getenv("HOME") + "/go/bin/httpx",
		"/root/go/bin/httpx",
		"/usr/local/go/bin/httpx",
	}
	for _, p := range candidates {
		if p == "/bin/httpx" || p == "//bin/httpx" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			// Verify it's the ProjectDiscovery version by checking for -l flag support
			out, _ := exec.Command(p, "-version").CombinedOutput()
			if strings.Contains(string(out), "projectdiscovery") {
				return p
			}
		}
	}
	// Fallback to PATH — might be wrong but let it fail naturally
	if p, err := exec.LookPath("httpx"); err == nil {
		return p
	}
	return "httpx"
}

func (e *Engine) runHttpx(ctx context.Context, targets []string) ([]Finding, []string, error) {

	var findings []Finding
	var liveHosts []string

	// Validate and filter targets
	targets = validateSubdomains(targets)
	if len(targets) == 0 {
		e.log.Debug("Httpx: no valid targets after filtering")
		return findings, liveHosts, nil
	}

	// Resolve the correct httpx binary (ProjectDiscovery, not Python httpx)
	httpxBin := resolveHttpxBinary()
	e.log.Debugf("Httpx binary: %s", httpxBin)
	e.log.Debugf("Httpx scanning %d targets", len(targets))

	// Write targets to temp file
	tmpFile, err := os.CreateTemp("", "httpx-targets-*.txt")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, target := range targets {
		fmt.Fprintln(tmpFile, target)
	}
	tmpFile.Close()

	args := []string{
		"-l", tmpFile.Name(),
		"-json",
		"-silent",
		"-td",
		"-sc",
		"-fr",
		"-t", fmt.Sprintf("%d", e.cfg.Scanning.Threads),
		"-rl", fmt.Sprintf("%d", e.cfg.Scanning.RateLimit),
	}

	cmd := exec.CommandContext(ctx, httpxBin, args...)

	// Capture stderr for debugging
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	output, err := cmd.Output()
	if err != nil {
		e.log.Debugf("Httpx finished with error: %v", err)
		if stderrBuf.Len() > 0 {
			e.log.Debugf("Httpx stderr: %s", stderrBuf.String())
		}
	}

	// Parse results
	seen := make(map[string]bool) // deduplicate live hosts
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var httpxResult struct {
			URL          string   `json:"url"`
			StatusCode   int      `json:"status-code"`
			Technologies []string `json:"tech"`
			Title        string   `json:"title"`
			Server       string   `json:"server"`
		}

		if err := json.Unmarshal([]byte(line), &httpxResult); err != nil {
			continue
		}

		// Collect live host URL (any HTTP response = live)
		if httpxResult.URL != "" && !seen[httpxResult.URL] {
			seen[httpxResult.URL] = true
			liveHosts = append(liveHosts, httpxResult.URL)
		}

		// Create findings for interesting status codes or technologies
		if httpxResult.StatusCode >= 500 {
			findings = append(findings, Finding{
				ID:          "httpx-server-error",
				Title:       "Server Error Detected",
				Description: fmt.Sprintf("Server returned %d status code", httpxResult.StatusCode),
				Severity:    "low",
				Type:        "misconfiguration",
				URL:         httpxResult.URL,
				Evidence:    fmt.Sprintf("Status Code: %d", httpxResult.StatusCode),
			})
		}

		if len(httpxResult.Technologies) > 0 {
			findings = append(findings, Finding{
				ID:          "httpx-tech-detection",
				Title:       "Web Technologies Detected",
				Description: "Technologies found on the target",
				Severity:    "info",
				Type:        "fingerprint",
				URL:         httpxResult.URL,
				Evidence:    strings.Join(httpxResult.Technologies, ", "),
				Tags:        httpxResult.Technologies,
			})
		}
	}

	return findings, liveHosts, nil
}

func (e *Engine) runNmap(ctx context.Context, targets []string) ([]Finding, error) {

	var findings []Finding

	// Validate and filter targets
	targets = validateSubdomains(targets)

	// Prioritize meaningful subdomains for Nmap (it's resource-intensive)
	targets = prioritizeTargets(targets)

	// Limit targets (increased from 10 since we now pass live hosts)
	if len(targets) > 25 {
		targets = targets[:25]
	}

	if len(targets) == 0 {
		e.log.Debug("Nmap: no valid targets after filtering")
		return findings, nil
	}

	e.log.Debugf("Nmap scanning %d targets", len(targets))

	for _, target := range targets {
		var args []string

		// Fix: -F and -p are mutually exclusive in nmap
		if e.cfg.Scanning.Tools.Nmap.Ports != "" {
			args = append(args, "-p", e.cfg.Scanning.Tools.Nmap.Ports)
		} else if e.cfg.Scanning.Tools.Nmap.FastScan {
			args = append(args, "-F")
		}

		args = append(args, "--open", "-T4", target)

		cmd := exec.CommandContext(ctx, "nmap", args...)
		var stderrBuf bytes.Buffer
		cmd.Stderr = &stderrBuf

		output, err := cmd.Output()
		if err != nil {
			errMsg := stderrBuf.String()
			if errMsg != "" {
				e.log.Debugf("Nmap scan failed for %s: %v (stderr: %s)", target, err, errMsg)
			} else {
				e.log.Debugf("Nmap scan failed for %s: %v", target, err)
			}
			continue
		}

		// Parse open ports
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "open") && !strings.Contains(line, "Nmap") {
				findings = append(findings, Finding{
					ID:          "nmap-open-port",
					Title:       "Open Port Detected",
					Description: "Port is open and accepting connections",
					Severity:    "info",
					Type:        "port-scan",
					Target:      target,
					Evidence:    line,
				})
			}
		}
	}

	return findings, nil
}

func (e *Engine) calculateStats(results *Results) {
	for _, finding := range results.Findings {
		results.Stats.TotalFindings++

		switch strings.ToLower(finding.Severity) {
		case "critical":
			results.Stats.Critical++
		case "high":
			results.Stats.High++
		case "medium":
			results.Stats.Medium++
		case "low":
			results.Stats.Low++
		default:
			results.Stats.Info++
		}
	}
}

// validDomainRegex matches valid domain name characters
var validDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

// validateSubdomains filters out invalid or garbage subdomain entries.
// It handles both bare domains (e.g. "www.example.com") and full URLs
// (e.g. "https://www.example.com/path") by extracting the hostname.
func validateSubdomains(targets []string) []string {
	var valid []string
	for _, t := range targets {
		t = strings.TrimSpace(t)

		// Strip protocol prefix if present (httpx returns full URLs)
		hostname := t
		if strings.HasPrefix(hostname, "https://") {
			hostname = strings.TrimPrefix(hostname, "https://")
		} else if strings.HasPrefix(hostname, "http://") {
			hostname = strings.TrimPrefix(hostname, "http://")
		}

		// Strip path, query, and port (keep only hostname)
		if idx := strings.IndexAny(hostname, "/:?#"); idx != -1 {
			hostname = hostname[:idx]
		}

		// Remove wildcard prefix
		hostname = strings.TrimPrefix(hostname, "*.")

		// Skip empty, dot-prefixed, or wildcard entries
		if hostname == "" || strings.HasPrefix(hostname, ".") || hostname == "*" {
			continue
		}

		// Must have at least one dot (be a FQDN)
		if !strings.Contains(hostname, ".") {
			continue
		}

		// Max DNS name length
		if len(hostname) > 253 {
			continue
		}

		// Must match valid domain pattern
		if !validDomainRegex.MatchString(hostname) {
			continue
		}

		// Verify it's a plausible hostname (no IP addresses for subdomain list)
		if net.ParseIP(hostname) != nil {
			continue
		}

		valid = append(valid, hostname)
	}

	// Deduplicate (after URL stripping, http:// and https:// variants collapse)
	seen := make(map[string]bool)
	deduped := make([]string, 0, len(valid))
	for _, v := range valid {
		lower := strings.ToLower(v)
		if !seen[lower] {
			seen[lower] = true
			deduped = append(deduped, v)
		}
	}
	return deduped
}

// prioritizeTargets sorts targets to put meaningful subdomains first
// (e.g., www, api, mail, staging) ahead of random CT log noise
func prioritizeTargets(targets []string) []string {
	// High-value prefixes that are more likely to be real, interesting hosts
	highValuePrefixes := []string{
		"www.", "api.", "mail.", "smtp.", "ftp.", "admin.",
		"staging.", "stage.", "dev.", "test.", "beta.",
		"portal.", "app.", "dashboard.", "panel.",
		"vpn.", "remote.", "owa.", "webmail.",
		"git.", "gitlab.", "jenkins.", "jira.", "confluence.",
	}

	sort.SliceStable(targets, func(i, j int) bool {
		iScore := subdomainScore(targets[i], highValuePrefixes)
		jScore := subdomainScore(targets[j], highValuePrefixes)
		return iScore > jScore
	})

	return targets
}

func subdomainScore(subdomain string, highValuePrefixes []string) int {
	score := 0
	lower := strings.ToLower(subdomain)

	// High-value prefix match
	for _, prefix := range highValuePrefixes {
		if strings.HasPrefix(lower, prefix) {
			score += 10
			break
		}
	}

	// Shorter subdomains tend to be more important
	parts := strings.Split(lower, ".")
	if len(parts) <= 3 {
		score += 5
	}

	// Penalize random-looking subdomains (long hex strings, stats subdomains)
	if strings.Contains(lower, ".stats.") {
		score -= 5
	}
	if len(parts) > 0 && len(parts[0]) > 20 {
		score -= 5 // Likely a random hash
	}

	return score
}

// ═══════════════════════════════════════════════════════════
// Dalfox XSS Parameter Fuzzing
// ═══════════════════════════════════════════════════════════

// extractParameterizedURLs filters URLs that have query parameters and deduplicates by pattern
func extractParameterizedURLs(urls []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, u := range urls {
		// Must have query parameters
		if !strings.Contains(u, "?") || !strings.Contains(u, "=") {
			continue
		}

		// Skip non-http URLs
		lower := strings.ToLower(u)
		if !strings.HasPrefix(lower, "http") {
			continue
		}

		// Skip static files (fonts, images, stylesheets, scripts, media)
		path := strings.Split(strings.Split(lower, "?")[0], "#")[0]
		staticExts := []string{
			// Images
			".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp", ".bmp", ".tiff",
			// Fonts
			".woff", ".woff2", ".ttf", ".eot", ".otf",
			// Styles & scripts (static assets, not dynamic endpoints)
			".css", ".js", ".map",
			// Media
			".mp4", ".mp3", ".avi", ".mov", ".webm", ".ogg", ".flac",
			// Documents
			".pdf", ".doc", ".docx", ".xls", ".xlsx",
			// Archives
			".zip", ".tar", ".gz", ".rar",
		}
		isStatic := false
		for _, ext := range staticExts {
			if strings.HasSuffix(path, ext) {
				isStatic = true
				break
			}
		}
		if isStatic {
			continue
		}

		// Skip static asset directories (version params like ?v=1.0 are cache busters, not injection points)
		staticDirs := []string{"/assets/", "/static/", "/dist/", "/vendor/", "/fonts/", "/img/", "/images/", "/media/", "/css/", "/js/"}
		isStaticDir := false
		for _, dir := range staticDirs {
			if strings.Contains(lower, dir) {
				isStaticDir = true
				break
			}
		}
		if isStaticDir {
			continue
		}

		// Skip URLs where the only parameter is a cache buster (v, ver, version, cb, t, _)
		queryPart := ""
		if idx := strings.Index(lower, "?"); idx != -1 {
			queryPart = lower[idx+1:]
		}
		cacheBusterOnly := true
		cacheBusterParams := map[string]bool{"v": true, "ver": true, "version": true, "cb": true, "t": true, "_": true, "ts": true, "cache": true}
		if queryPart != "" {
			pairs := strings.Split(queryPart, "&")
			for _, pair := range pairs {
				name := strings.SplitN(pair, "=", 2)[0]
				if !cacheBusterParams[name] {
					cacheBusterOnly = false
					break
				}
			}
		}
		if cacheBusterOnly {
			continue
		}

		// Deduplicate by base URL + sorted parameter names (not values)
		// e.g. https://example.com/search?q=foo&page=1 → example.com/search?page=&q=
		parts := strings.SplitN(u, "?", 2)
		basePath := parts[0]
		paramNames := []string{}
		if len(parts) > 1 {
			pairs := strings.Split(parts[1], "&")
			for _, pair := range pairs {
				name := strings.SplitN(pair, "=", 2)[0]
				if name != "" {
					paramNames = append(paramNames, name)
				}
			}
		}
		sort.Strings(paramNames)
		pattern := basePath + "?" + strings.Join(paramNames, "&")

		if !seen[pattern] {
			seen[pattern] = true
			result = append(result, u)
		}
	}

	return result
}

// runDalfox runs dalfox XSS scanner on parameterized URLs
func (e *Engine) runDalfox(ctx context.Context, urls []string) ([]Finding, error) {
	var findings []Finding

	if len(urls) == 0 {
		return findings, nil
	}

	// Check if dalfox is installed
	if _, err := exec.LookPath("dalfox"); err != nil {
		return nil, fmt.Errorf("dalfox not installed (run: go install github.com/hahwul/dalfox/v2@latest)")
	}

	// Write URLs to temp file
	tmpFile, err := os.CreateTemp("", "dalfox-urls-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	for _, u := range urls {
		fmt.Fprintln(tmpFile, u)
	}
	tmpFile.Close()

	e.log.Debugf("Dalfox scanning %d parameterized URLs", len(urls))

	// Build dalfox command
	args := []string{
		"file", tmpFile.Name(),
		"--silence",
		"--no-color",
		"--format", "json",
		"--timeout", "10",
		"--delay", "100",
		"--worker", "5",
		"--only-poc", "r",  // Only report reflected XSS PoC
	}

	// Add blind XSS callback if configured
	if e.cfg.Scanning.Tools.Dalfox.BlindURL != "" {
		args = append(args, "-b", e.cfg.Scanning.Tools.Dalfox.BlindURL)
	}

	cmd := exec.CommandContext(ctx, "dalfox", args...)

	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	output, err := cmd.Output()
	if err != nil {
		// Dalfox may return non-zero even with results
		e.log.Debugf("Dalfox finished with error (may be normal): %v", err)
		if stderrBuf.Len() > 0 {
			e.log.Debugf("Dalfox stderr: %s", stderrBuf.String())
		}
	}

	// Parse JSON output (one JSON object per line)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var dalfoxResult struct {
			Type          string `json:"type"`
			Severity      string `json:"severity"`
			PoCType       string `json:"poc_type"`
			PoCURL        string `json:"data"`
			Param         string `json:"param"`
			InjectType    string `json:"inject_type"`
			CWE           string `json:"cwe"`
			MessageStr    string `json:"message_str"`
		}

		if err := json.Unmarshal([]byte(line), &dalfoxResult); err != nil {
			e.log.Debugf("Dalfox: skipping non-JSON line: %s", line)
			continue
		}

		// Only care about actual vulnerability findings
		if dalfoxResult.Type != "v" && dalfoxResult.Type != "vuln" {
			continue
		}

		// Map severity
		severity := "medium"
		switch strings.ToLower(dalfoxResult.Severity) {
		case "high":
			severity = "high"
		case "critical":
			severity = "critical"
		case "low":
			severity = "low"
		}

		// Build finding
		title := "XSS"
		if dalfoxResult.InjectType != "" {
			title = fmt.Sprintf("XSS (%s)", dalfoxResult.InjectType)
		}
		if dalfoxResult.Param != "" {
			title = fmt.Sprintf("%s in param '%s'", title, dalfoxResult.Param)
		}

		finding := Finding{
			ID:          fmt.Sprintf("dalfox-xss-%s", dalfoxResult.Param),
			Title:       title,
			Description: fmt.Sprintf("Reflected XSS vulnerability found by parameter fuzzing. Parameter: %s", dalfoxResult.Param),
			Severity:    severity,
			Type:        "xss",
			URL:         dalfoxResult.PoCURL,
			Evidence:    dalfoxResult.PoCURL,
			CWE:         "CWE-79",
			Tags:        []string{"xss", "dalfox", "parameter-fuzzing"},
			Metadata: map[string]string{
				"inject_type": dalfoxResult.InjectType,
				"param":       dalfoxResult.Param,
				"poc_type":    dalfoxResult.PoCType,
				"tool":        "dalfox",
			},
			Timestamp: time.Now().Format(time.RFC3339),
		}

		findings = append(findings, finding)
	}

	return findings, nil
}
