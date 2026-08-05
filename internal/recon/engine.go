package recon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/jsselection"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	scopepolicy "github.com/Btr4k/bugbounty-agent/internal/scope"
)

type Engine struct {
	cfg                     *config.Config
	log                     *logger.Logger
	activeTargetURLValidate func(context.Context, string) error
}

type urlScope interface {
	AllowsURL(string) bool
}

type guardedURLScope interface {
	urlScope
	ValidateURL(context.Context, string) error
	SafeTransport(*http.Transport) *http.Transport
}

type pacedRoundTripper struct {
	base  http.RoundTripper
	ticks <-chan time.Time
}

func (p pacedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	select {
	case <-req.Context().Done():
		return nil, req.Context().Err()
	case <-p.ticks:
		return p.base.RoundTrip(req)
	}
}

// jsRequestPolicy keeps target scope and credential scope separate. Target
// scope decides where the downloader may go; credential scope is deliberately
// narrower and requires an explicitly allowed HTTPS origin.
type jsRequestPolicy struct {
	scope          urlScope
	authentication config.AuthenticationConfig
}

func newJSRequestPolicy(cfg *config.Config) jsRequestPolicy {
	return jsRequestPolicy{
		scope:          scopepolicy.New(cfg.Target),
		authentication: cfg.Authentication,
	}
}

// headersForURL returns credentials only for an in-scope, explicitly allowed
// HTTPS URL. AuthenticationConfig intentionally works at host granularity; the
// redirect policy below binds those credentials to this request's exact origin
// (scheme + host + effective port) for the lifetime of the redirect chain.
func (p jsRequestPolicy) headersForURL(raw string) map[string]string {
	parsed, origin, ok := secureOrigin(raw)
	if !ok || p.scope == nil || !p.scope.AllowsURL(parsed.String()) || !p.authentication.AllowsTarget(parsed.String()) {
		return nil
	}
	if origin == "" {
		return nil
	}
	return p.authentication.HeaderValuesForTargets(parsed.String())
}

func (p jsRequestPolicy) headersForURLs(targets ...string) map[string]string {
	if len(targets) == 0 {
		return nil
	}
	var headers map[string]string
	for _, target := range targets {
		candidate := p.headersForURL(target)
		if len(candidate) == 0 {
			return nil
		}
		if headers == nil {
			headers = candidate
		}
	}
	return headers
}

func secureOrigin(raw string) (*url.URL, string, bool) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Opaque != "" || parsed.User != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" {
		return nil, "", false
	}
	host := strings.Trim(strings.ToLower(parsed.Hostname()), ".")
	if host == "" {
		return nil, "", false
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return parsed, "https://" + net.JoinHostPort(host, port), true
}

func normalizeJSURL(raw string) (*url.URL, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" {
		return nil, false
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, false
	}
	return parsed, true
}

func (p jsRequestPolicy) stripAuthenticationHeaders(headers http.Header) {
	for name := range p.authentication.Headers {
		headers.Del(name)
	}
	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Cookie2",
	} {
		headers.Del(name)
	}
}

func (p jsRequestPolicy) checkRedirect(req *http.Request, via []*http.Request) error {
	if req == nil || req.URL == nil {
		return fmt.Errorf("invalid redirect request")
	}
	if len(via) == 0 {
		p.stripAuthenticationHeaders(req.Header)
		return fmt.Errorf("redirect has no originating request")
	}
	if len(via) >= 10 {
		p.stripAuthenticationHeaders(req.Header)
		return fmt.Errorf("stopped after 10 redirects")
	}

	// URL userinfo can cause net/http to synthesize a Basic Authorization header
	// after CheckRedirect. Never follow such a redirect.
	if req.URL.User != nil || p.scope == nil || !p.scope.AllowsURL(req.URL.String()) {
		p.stripAuthenticationHeaders(req.Header)
		return http.ErrUseLastResponse
	}
	// Internal downloads are HTTPS-only. This rejects plaintext redirects even
	// when the originating request was also plaintext.
	if !strings.EqualFold(req.URL.Scheme, "https") {
		p.stripAuthenticationHeaders(req.Header)
		return http.ErrUseLastResponse
	}

	if guarded, ok := p.scope.(guardedURLScope); ok {
		if err := guarded.ValidateURL(req.Context(), req.URL.String()); err != nil {
			p.stripAuthenticationHeaders(req.Header)
			return http.ErrUseLastResponse
		}
	}

	previous := via[len(via)-1].URL
	if previous == nil || !strings.EqualFold(previous.Scheme, "https") {
		p.stripAuthenticationHeaders(req.Header)
		return http.ErrUseLastResponse
	}

	_, initialOrigin, initialSecure := secureOrigin(via[0].URL.String())
	_, destinationOrigin, destinationSecure := secureOrigin(req.URL.String())
	if !initialSecure || !destinationSecure || initialOrigin != destinationOrigin || !p.authentication.AllowsTarget(req.URL.String()) {
		p.stripAuthenticationHeaders(req.Header)
	}
	return nil
}

func newJSHTTPClient(policy jsRequestPolicy, transport http.RoundTripper) *http.Client {
	if transport == nil {
		base := http.DefaultTransport.(*http.Transport).Clone()
		if guarded, ok := policy.scope.(guardedURLScope); ok {
			transport = guarded.SafeTransport(base)
		} else {
			transport = base
		}
	}
	return &http.Client{
		Timeout:       15 * time.Second,
		Transport:     transport,
		CheckRedirect: policy.checkRedirect,
	}
}

func reconRootDomain(raw string) string {
	return strings.TrimPrefix(strings.TrimSpace(raw), "*.")
}

func configuredReconRoots(domains []string) []string {
	seen := make(map[string]bool, len(domains))
	roots := make([]string, 0, len(domains))
	for _, raw := range domains {
		if root := strings.ToLower(reconRootDomain(raw)); root != "" && !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}
	sort.Strings(roots)
	return roots
}

// configuredSubdomainReconRoots returns only roots whose children were
// explicitly authorized. A wildcard on one root must never cause passive
// subdomain enumeration of a different exact-only root in a mixed policy.
func configuredSubdomainReconRoots(domains []string) []string {
	seen := make(map[string]bool, len(domains))
	roots := make([]string, 0, len(domains))
	for _, raw := range domains {
		raw = strings.TrimSpace(raw)
		if !strings.HasPrefix(raw, "*.") {
			continue
		}
		root := strings.ToLower(reconRootDomain(raw))
		if root != "" && !seen[root] {
			seen[root] = true
			roots = append(roots, root)
		}
	}
	sort.Strings(roots)
	return roots
}

func authorizesDiscoveredSubdomains(domains []string) bool {
	for _, raw := range domains {
		if strings.HasPrefix(strings.TrimSpace(raw), "*.") {
			return true
		}
	}
	return false
}

type Results struct {
	Subdomains   []string
	URLs         []string
	Endpoints    []string
	IPs          []string
	Technologies []Technology
	Secrets      []Secret
	JSFiles      []JSFile
	Complete     bool
	FailedTools  []string
}

type JSFile struct {
	URL       string `json:"url"`
	Content   string `json:"content"`
	Size      int    `json:"size"`
	Source    string `json:"source"` // "katana" or "wayback"
	Truncated bool   `json:"truncated,omitempty"`
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
	engine := &Engine{cfg: cfg, log: log}
	if cfg != nil {
		policy := scopepolicy.New(cfg.Target)
		engine.activeTargetURLValidate = policy.ValidateURL
	}
	return engine
}

func (e *Engine) reconConcurrency(maximum int) int {
	workers := e.cfg.Scanning.Threads
	if workers < 1 {
		workers = 1
	}
	rate := e.reconRateLimit()
	if workers > rate {
		workers = rate
	}
	if maximum > 0 && workers > maximum {
		workers = maximum
	}
	return workers
}

func (e *Engine) reconRateLimit() int {
	rate := e.cfg.Scanning.RateLimit
	if rate < 1 {
		return 1
	}
	return rate
}

func (e *Engine) Run(ctx context.Context) (*Results, error) {
	if e == nil || e.cfg == nil {
		return nil, errors.New("recon configuration is not available")
	}
	if e.log == nil {
		return nil, errors.New("recon logger is not available")
	}
	if len(e.cfg.Target.Domains) == 0 {
		return nil, errors.New("recon requires at least one authorized target")
	}
	policy := scopepolicy.New(e.cfg.Target)
	if policy.ValidationError() != nil {
		// Keep invalid raw target data out of diagnostics; configuration validation
		// provides the detailed user-facing error before the engine is constructed.
		return nil, errors.New("recon target scope is invalid")
	}

	results := &Results{
		Subdomains:   configuredReconRoots(e.cfg.Target.Domains),
		URLs:         make([]string, 0),
		Endpoints:    make([]string, 0),
		IPs:          make([]string, 0),
		Technologies: make([]Technology, 0),
		Secrets:      make([]Secret, 0),
		JSFiles:      make([]JSFile, 0),
		Complete:     true,
		FailedTools:  make([]string, 0),
	}

	// The configured recon timeout applies to passive sources only. Crawling and
	// JS downloads have their own limits and must not inherit an expired passive
	// recon context.
	passiveCtx, passiveCancel := context.WithTimeout(ctx, time.Duration(e.cfg.Recon.Timeout)*time.Second)
	defer passiveCancel()

	var wg sync.WaitGroup
	mu := &sync.Mutex{}
	var toolErrors []error
	recordToolError := func(tool string, err error) {
		mu.Lock()
		toolErrors = append(toolErrors, fmt.Errorf("%s: %w", tool, err))
		results.Complete = false
		results.FailedTools = append(results.FailedTools, tool)
		mu.Unlock()
	}

	e.log.PhaseNote(fmt.Sprintf("Target: %s (timeout: %ds)", e.cfg.Target.Domains[0], e.cfg.Recon.Timeout))
	discoverSubdomains := authorizesDiscoveredSubdomains(e.cfg.Target.Domains)

	// Subfinder
	if e.cfg.Recon.Tools.Subfinder && discoverSubdomains {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.log.ToolStart("Subfinder", "enumerating subdomains...")
			start := time.Now()
			subs, err := e.runSubfinder(passiveCtx)
			mu.Lock()
			results.Subdomains = append(results.Subdomains, subs...)
			mu.Unlock()
			if err != nil {
				e.log.ToolFail("Subfinder", err)
				recordToolError("subfinder", err)
				return
			}
			e.log.ToolDone("Subfinder", len(subs), time.Since(start))
		}()
	} else if !discoverSubdomains {
		e.log.ToolSkip("Subfinder", "exact-host scope does not authorize discovered subdomains")
	} else {
		e.log.ToolSkip("Subfinder", "disabled in config")
	}

	// Assetfinder
	if e.cfg.Recon.Tools.Assetfinder && discoverSubdomains {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.log.ToolStart("Assetfinder", "discovering assets...")
			start := time.Now()
			subs, err := e.runAssetfinder(passiveCtx)
			mu.Lock()
			results.Subdomains = append(results.Subdomains, subs...)
			mu.Unlock()
			if err != nil {
				e.log.ToolFail("Assetfinder", err)
				recordToolError("assetfinder", err)
				return
			}
			e.log.ToolDone("Assetfinder", len(subs), time.Since(start))
		}()
	} else if !discoverSubdomains {
		e.log.ToolSkip("Assetfinder", "exact-host scope does not authorize discovered subdomains")
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
			urls, err := e.runWaybackURLs(passiveCtx)
			mu.Lock()
			results.URLs = append(results.URLs, urls...)
			mu.Unlock()
			if err != nil {
				e.log.ToolFail("WaybackURLs", err)
				recordToolError("waybackurls", err)
				return
			}
			e.log.ToolDone("WaybackURLs", len(urls), time.Since(start))
			if len(urls) == 0 {
				e.log.Warnf("WaybackURLs returned no historical URLs; Katana crawl URLs will be used as the active-scan fallback")
			}
		}()
	} else {
		e.log.ToolSkip("WaybackURLs", "disabled in config")
	}

	// C99 API Intelligence
	if discoverSubdomains && e.cfg.C99.Enabled && e.cfg.C99.APIKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.log.ToolStart("C99 API", "querying subdomain intelligence...")
			start := time.Now()
			subs, err := e.runC99Subdomains(passiveCtx)
			if err != nil {
				e.log.ToolFail("C99 API", err)
				recordToolError("c99", err)
				return
			}
			e.log.ToolDone("C99 API", len(subs), time.Since(start))
			mu.Lock()
			results.Subdomains = append(results.Subdomains, subs...)
			mu.Unlock()
		}()
	} else if !discoverSubdomains {
		e.log.ToolSkip("C99 API", "exact-host scope does not authorize discovered subdomains")
	} else {
		e.log.ToolSkip("C99 API", "disabled or no API key")
	}

	// Certificate Transparency
	if e.cfg.Recon.Tools.CertTransparency && discoverSubdomains {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.log.ToolStart("CertTransparency", "querying CT logs...")
			start := time.Now()
			subs, err := e.runCertTransparency(ctx, passiveCtx)
			if err != nil {
				e.log.ToolFail("CertTransparency", err)
				recordToolError("certificate-transparency", err)
				return
			}
			e.log.ToolDone("CertTransparency", len(subs), time.Since(start))
			mu.Lock()
			results.Subdomains = append(results.Subdomains, subs...)
			mu.Unlock()
		}()
	} else if !discoverSubdomains {
		e.log.ToolSkip("CertTransparency", "exact-host scope does not authorize discovered subdomains")
	} else {
		e.log.ToolSkip("CertTransparency", "disabled in config")
	}

	// Wait for all goroutines
	wg.Wait()
	passiveCancel()

	// Deduplicate
	results.Subdomains = e.deduplicate(results.Subdomains)
	results.URLs = e.deduplicate(results.URLs)

	// Sanitize subdomains: strip wildcards, remove invalid entries
	results.Subdomains = e.sanitizeSubdomains(results.Subdomains)
	results.Subdomains = policy.FilterHosts(results.Subdomains)
	results.URLs = policy.FilterURLs(results.URLs)
	sort.Slice(results.Subdomains, func(i, j int) bool {
		return strings.ToLower(results.Subdomains[i]) < strings.ToLower(results.Subdomains[j])
	})
	sort.Slice(results.URLs, func(i, j int) bool {
		return strings.ToLower(results.URLs[i]) < strings.ToLower(results.URLs[j])
	})

	// Apply limits (guard against MaxSubdomains=0 to avoid wiping results)
	if e.cfg.Recon.MaxSubdomains > 0 && len(results.Subdomains) > e.cfg.Recon.MaxSubdomains {
		omitted := len(results.Subdomains) - e.cfg.Recon.MaxSubdomains
		results.Subdomains = results.Subdomains[:e.cfg.Recon.MaxSubdomains]
		recordToolError("subdomain-cap", fmt.Errorf("%d authorized subdomain(s) omitted by max_subdomains", omitted))
	}

	// ═══════════════════════════════════════
	// JS File Extraction (after subdomains are ready)
	// ═══════════════════════════════════════
	var jsURLs []string

	// Katana JS crawling
	if e.cfg.Recon.Tools.Katana {
		e.log.ToolStart("Katana", "crawling for JS files...")
		start := time.Now()
		kURLs, kJSURLs, err := e.runKatana(ctx, results.Subdomains)
		results.URLs = append(results.URLs, kURLs...)
		jsURLs = append(jsURLs, kJSURLs...)
		if err != nil {
			e.log.ToolFail("Katana", err)
			recordToolError("katana", err)
		} else {
			e.log.ToolDone("Katana", len(kURLs), time.Since(start))
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

	// Katana supplements historical sources with current crawl URLs. This keeps
	// parameter-based scanners useful when archive providers return no data.
	results.URLs = e.deduplicate(results.URLs)
	results.URLs = policy.FilterURLs(results.URLs)
	sort.Slice(results.URLs, func(i, j int) bool {
		left, right := strings.ToLower(results.URLs[i]), strings.ToLower(results.URLs[j])
		if left != right {
			return left < right
		}
		return results.URLs[i] < results.URLs[j]
	})

	// Deduplicate JS URLs
	jsURLs = e.deduplicate(jsURLs)
	jsURLs = policy.FilterURLs(jsURLs)
	sort.Slice(jsURLs, func(i, j int) bool { return jsselection.Less(jsURLs[i], jsURLs[j]) })

	// Download JS content
	if len(jsURLs) > 0 {
		e.log.ToolStart("JS Download", fmt.Sprintf("fetching %d JS files...", len(jsURLs)))
		start := time.Now()
		var attempted, incomplete, omitted int
		results.JSFiles, attempted, incomplete, omitted = e.downloadJSFiles(ctx, jsURLs)
		e.log.ToolDone("JS Download", len(results.JSFiles), time.Since(start))
		if incomplete > 0 || omitted > 0 {
			recordToolError("js-download", fmt.Errorf("%d/%d download(s) failed or were truncated and %d URL(s) were omitted by the cap", incomplete, attempted, omitted))
		}

		// Mine endpoints/parameters out of the downloaded JS. This is what turns a
		// subdomain-only surface into one with real, observed endpoints — enabling
		// dalfox and letting the hunter ground its leads instead of guessing.
		if mined := mineJSEndpoints(results.JSFiles); len(mined) > 0 {
			before := len(results.URLs)
			results.URLs = append(results.URLs, mined...)
			results.URLs = e.deduplicate(results.URLs)
			results.URLs = policy.FilterURLs(results.URLs)
			if added := len(results.URLs) - before; added > 0 {
				e.log.PhaseNote(fmt.Sprintf("Mined %d in-scope endpoint(s) from JS", added))
			}
		}
	}
	results.URLs = e.deduplicate(policy.FilterURLs(results.URLs))
	sort.Slice(results.URLs, func(i, j int) bool {
		left, right := strings.ToLower(results.URLs[i]), strings.ToLower(results.URLs[j])
		if left != right {
			return left < right
		}
		return results.URLs[i] < results.URLs[j]
	})
	results.Endpoints = append([]string(nil), results.URLs...)

	if len(toolErrors) > 0 {
		e.log.Warnf("Reconnaissance completed partially: %d enabled source(s) failed", len(toolErrors))
	}
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

func (e *Engine) runSubfinder(ctx context.Context) ([]string, error) {
	e.log.Debug("Running subfinder...")
	return e.runPassiveHostTool(ctx, "subfinder", func(domain string) *exec.Cmd {
		return exec.CommandContext(ctx, "subfinder",
			"-d", domain,
			"-silent",
			"-all",
		)
	})
}

func (e *Engine) runAssetfinder(ctx context.Context) ([]string, error) {
	e.log.Debug("Running assetfinder...")
	return e.runPassiveHostTool(ctx, "assetfinder", func(domain string) *exec.Cmd {
		return exec.CommandContext(ctx, "assetfinder",
			"--subs-only",
			domain,
		)
	})
}

// runPassiveHostTool applies a static scope policy only. It intentionally does
// not resolve discovered names: passive enumeration must not become active
// target traffic. Valid records produced before truncation or process failure
// are returned alongside the coverage error.
func (e *Engine) runPassiveHostTool(
	ctx context.Context,
	tool string,
	command func(string) *exec.Cmd,
) ([]string, error) {
	policy := scopepolicy.New(e.cfg.Target)
	var results []string
	var coverageErrors []error
	malformed := 0

	for _, domain := range configuredSubdomainReconRoots(e.cfg.Target.Domains) {
		cmd := command(domain)
		cmd.Env = config.ExternalToolEnvironment()
		_, commandErr := executeBoundedLines(
			ctx,
			tool,
			cmd,
			maxPassiveCommandOutputBytes,
			maxCommandOutputLineBytes,
			func(line string) {
				host, ok := normalizePassiveHostname(line)
				if !ok {
					if strings.TrimSpace(line) != "" {
						malformed++
					}
					return
				}
				if policy.AllowsHost(host) {
					results = append(results, host)
				}
			},
		)
		if commandErr != nil {
			coverageErrors = append(coverageErrors, commandErr)
		}
		if ctx.Err() != nil {
			break
		}
	}
	if malformed > 0 {
		coverageErrors = append(coverageErrors, fmt.Errorf("%s discarded %d malformed output record(s)", tool, malformed))
	}
	return results, joinDiagnosticErrors(coverageErrors...)
}

func normalizePassiveHostname(raw string) (string, bool) {
	raw = strings.TrimSuffix(raw, "\r")
	for _, character := range raw {
		if character < 0x20 || character == 0x7f {
			return "", false
		}
	}
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimPrefix(host, "*.")
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 || strings.ContainsAny(host, "/\\:@?#[]*") {
		return "", false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", false
			}
		}
	}
	return host, true
}

func (e *Engine) runWaybackURLs(ctx context.Context) ([]string, error) {
	return e.runWaybackURLsBounded(ctx, maxWaybackCommandOutputBytes, maxWaybackOutputLineBytes)
}

func (e *Engine) runWaybackURLsBounded(ctx context.Context, maxOutputBytes int64, maxLineBytes int) ([]string, error) {
	e.log.Debug("Running waybackurls...")

	// Keep both a record cap and one aggregate byte budget. A record-only limit is
	// insufficient because a malicious archive/tool can emit hundreds of
	// kilobytes per URL and exhaust memory long before max_wayback_urls is reached.
	maxURLs := e.cfg.Recon.MaxWaybackURLs
	if maxURLs <= 0 {
		maxURLs = 10000
	}
	if maxOutputBytes < 1 || maxLineBytes < 1 {
		return nil, errors.New("waybackurls output limits are invalid")
	}

	var results []string
	remainingBytes := maxOutputBytes
	var coverageErrors []error
	for _, domain := range configuredReconRoots(e.cfg.Target.Domains) {
		if remainingBytes <= 0 {
			coverageErrors = append(coverageErrors, fmt.Errorf("waybackurls aggregate output exceeded the %d-byte limit", maxOutputBytes))
			break
		}

		commandCtx, cancel := context.WithCancel(ctx)
		cmd := exec.CommandContext(commandCtx, "waybackurls", domain)
		cmd.Env = config.ExternalToolEnvironment()
		recordCapReached := false
		stats, commandErr := executeBoundedLines(
			commandCtx,
			"waybackurls",
			cmd,
			remainingBytes,
			maxLineBytes,
			func(line string) {
				candidate := strings.TrimSpace(line)
				if candidate == "" {
					return
				}
				if len(results) >= maxURLs {
					recordCapReached = true
					cancel()
					return
				}
				results = append(results, candidate)
			},
		)
		cancel()
		remainingBytes -= stats.Bytes

		if recordCapReached {
			e.log.Infof("WaybackURLs: reached %d URL limit, stopping", maxURLs)
			coverageErrors = append(coverageErrors, fmt.Errorf("waybackurls coverage capped at %d URLs", maxURLs))
			break
		}
		if commandErr != nil {
			coverageErrors = append(coverageErrors, commandErr)
			break
		}
	}

	return results, joinDiagnosticErrors(coverageErrors...)
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
	for _, domain := range configuredSubdomainReconRoots(e.cfg.Target.Domains) {
		apiURL := fmt.Sprintf("https://api.c99.nl/subdomainfinder?key=%s&domain=%s&json",
			url.QueryEscape(e.cfg.C99.APIKey), url.QueryEscape(domain))

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, errors.New("C99 request creation failed")
		}

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, safeHTTPFailure(ctx, "C99 API request", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("C99 API returned status %d", resp.StatusCode)
		}

		body, err := readBoundedResponseBody(resp.Body, 8<<20, "C99 API")
		if err != nil {
			return results, err
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

// runCertTransparency queries Certificate Transparency logs with retry.
// crt.sh runs under passiveCtx (the shared passive-recon budget); the certspotter
// fallback runs under a fresh budget derived from rootCtx so an exhausted passive
// window can never starve it.
func (e *Engine) runCertTransparency(rootCtx, passiveCtx context.Context) ([]string, error) {
	e.log.Debug("Querying Certificate Transparency logs...")

	var results []string
	var requestErrors []error
	ipv4Transport := http.DefaultTransport.(*http.Transport).Clone()
	ipv4Transport.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp4", address)
	}
	client := &http.Client{
		Timeout:   30 * time.Second,
		Transport: ipv4Transport,
	}
	for _, domain := range configuredSubdomainReconRoots(e.cfg.Target.Domains) {
		crtURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

		// Retry logic: up to 3 attempts with backoff
		var body []byte
		var lastErr error

		for attempt := 0; attempt < 3; attempt++ {
			if attempt > 0 {
				backoff := time.Duration(attempt*5) * time.Second
				e.log.Debugf("crt.sh: retry %d after %s", attempt+1, backoff)
				select {
				case <-time.After(backoff):
				case <-passiveCtx.Done():
					// Passive budget spent — stop retrying crt.sh and let the
					// certspotter fallback below get its own fresh budget.
					lastErr = passiveCtx.Err()
				}
				if lastErr != nil {
					break
				}
			}

			req, err := http.NewRequestWithContext(passiveCtx, "GET", crtURL, nil)
			if err != nil {
				lastErr = errors.New("crt.sh request creation failed")
				continue
			}

			resp, err := client.Do(req)
			if err != nil {
				lastErr = safeHTTPFailure(passiveCtx, "crt.sh request", err)
				e.log.Warnf("crt.sh attempt %d failed: %v", attempt+1, lastErr)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				lastErr = fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
				continue
			}

			body, err = readBoundedResponseBody(resp.Body, 32<<20, "crt.sh")
			resp.Body.Close()
			if err != nil {
				lastErr = err
				continue
			}

			lastErr = nil
			break // Success
		}

		if lastErr != nil {
			// crt.sh is frequently unreachable (e.g. IPv4-less DNS, i/o timeouts).
			// Fall back to certspotter's free CT API so we still get CT data. Use a
			// fresh budget off rootCtx so a spent passive window doesn't starve it.
			e.log.Warnf("crt.sh all attempts failed for %s: %v — trying certspotter fallback", domain, lastErr)
			csCtx, csCancel := context.WithTimeout(rootCtx, 30*time.Second)
			csNames, csErr := e.queryCertSpotter(csCtx, domain)
			csCancel()
			if csErr != nil {
				e.log.Warnf("certspotter fallback failed for %s: %v", domain, csErr)
				requestErrors = append(requestErrors, fmt.Errorf("%s: crt.sh: %w; certspotter: %v", domain, lastErr, csErr))
				continue
			}
			e.log.Infof("certspotter fallback found %d names for %s", len(csNames), domain)
			results = append(results, csNames...)
			continue
		}
		var crtEntries []struct {
			NameValue string `json:"name_value"`
		}

		if err := json.Unmarshal(body, &crtEntries); err != nil {
			requestErrors = append(requestErrors, fmt.Errorf("%s: crt.sh returned malformed JSON", domain))
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
	if len(requestErrors) > 0 {
		return results, joinDiagnosticErrors(requestErrors...)
	}
	return results, nil
}

// queryCertSpotter is the fallback Certificate Transparency source used when
// crt.sh is unreachable. certspotter's free API needs no key and returns the
// DNS names observed in CT logs for the domain and its subdomains.
func (e *Engine) queryCertSpotter(ctx context.Context, domain string) ([]string, error) {
	csURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", csURL, nil)
	if err != nil {
		return nil, errors.New("certspotter request creation failed")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, safeHTTPFailure(ctx, "certspotter request", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certspotter returned status %d", resp.StatusCode)
	}

	body, err := readBoundedResponseBody(resp.Body, 32<<20, "certspotter")
	if err != nil {
		return nil, err
	}
	return parseCertSpotterNames(body)
}

// parseCertSpotterNames extracts and normalizes DNS names from a certspotter
// issuances response body. Kept pure (no I/O) so it is unit-testable.
func parseCertSpotterNames(body []byte) ([]string, error) {
	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("certspotter parse error: %w", err)
	}

	var names []string
	for _, entry := range entries {
		for _, name := range entry.DNSNames {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			if name != "" {
				names = append(names, name)
			}
		}
	}
	return names, nil
}

// ═══════════════════════════════════════════════════════════
// JS File Extraction Functions
// ═══════════════════════════════════════════════════════════

// prioritizeKatanaTargets orders subdomains so the most likely application
// hosts (api, app, portal, www, and short names) are crawled first when the
// target list is capped. Sorting is stable, so equal-scored hosts keep order.
func prioritizeKatanaTargets(subdomains []string) []string {
	highValue := []string{"www.", "api.", "app.", "portal.", "admin.", "dashboard.", "account.", "my.", "secure.", "auth."}
	out := append([]string(nil), subdomains...)
	sort.SliceStable(out, func(i, j int) bool {
		left, right := katanaScore(out[i], highValue), katanaScore(out[j], highValue)
		if left != right {
			return left > right
		}
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

func katanaScore(host string, highValue []string) int {
	lower := strings.ToLower(host)
	if parsed, err := url.Parse(lower); err == nil && parsed.Hostname() != "" {
		lower = parsed.Hostname()
	}
	score := 0
	for _, p := range highValue {
		if strings.HasPrefix(lower, p) {
			score += 10
			break
		}
	}
	if parts := strings.Split(lower, "."); len(parts) <= 3 {
		score += 3
	}
	return score
}

// runKatana crawls subdomains and returns all discovered URLs plus the JS subset.
func (e *Engine) runKatana(ctx context.Context, subdomains []string) ([]string, []string, error) {
	if !isToolInstalled("katana") {
		return nil, nil, fmt.Errorf("katana not installed (run ./install.sh)")
	}

	var crawlURLs []string
	var jsURLs []string
	var coverageErrors []error
	policy := scopepolicy.New(e.cfg.Target)

	// Limit subdomains for katana (it crawls each one). Katana is the single
	// most expensive recon step, so it is capped tightly — its only job here is
	// to surface JS files and endpoints, which a shallow crawl already covers.
	targets := make([]string, 0, len(subdomains))
	seenTargets := make(map[string]bool, len(subdomains))
	malformedTargets := 0
	outOfScopeTargets := 0
	for _, rawTarget := range subdomains {
		target, ok := normalizeKatanaTarget(rawTarget)
		if !ok {
			malformedTargets++
			continue
		}
		if !policy.AllowsURL(target) {
			outOfScopeTargets++
			continue
		}
		key := strings.ToLower(target)
		if !seenTargets[key] {
			seenTargets[key] = true
			targets = append(targets, target)
		}
	}
	if malformedTargets > 0 {
		coverageErrors = append(coverageErrors, fmt.Errorf("katana omitted %d malformed target(s)", malformedTargets))
	}
	if outOfScopeTargets > 0 {
		coverageErrors = append(coverageErrors, fmt.Errorf("katana omitted %d unauthorized target(s)", outOfScopeTargets))
	}

	omittedTargets := 0
	if len(targets) > 20 {
		omittedTargets = len(targets) - 20
		targets = prioritizeKatanaTargets(targets)[:20]
	}
	if omittedTargets > 0 {
		coverageErrors = append(coverageErrors, fmt.Errorf("katana target cap omitted %d authorized host(s)", omittedTargets))
	}

	// Perform a fresh public-address check as close as possible to process start.
	// Katana is an external process and resolves each hostname independently, so
	// this gate reduces SSRF exposure but cannot eliminate a DNS-rebinding race.
	validator := e.activeTargetURLValidate
	if validator == nil {
		validator = policy.ValidateURL
	}
	validatedTargets := make([]string, 0, len(targets))
	unsafeTargets := 0
	for _, target := range targets {
		if err := validator(ctx, target); err != nil {
			unsafeTargets++
			continue
		}
		validatedTargets = append(validatedTargets, target)
	}
	if unsafeTargets > 0 {
		// Do not include the validator error or raw target: either may contain a
		// query value, secret, or control characters supplied by an integration.
		coverageErrors = append(coverageErrors, fmt.Errorf("katana public-address validation rejected %d target(s)", unsafeTargets))
	}
	if len(validatedTargets) == 0 {
		coverageErrors = append(coverageErrors, errors.New("katana has no validated public target to crawl"))
		return nil, nil, joinDiagnosticErrors(coverageErrors...)
	}
	targets = validatedTargets

	// Write targets to temp file
	tmpFile, err := os.CreateTemp("", "katana-targets-*.txt")
	if err != nil {
		coverageErrors = append(coverageErrors, errors.New("katana target file creation failed"))
		return nil, nil, joinDiagnosticErrors(coverageErrors...)
	}
	defer os.Remove(tmpFile.Name())

	for _, target := range targets {
		if _, err := fmt.Fprintln(tmpFile, target); err != nil {
			_ = tmpFile.Close()
			coverageErrors = append(coverageErrors, errors.New("katana target file write failed"))
			return nil, nil, joinDiagnosticErrors(coverageErrors...)
		}
	}
	if err := tmpFile.Close(); err != nil {
		coverageErrors = append(coverageErrors, errors.New("katana target file close failed"))
		return nil, nil, joinDiagnosticErrors(coverageErrors...)
	}

	// Adaptive timeout: scale based on number of targets, cap at 4 minutes.
	// A depth-1 crawl over 20 hosts surfaces JS/endpoints quickly; the old
	// depth-2 / 10-minute crawl dominated total runtime (9m+) for little extra.
	katanaTimeout := 90*time.Second + time.Duration(len(targets))*8*time.Second
	if katanaTimeout > 4*time.Minute {
		katanaTimeout = 4 * time.Minute
	}
	e.log.Debugf("Katana: %d targets, timeout: %s", len(targets), katanaTimeout)
	katanaCtx, cancel := context.WithTimeout(ctx, katanaTimeout)
	defer cancel()

	workers := e.reconConcurrency(10)
	args := []string{
		"-list", tmpFile.Name(),
		"-jsluice", // extract JS file URLs and inline JS endpoints (v1.1+)
		"-silent",
		"-d", "1", // shallow crawl depth — enough to surface JS files and endpoints
		"-c", fmt.Sprintf("%d", workers),
		"-p", "1", // one input at a time; -rl is the global request ceiling
		"-rl", fmt.Sprintf("%d", e.reconRateLimit()),
		"-timeout", "8",
		"-fs", "fqdn", // never crawl links on a different host
		"-dr", // do not let an external redirect move the crawler across an authorization boundary
		// No -em filter: Go-side filter handles .js suffix check,
		// preserving URLs with query strings like app.js?v=123
	}

	// Katana cannot enforce HawkEye's dial-time public-address validation and its
	// header flag exposes values in the process argument list. Never give the
	// external crawler credentials; the guarded internal HTTPS downloader below
	// is the only authenticated recon client.
	if e.log != nil && e.cfg.Authentication.Configured() {
		e.log.Debugf("Authentication intentionally disabled for external Katana; guarded internal HTTPS downloads remain available")
	}

	cmd := exec.CommandContext(katanaCtx, "katana", args...)
	cmd.Env = config.ExternalToolEnvironment()
	malformedRecords := 0
	_, commandErr := executeBoundedLines(
		katanaCtx,
		"katana",
		cmd,
		maxKatanaCommandOutputBytes,
		maxCommandOutputLineBytes,
		func(line string) {
			discoveredURL, ok := normalizeKatanaDiscoveredURL(line)
			if !ok {
				if strings.TrimSpace(line) != "" {
					malformedRecords++
				}
				return
			}
			// Static authorization only: Katana already performed the request. Never
			// resolve its output merely to decide whether to retain the record.
			if !policy.AllowsURL(discoveredURL) {
				return
			}
			crawlURLs = append(crawlURLs, discoveredURL)
			if strings.HasSuffix(strings.ToLower(strings.Split(discoveredURL, "?")[0]), ".js") && !isNoiseJS(discoveredURL) {
				jsURLs = append(jsURLs, discoveredURL)
			}
		},
	)
	if commandErr != nil {
		coverageErrors = append(coverageErrors, commandErr)
	}
	if malformedRecords > 0 {
		coverageErrors = append(coverageErrors, fmt.Errorf("katana discarded %d malformed output record(s)", malformedRecords))
	}

	return crawlURLs, jsURLs, joinDiagnosticErrors(coverageErrors...)
}

func normalizeKatanaTarget(raw string) (string, bool) {
	if containsControl(raw) {
		return "", false
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	authority := host
	if port := parsed.Port(); port != "" {
		authority = net.JoinHostPort(host, port)
	}
	// Crawl an origin only. Paths, fragments, and especially query values are
	// never copied into the target file or diagnostic context.
	return strings.ToLower(parsed.Scheme) + "://" + authority, true
}

func normalizeKatanaDiscoveredURL(raw string) (string, bool) {
	if containsControl(raw) {
		return "", false
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", false
	}
	return raw, true
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
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
		"/cdn-cgi/",            // Cloudflare challenge & analytics scripts
		"/challenge-platform/", // Cloudflare bot-management JS
		"challenges.cloudflare.com",
		"googletagmanager.com",
		"google-analytics.com",
		"/gtag/js",
		"facebook.net/",
		"connect.facebook.net/",
	}
	for _, pattern := range noisePatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// downloadJSFiles downloads JS file content for AI analysis
func (e *Engine) downloadJSFiles(ctx context.Context, jsURLs []string) ([]JSFile, int, int, int) {
	// Prioritize application bundles, then use a lexical tie-break so network
	// completion timing never changes which files enter the AI budget.
	jsURLs = append([]string(nil), jsURLs...)
	sort.Slice(jsURLs, func(i, j int) bool {
		return jsselection.Less(jsURLs[i], jsURLs[j])
	})
	omitted := 0
	if len(jsURLs) > jsselection.MaxFiles {
		omitted = len(jsURLs) - jsselection.MaxFiles
		jsURLs = jsURLs[:jsselection.MaxFiles]
	}

	// Bound memory while retaining enough of modern application bundles for the
	// local regex pass. Reading one extra byte lets coverage detect truncation.
	const maxContentSize = 1 << 20

	interval := time.Second / time.Duration(e.reconRateLimit())
	if interval <= 0 {
		interval = time.Nanosecond
	}
	pacer := time.NewTicker(interval)
	defer pacer.Stop()
	policy := newJSRequestPolicy(e.cfg)
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	if guarded, ok := policy.scope.(guardedURLScope); ok {
		baseTransport = guarded.SafeTransport(baseTransport)
	}
	client := newJSHTTPClient(policy, pacedRoundTripper{base: baseTransport, ticks: pacer.C})
	defer client.CloseIdleConnections()

	// Download concurrently; the transport pacer accounts for every outbound
	// HTTP request, including redirects, under the configured request ceiling.
	sem := make(chan struct{}, e.reconConcurrency(5))
	var wg sync.WaitGroup
	type downloadSlot struct {
		file    JSFile
		ok      bool
		partial bool
	}
	slots := make([]downloadSlot, len(jsURLs))

	for index, jsURL := range jsURLs {
		wg.Add(1)
		go func(slotIndex int, rawURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Determine source
			source := "katana"
			if strings.Contains(rawURL, "web.archive.org") {
				source = "wayback"
			}

			parsed, ok := normalizeJSURL(rawURL)
			if !ok || policy.scope == nil || !policy.scope.AllowsURL(parsed.String()) {
				return
			}

			req, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BugBountyAgent/1.0)")
			for name, value := range policy.headersForURL(parsed.String()) {
				req.Header.Set(name, value)
			}

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return
			}

			// Read limited content
			body, err := io.ReadAll(io.LimitReader(resp.Body, maxContentSize+1))
			if err != nil {
				return
			}
			truncated := len(body) > maxContentSize
			if truncated {
				body = body[:maxContentSize]
			}

			content := string(body)
			// Skip if too small (likely error page) or is HTML
			if len(content) < 100 || strings.Contains(content[:min(200, len(content))], "<!DOCTYPE") {
				return
			}

			finalURL := parsed.String()
			if resp.Request != nil && resp.Request.URL != nil {
				finalURL = resp.Request.URL.String()
			}

			slots[slotIndex] = downloadSlot{ok: true, partial: truncated, file: JSFile{
				URL:       finalURL,
				Content:   content,
				Size:      len(content),
				Source:    source,
				Truncated: truncated,
			}}
		}(index, jsURL)
	}

	wg.Wait()
	jsFiles := make([]JSFile, 0, len(slots))
	incomplete := 0
	for _, slot := range slots {
		if slot.ok {
			jsFiles = append(jsFiles, slot.file)
			if slot.partial {
				incomplete++
			}
		} else {
			incomplete++
		}
	}
	return jsFiles, len(jsURLs), incomplete, omitted
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
