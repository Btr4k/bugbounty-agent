package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/recon"
	"github.com/Btr4k/bugbounty-agent/internal/redaction"
	scopepolicy "github.com/Btr4k/bugbounty-agent/internal/scope"
)

const (
	toolStdoutLimit = 16 << 20 // 16 MiB of machine-readable output
	toolStderrLimit = 64 << 10 // 64 KiB of diagnostics
	toolLineLimit   = 1 << 20  // 1 MiB per result record
)

// boundedCapture implements io.Writer without allowing a noisy or compromised
// subprocess to grow the agent's memory without bound. Write always reports the
// input as consumed so os/exec can continue draining the child process after
// the retained prefix reaches the configured limit.
type boundedCapture struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func newBoundedCapture(limit int) *boundedCapture {
	return &boundedCapture{limit: limit}
}

func (capture *boundedCapture) Write(input []byte) (int, error) {
	originalLength := len(input)
	remaining := capture.limit - capture.buffer.Len()
	if remaining > 0 {
		if remaining > len(input) {
			remaining = len(input)
		}
		_, _ = capture.buffer.Write(input[:remaining])
	}
	if remaining < len(input) {
		capture.truncated = true
	}
	return originalLength, nil
}

func (capture *boundedCapture) Bytes() []byte  { return capture.buffer.Bytes() }
func (capture *boundedCapture) String() string { return capture.buffer.String() }
func (capture *boundedCapture) Len() int       { return capture.buffer.Len() }
func (capture *boundedCapture) Truncated() bool {
	return capture.truncated
}

type Engine struct {
	cfg                     *config.Config
	log                     *logger.Logger
	authWarningOnce         sync.Once
	externalTargetValidator externalTargetValidator
}

type externalTargetValidator func(context.Context, string) error

var errExternalTargetRejected = errors.New("external target rejected")

type Results struct {
	Findings    []Finding
	Stats       ScanStats
	Complete    bool
	FailedTools []string
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
	// Coverage counters are tool-target work items. A target scanned by two
	// enabled tools contributes two attempted/scanned items. This preserves the
	// distinction between host coverage and the number of unique hosts.
	TotalAttempted       int
	TotalScanned         int
	TotalSkipped         int
	TotalFailed          int
	SubstantiveAttempted int
	SubstantiveScanned   int
	SubstantiveSkipped   int
	SubstantiveFailed    int
	TotalFindings        int
	Critical             int
	High                 int
	Medium               int
	Low                  int
	Info                 int
}

func NewEngine(cfg *config.Config, log *logger.Logger) *Engine {
	return &Engine{
		cfg: cfg,
		log: log,
	}
}

// externalTargetGuard returns the injected test/runtime guard when present.
// Production callers otherwise get the same scope and public-address checks as
// the guarded in-process HTTP client. The child tools still resolve hostnames
// independently, so this narrows their DNS-rebinding window but cannot pin the
// address they ultimately connect to.
func (e *Engine) externalTargetGuard() externalTargetValidator {
	if e != nil && e.externalTargetValidator != nil {
		return e.externalTargetValidator
	}
	if e == nil || e.cfg == nil {
		return func(context.Context, string) error {
			return errors.New("scanner configuration is unavailable")
		}
	}
	policy := scopepolicy.New(e.cfg.Target)
	policyErr := policy.ValidationError()
	return func(ctx context.Context, rawTarget string) error {
		if policyErr != nil {
			return policyErr
		}

		trimmed := strings.TrimSpace(rawTarget)
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
			return policy.ValidateURL(ctx, trimmed)
		case strings.Contains(lower, "://"):
			return errors.New("unsupported target scheme")
		default:
			_, err := policy.ResolveAndValidateHost(ctx, trimmed)
			return err
		}
	}
}

// externalTargetHost returns a diagnostic label that cannot contain URL paths,
// query values, fragments, or userinfo. Validation failures must never echo the
// raw target because discovered URLs can contain opaque credentials.
func externalTargetHost(rawTarget string) string {
	trimmed := strings.TrimSpace(rawTarget)
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = host
	}
	trimmed = strings.Trim(strings.ToLower(trimmed), ".")
	if trimmed == "" || len(trimmed) > 253 || strings.Contains(trimmed, "..") || !validDomainRegex.MatchString(trimmed) {
		return "<invalid>"
	}
	return trimmed
}

func validateExternalTargetWith(
	ctx context.Context,
	validator externalTargetValidator,
	rawTarget string,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validator(ctx, rawTarget); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("%w: host %q failed scope/public-address validation", errExternalTargetRejected, externalTargetHost(rawTarget))
	}
	return nil
}

// partitionExternalTargets preserves safe work while rejecting targets that do
// not resolve exclusively to public addresses. It deliberately reports only a
// count and hostname label, never a raw URL or query string.
func (e *Engine) partitionExternalTargets(ctx context.Context, targets []string) ([]string, int, error) {
	validator := e.externalTargetGuard()
	safe := make([]string, 0, len(targets))
	rejected := 0
	firstRejectedHost := ""
	for index, target := range targets {
		if err := validateExternalTargetWith(ctx, validator, target); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				rejected += len(targets) - index
				return safe, rejected, err
			}
			rejected++
			if firstRejectedHost == "" {
				firstRejectedHost = externalTargetHost(target)
			}
			continue
		}
		safe = append(safe, target)
	}
	if rejected > 0 {
		return safe, rejected, fmt.Errorf("%w: %d of %d target(s) failed scope/public-address validation; first host %q", errExternalTargetRejected, rejected, len(targets), firstRejectedHost)
	}
	return safe, 0, nil
}

// ensureExternalTargets is the second, immediate pre-exec boundary. A changed
// DNS answer fails the invocation closed; orchestration already partitioned the
// initial list so stable safe targets are still executed independently of the
// initially rejected targets.
func (e *Engine) ensureExternalTargets(ctx context.Context, targets []string) error {
	_, rejected, err := e.partitionExternalTargets(ctx, targets)
	if err != nil {
		return err
	}
	if rejected != 0 {
		return fmt.Errorf("%w: %d target(s) rejected immediately before execution", errExternalTargetRejected, rejected)
	}
	return nil
}

// safeToolDiagnostic removes configured and discovered credentials and folds
// control characters before subprocess-controlled text reaches logs or errors.
func (e *Engine) safeToolDiagnostic(value string) string {
	if e.cfg != nil {
		value = e.cfg.Redact(value)
	}
	value = redaction.SanitizeURLsInText(value)
	return strings.TrimSpace(redaction.Mask(value))
}

func truncateToolField(value string, maximum int) string {
	if maximum <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	return string(runes[:maximum]) + "…"
}

func (e *Engine) safeFindingField(value string, maximum int) string {
	value = redaction.SanitizeURLsInText(value)
	if e.cfg != nil {
		value = e.cfg.Redact(value)
	}
	return truncateToolField(redaction.Mask(value), maximum)
}

func (e *Engine) safeFindingBlock(value string, maximum int) string {
	value = redaction.SanitizeURLsInText(value)
	if e.cfg != nil {
		value = e.cfg.Redact(value)
	}
	return truncateToolField(redaction.MaskMultiline(value), maximum)
}

func (e *Engine) safeFindingURL(value string) string {
	value = redaction.SanitizeURL(value)
	if e.cfg != nil {
		value = e.cfg.Redact(value)
	}
	return truncateToolField(redaction.Mask(value), 4096)
}

func safeStringSlice(values []string, maximumItems int, sanitize func(string) string) []string {
	if len(values) > maximumItems {
		values = values[:maximumItems]
	}
	safe := make([]string, 0, len(values))
	for _, value := range values {
		if value = sanitize(value); value != "" {
			safe = append(safe, value)
		}
	}
	return safe
}

// writeTargetLines makes a subprocess input file complete-or-error. Ignoring a
// short write, buffered flush, or close error can make a tool scan an empty or
// partial target list while orchestration incorrectly records full coverage.
func writeTargetLines(file io.WriteCloser, targets []string) error {
	if file == nil {
		return errors.New("target file is unavailable")
	}
	writer := bufio.NewWriter(file)
	for _, target := range targets {
		if _, err := writer.WriteString(target); err != nil {
			_ = file.Close()
			return errors.New("target file write failed")
		}
		if err := writer.WriteByte('\n'); err != nil {
			_ = file.Close()
			return errors.New("target file write failed")
		}
	}
	if err := writer.Flush(); err != nil {
		_ = file.Close()
		return errors.New("target file flush failed")
	}
	if err := file.Close(); err != nil {
		return errors.New("target file close failed")
	}
	return nil
}

func (e *Engine) boundedRateLimit(toolMaximum int) int {
	rate := e.cfg.Scanning.RateLimit
	if rate <= 0 {
		rate = 1
	}
	if toolMaximum > 0 && rate > toolMaximum {
		rate = toolMaximum
	}
	return rate
}

func (e *Engine) boundedThreads(toolMaximum int) int {
	threads := e.cfg.Scanning.Threads
	if threads <= 0 {
		threads = 1
	}
	if toolMaximum > 0 && threads > toolMaximum {
		threads = toolMaximum
	}
	return threads
}

// conservativeConcurrency keeps in-flight work at or below both the configured
// thread ceiling and request-rate ceiling. A low rate limit must never be
// undermined by dozens of concurrent workers waiting to burst requests.
func (e *Engine) conservativeConcurrency(toolMaximum int) int {
	workers := e.boundedThreads(toolMaximum)
	rate := e.boundedRateLimit(0)
	if workers > rate {
		workers = rate
	}
	if workers < 1 {
		return 1
	}
	return workers
}

// dalfoxDelayMillis translates the global requests/second ceiling into a
// conservative per-worker delay. Rounding up avoids exceeding the requested
// rate due to integer truncation.
func dalfoxDelayMillis(workers, rate int) int {
	if workers < 1 {
		workers = 1
	}
	if rate < 1 {
		rate = 1
	}
	delay := (1000*workers + rate - 1) / rate
	if delay < 1 {
		return 1
	}
	return delay
}

func addCoverage(stats *ScanStats, attempted, scanned, skipped, failed int) {
	stats.TotalAttempted += attempted
	stats.TotalScanned += scanned
	stats.TotalSkipped += skipped
	stats.TotalFailed += failed
}

// withoutExternalToolAuth intentionally leaves authentication credentials out
// of subprocess arguments. Command lines are observable through process
// inspection and CI/runtime telemetry, so even allowlisted credentials belong
// only in the guarded in-process HTTPS client.
func (e *Engine) withoutExternalToolAuth(args []string) []string {
	if e.cfg.Authentication.Configured() && e.log != nil {
		e.authWarningOnce.Do(func() {
			e.log.Warn("Authentication credentials are not passed to external scanner processes; authenticated requests require the guarded internal HTTPS client")
		})
	}
	return args
}

func (e *Engine) appendNucleiRedactionArgs(args []string) []string {
	for name := range e.cfg.Authentication.Headers {
		args = append(args, "-rd", name)
	}
	if len(e.cfg.Authentication.Cookies) > 0 {
		args = append(args, "-rd", "Cookie")
	}
	return args
}

func (e *Engine) Run(ctx context.Context, reconResults *recon.Results) (*Results, error) {
	results := &Results{
		Findings:    make([]Finding, 0),
		Complete:    true,
		FailedTools: make([]string, 0),
	}
	if reconResults == nil {
		results.Complete = false
		results.FailedTools = append(results.FailedTools, "recon-input")
		return results, errors.New("scan requires non-nil reconnaissance results")
	}
	policy := scopepolicy.New(e.cfg.Target)
	if err := policy.ValidationError(); err != nil {
		results.Complete = false
		results.FailedTools = append(results.FailedTools, "scope")
		return results, fmt.Errorf("invalid scan scope: %w", err)
	}
	reconResults.Subdomains = policy.FilterHosts(reconResults.Subdomains)
	reconResults.URLs = policy.FilterURLs(reconResults.URLs)

	mu := &sync.Mutex{}
	var toolErrors []error
	failedToolSet := make(map[string]bool)
	recordToolError := func(tool string, err error) {
		mu.Lock()
		results.Complete = false
		if !failedToolSet[tool] {
			failedToolSet[tool] = true
			toolErrors = append(toolErrors, fmt.Errorf("%s: %w", tool, err))
			results.FailedTools = append(results.FailedTools, tool)
		}
		mu.Unlock()
	}
	filterExternalTargets := func(tool string, toolCtx context.Context, targets []string, substantive bool) []string {
		safe, rejected, validationErr := e.partitionExternalTargets(toolCtx, targets)
		if rejected > 0 {
			results.Stats.TotalFailed += rejected
			if substantive {
				results.Stats.SubstantiveFailed += rejected
			}
			e.log.Warnf("%s public-address validation rejected %d target(s); safe targets will continue and coverage is partial", tool, rejected)
		}
		if validationErr != nil {
			recordToolError(strings.ToLower(tool), validationErr)
		}
		return safe
	}
	recordCap := func(tool string, skipped int) {
		if skipped <= 0 {
			return
		}
		results.Stats.TotalSkipped += skipped
		results.Complete = false
		e.log.Warnf("%s target cap skipped %d eligible target(s); coverage is partial", tool, skipped)
	}

	// Show what tools will run
	totalTargets := len(reconResults.Subdomains)
	e.log.PhaseNote(fmt.Sprintf("Scanning %d subdomains with enabled tools...", totalTargets))

	// Per-tool timeout (default: scanning timeout from config)
	toolTimeout := time.Duration(e.cfg.Scanning.Timeout) * time.Second
	if toolTimeout <= 0 {
		toolTimeout = 5 * time.Minute
	}

	// ════════════════════════════════════════════════
	// STAGE 1: Httpx live-host probe (runs FIRST)
	// ════════════════════════════════════════════════
	var liveHosts []string
	if e.cfg.Scanning.Tools.Httpx.Enabled {
		httpxTargets := append([]string(nil), reconResults.Subdomains...)
		results.Stats.TotalAttempted += len(httpxTargets)
		httpxCtx, httpxCancel := context.WithTimeout(ctx, toolTimeout)
		httpxTargets = filterExternalTargets("Httpx", httpxCtx, httpxTargets, false)
		e.log.ToolStart("Httpx", fmt.Sprintf("probing %d public-address-validated targets for live hosts...", len(httpxTargets)))
		start := time.Now()

		var hosts []string
		var findings []Finding
		var err error

		// Retry once only after a real tool error. A successful zero-live-host
		// result is valid and must not double the target's request volume.
		for attempt := 1; attempt <= 2; attempt++ {
			attemptFindings, attemptHosts, attemptErr := e.runHttpx(httpxCtx, httpxTargets)
			findings = append(findings, attemptFindings...)
			hosts = deduplicateURLs(append(hosts, attemptHosts...))
			err = attemptErr
			if err == nil {
				break
			}
			if errors.Is(err, errExternalTargetRejected) {
				break
			}
			if attempt < 2 {
				e.log.Warnf("Httpx attempt %d/2 failed — retrying in 3s", attempt)
				select {
				case <-httpxCtx.Done():
					httpxCancel()
					err = httpxCtx.Err()
					attempt = 2
				case <-time.After(3 * time.Second):
				}
			}
		}
		httpxCancel()

		if err != nil {
			confirmed := countMatchedHostTargets(httpxTargets, policy.FilterURLs(hosts))
			addCoverage(&results.Stats, 0, confirmed, 0, len(httpxTargets)-confirmed)
			e.log.ToolFail("Httpx", err)
			recordToolError("httpx", err)
		} else {
			results.Stats.TotalScanned += len(httpxTargets)
			e.log.ToolDone("Httpx", len(hosts), time.Since(start))
			e.log.PhaseNote(fmt.Sprintf("Live hosts: %d / %d subdomains respond", len(hosts), totalTargets))
			liveHosts = hosts
			liveHosts = policy.FilterURLs(liveHosts)
			mu.Lock()
			results.Findings = append(results.Findings, findings...)
			mu.Unlock()
		}
	} else {
		e.log.ToolSkip("Httpx", "disabled in config")
	}

	// When httpx is intentionally disabled, raw targets are the user's chosen
	// input. When it is enabled but finds no live hosts, do not turn that failure
	// into blind active scanning against every discovered hostname.
	if len(liveHosts) == 0 && !e.cfg.Scanning.Tools.Httpx.Enabled {
		for _, sub := range reconResults.Subdomains {
			if strings.HasPrefix(sub, "http://") || strings.HasPrefix(sub, "https://") {
				liveHosts = append(liveHosts, sub)
			} else {
				liveHosts = append(liveHosts, "https://"+sub)
			}
		}
		e.log.PhaseNote("Httpx disabled: using raw in-scope subdomains")
	} else if len(liveHosts) == 0 {
		e.log.PhaseNote("No live hosts confirmed by httpx; active host scanning will be skipped")
	}

	// ════════════════════════════════════════════════
	// STAGE 2: Active scanners run SEQUENTIALLY, not in parallel.
	// ════════════════════════════════════════════════
	// Running multiple heavy scanners (nuclei, dalfox) at once on a modest host
	// exhausts memory and the OOM killer terminates them mid-scan
	// ("signal: killed"), wasting the entire budget for zero results. Each
	// scanner now gets the machine to itself and finishes within its budget.

	// ── Nuclei: the primary value engine (CVEs, misconfigs, exposures, takeovers).
	// Uses full URLs from httpx (preserves ports like :8080, :8443).
	if e.cfg.Scanning.Tools.Nuclei.Enabled {
		// Cap the host count so the full template sweep can actually COMPLETE
		// within the budget. On targets fronted by slow/WAF-throttled hosts an
		// uncapped sweep never finishes, and which findings surface before the
		// deadline becomes luck. Hosts are prioritized, so the cap keeps the
		// high-value names (api, admin, www, …) and drops CT-log noise.
		allNucleiTargets := deduplicateURLs(liveHosts)
		nucleiTargets := prioritizeNucleiTargets(allNucleiTargets, 25)
		nucleiSkipped := len(allNucleiTargets) - len(nucleiTargets)
		recordCap("Nuclei", nucleiSkipped)
		results.Stats.SubstantiveSkipped += nucleiSkipped
		results.Stats.TotalAttempted += len(nucleiTargets)
		results.Stats.SubstantiveAttempted += len(nucleiTargets)
		nucleiCtx, nucleiCancel := context.WithTimeout(ctx, toolTimeout)
		nucleiTargets = filterExternalTargets("Nuclei", nucleiCtx, nucleiTargets, true)

		e.log.Debugf("Nuclei targets: %d full URLs", len(nucleiTargets))
		if len(nucleiTargets) > 0 {
			limit := 5
			if len(nucleiTargets) < limit {
				limit = len(nucleiTargets)
			}
			hosts := make([]string, 0, limit)
			for _, target := range nucleiTargets[:limit] {
				hosts = append(hosts, externalTargetHost(target))
			}
			e.log.Debugf("Sample target hosts: %v", hosts)
		}

		e.log.ToolStart("Nuclei", fmt.Sprintf("scanning %d public-address-validated live targets with high-value templates...", len(nucleiTargets)))
		start := time.Now()

		// Retry only twice: a hard failure with partial results is usually a
		// budget issue, not a transient network blip, so endless retries only
		// burn the remaining budget. Partial findings are always preserved.
		findings, err := runWithRetry(nucleiCtx, e.log, "Nuclei", 2, func(rctx context.Context) ([]Finding, error) {
			return e.runNucleiDirect(rctx, nucleiTargets)
		})
		timedOut := nucleiCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil
		nucleiCancel()
		if len(findings) > 0 {
			results.Findings = append(results.Findings, findings...)
		}
		switch {
		case err == nil:
			results.Stats.TotalScanned += len(nucleiTargets)
			results.Stats.SubstantiveScanned += len(nucleiTargets)
			e.log.ToolDone("Nuclei", len(findings), time.Since(start))
		case timedOut:
			// The budget expired. Nuclei is time-boxed, NOT failed: it ran and
			// findings already emitted to the bounded stdout stream were kept. Treat this as a
			// coverage limit (partial), not a tool failure — so the report does
			// not show a scary "❌ failed" while still being honest that not
			// every host was fully scanned.
			e.log.Warnf("Nuclei time-boxed at the %s budget — %d finding(s) kept; host coverage is partial", toolTimeout, len(findings))
			e.log.ToolDone("Nuclei", len(findings), time.Since(start))
			results.Stats.TotalFailed += len(nucleiTargets)
			results.Stats.SubstantiveFailed += len(nucleiTargets)
			results.Complete = false
		default:
			results.Stats.TotalFailed += len(nucleiTargets)
			results.Stats.SubstantiveFailed += len(nucleiTargets)
			e.log.ToolFail("Nuclei", err)
			recordToolError("nuclei", err)
		}
	} else {
		e.log.ToolSkip("Nuclei", "disabled in config")
	}

	// ── Nmap: opt-in port scanning (disabled by default — recon only).
	if e.cfg.Scanning.Tools.Nmap.Enabled {
		nmapCandidates := prioritizeTargets(validateSubdomains(liveHosts))
		nmapTargets := nmapCandidates
		if len(nmapTargets) > 25 {
			nmapTargets = nmapTargets[:25]
		}
		recordCap("Nmap", len(nmapCandidates)-len(nmapTargets))
		results.Stats.TotalAttempted += len(nmapTargets)
		nmapCtx, nmapCancel := context.WithTimeout(ctx, toolTimeout)
		nmapTargets = filterExternalTargets("Nmap", nmapCtx, nmapTargets, false)
		e.log.ToolStart("Nmap", fmt.Sprintf("port scanning %d public-address-validated live targets (ports: %s)...",
			len(nmapTargets), e.cfg.Scanning.Tools.Nmap.Ports))
		start := time.Now()

		findings, scanned, failed, err := e.runNmapWithStats(nmapCtx, nmapTargets)
		nmapCancel()
		addCoverage(&results.Stats, 0, scanned, 0, failed)
		if len(findings) > 0 {
			results.Findings = append(results.Findings, findings...)
		}
		if err != nil {
			e.log.ToolFail("Nmap", err)
			recordToolError("nmap", err)
		} else {
			e.log.ToolDone("Nmap", len(findings), time.Since(start))
		}
	} else {
		e.log.ToolSkip("Nmap", "disabled in config")
	}

	// ── Dalfox: reflected-XSS fuzzing of parameterized URLs (runs last, alone).
	if e.cfg.Scanning.Tools.Dalfox.Enabled {
		allParamURLs := deduplicateURLs(extractParameterizedURLs(reconResults.URLs))
		sort.Slice(allParamURLs, func(i, j int) bool {
			left, right := strings.ToLower(allParamURLs[i]), strings.ToLower(allParamURLs[j])
			if left != right {
				return left < right
			}
			return allParamURLs[i] < allParamURLs[j]
		})

		if len(allParamURLs) == 0 {
			e.log.ToolSkip("Dalfox", "no parameterized URLs found")
		} else {
			maxURLs := e.cfg.Scanning.Tools.Dalfox.MaxURLs
			if maxURLs <= 0 {
				maxURLs = 75
			}
			eligibleCount := len(allParamURLs)
			if eligibleCount > maxURLs {
				allParamURLs = allParamURLs[:maxURLs]
			}
			dalfoxSkipped := eligibleCount - len(allParamURLs)
			recordCap("Dalfox", dalfoxSkipped)
			results.Stats.SubstantiveSkipped += dalfoxSkipped
			results.Stats.TotalAttempted += len(allParamURLs)
			results.Stats.SubstantiveAttempted += len(allParamURLs)

			dalfoxTimeout := toolTimeout
			if dalfoxTimeout > 5*time.Minute {
				dalfoxTimeout = 5 * time.Minute
			}
			dalfoxCtx, dalfoxCancel := context.WithTimeout(ctx, dalfoxTimeout)
			allParamURLs = filterExternalTargets("Dalfox", dalfoxCtx, allParamURLs, true)
			e.log.ToolStart("Dalfox", fmt.Sprintf("XSS fuzzing %d public-address-validated parameterized URLs...", len(allParamURLs)))
			start := time.Now()

			findings, err := e.runDalfox(dalfoxCtx, allParamURLs)
			dalfoxCancel()
			if len(findings) > 0 {
				results.Findings = append(results.Findings, findings...)
			}
			if err != nil {
				results.Stats.TotalFailed += len(allParamURLs)
				results.Stats.SubstantiveFailed += len(allParamURLs)
				e.log.ToolFail("Dalfox", err)
				recordToolError("dalfox", err)
			} else {
				results.Stats.TotalScanned += len(allParamURLs)
				results.Stats.SubstantiveScanned += len(allParamURLs)
				e.log.ToolDone("Dalfox", len(findings), time.Since(start))
			}
		}
	} else {
		e.log.ToolSkip("Dalfox", "disabled in config")
	}

	// Deduplicate findings (exact match only: same title + same URL). Broad
	// URL/class dedup can erase distinct vulnerabilities on the same endpoint,
	// which is worse than retaining a duplicate candidate for the AI pass.
	results.Findings = deduplicateFindings(policy, results.Findings)

	// Calculate statistics
	e.calculateStats(results)
	if len(toolErrors) > 0 {
		e.log.Warnf("Vulnerability scanning completed partially: %d enabled tool(s) failed", len(toolErrors))
	}
	if err := ctx.Err(); err != nil {
		return results, err
	}

	return results, nil
}

func findingInScope(policy *scopepolicy.Policy, finding Finding) bool {
	if finding.URL != "" {
		return policy.AllowsURL(finding.URL)
	}
	return policy.AllowsHost(finding.Target)
}

func deduplicateFindings(policy *scopepolicy.Policy, findings []Finding) []Finding {
	exactSeen := make(map[string]bool)
	deduped := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		if !findingInScope(policy, finding) {
			continue
		}
		key := strings.ToLower(finding.Title + "|" + finding.URL)
		if port, ok := nmapPortIdentity(finding); ok {
			key = "nmap|" + strings.ToLower(finding.Target) + "|" + port
		} else if finding.URL == "" {
			// Host-oriented findings (notably Nmap) have no URL. Include the
			// target and evidence so distinct observations are not collapsed.
			key = strings.ToLower(finding.Title + "|" + finding.Target + "|" + finding.Evidence)
		}
		if exactSeen[key] {
			continue
		}
		exactSeen[key] = true
		deduped = append(deduped, finding)
	}
	return deduped
}

// nmapPortIdentity returns the stable host-local service identity used for
// deduplication. Service banners may vary between observations, but the same
// host and port/protocol still represent one open-port finding.
func nmapPortIdentity(finding Finding) (string, bool) {
	if finding.ID != "nmap-open-port" && finding.Type != "port-scan" {
		return "", false
	}
	fields := strings.Fields(finding.Evidence)
	if len(fields) == 0 {
		return "", false
	}
	parts := strings.SplitN(strings.ToLower(fields[0]), "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}
	for _, digit := range parts[0] {
		if digit < '0' || digit > '9' {
			return "", false
		}
	}
	return parts[0] + "/" + parts[1], true
}

// countMatchedHostTargets conservatively counts only requested hosts for which
// httpx emitted a result. Extra output, redirects to another in-scope host, or
// repeated scheme/port variants must not make incomplete coverage look full.
func countMatchedHostTargets(targets, liveHosts []string) int {
	requested := make(map[string]bool)
	for _, target := range validateSubdomains(targets) {
		requested[strings.ToLower(target)] = true
	}
	matched := make(map[string]bool)
	for _, host := range validateSubdomains(liveHosts) {
		host = strings.ToLower(host)
		if requested[host] {
			matched[host] = true
		}
	}
	return len(matched)
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

	targetLines := make([]string, 0, len(targets))
	for _, target := range targets {
		// Ensure protocol prefix
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}
		targetLines = append(targetLines, target)
	}
	if err := writeTargetLines(tmpFile, targetLines); err != nil {
		return nil, fmt.Errorf("nuclei %w", err)
	}

	// Reuse existing Nuclei command builder logic
	args := []string{
		"-l", tmpFile.Name(),
		"-jsonl",
		"-silent",
		"-irr",
		"-fhr", // follow redirects only on the same host
	}
	if len(e.cfg.Scanning.Tools.Nuclei.Severity) > 0 {
		args = append(args, "-severity", strings.Join(e.cfg.Scanning.Tools.Nuclei.Severity, ","))
	} else {
		// Do not spend the default scan budget on informational templates. If an
		// operator enables them explicitly, the analyzer still accounts for them.
		args = append(args, "-severity", "critical,high,medium,low")
	}
	tags := e.cfg.Scanning.Tools.Nuclei.Tags
	if len(tags) == 0 {
		tags = []string{"exposure", "takeover", "default-login"}
	}
	args = append(args, "-tags", strings.Join(tags, ","))
	args = append(args, "-pt", "http,ssl,dns")

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

	concurrency := e.conservativeConcurrency(100)
	rateLimit := e.boundedRateLimit(0)
	bulkSize := e.conservativeConcurrency(25)
	args = append(args, "-c", fmt.Sprintf("%d", concurrency))
	args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))
	// Tight per-request budget: the bottleneck is slow / WAF-throttled hosts
	// holding connections open. A short timeout + a single retry keeps wasted
	// time on dead hosts low so the rate-limited scan finishes inside its budget.
	// Per-request budget kept modest so slow hosts don't stall the scan, but not
	// so short that a large legitimate response (e.g. a 100 KB phpinfo page) is
	// cut off. No -mhe: it abandons a host after N errors, but the vulnerable
	// hosts on real targets are often the slow/erroring ones, so dropping them
	// throws away exactly the findings we want.
	args = append(args, "-timeout", "7")
	args = append(args, "-retries", "1")
	args = append(args, "-bulk-size", fmt.Sprintf("%d", bulkSize))

	args = e.withoutExternalToolAuth(args)
	args = e.appendNucleiRedactionArgs(args)

	e.log.Debugf("Nuclei: scanning %d full URLs", len(targets))

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	cmd.Env = config.ExternalToolEnvironment()
	stderrBuf := newBoundedCapture(toolStderrLimit)
	stdoutBuf := newBoundedCapture(toolStdoutLimit)
	cmd.Stderr = stderrBuf
	cmd.Stdout = stdoutBuf

	if validationErr := e.ensureExternalTargets(ctx, targets); validationErr != nil {
		return nil, fmt.Errorf("nuclei pre-execution target validation: %w", validationErr)
	}
	err = runExternalCommand(cmd)
	if err != nil {
		e.log.Debugf("Nuclei finished with error: %v", err)
	}

	// Keep exactly one bounded result stream. Passing -o would let a compromised
	// or noisy child grow an output file without limit while the process runs.
	// boundedCapture continues draining after the retained prefix is full, and
	// truncation is surfaced below as an integrity/coverage error.
	output := stdoutBuf.Bytes()
	outputTruncated := stdoutBuf.Truncated()

	// Parse JSON output (same parsing as runNuclei)
	var findings []Finding
	malformedLines := 0
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	scanner.Buffer(make([]byte, 64*1024), toolLineLimit)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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
			malformedLines++
			continue
		}
		if strings.TrimSpace(nucleiResult.TemplateID) == "" ||
			(strings.TrimSpace(nucleiResult.MatchedAt) == "" && strings.TrimSpace(nucleiResult.Host) == "") {
			malformedLines++
			continue
		}

		severity := "info"
		title := nucleiResult.TemplateID
		description := ""
		var tags []string
		var references []string

		if info, ok := nucleiResult.Info["severity"].(string); ok {
			switch strings.ToLower(strings.TrimSpace(info)) {
			case "critical", "high", "medium", "low":
				severity = strings.ToLower(strings.TrimSpace(info))
			}
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

		safeTags := safeStringSlice(tags, 50, func(value string) string { return e.safeFindingField(value, 128) })
		safeReferences := safeStringSlice(references, 50, func(value string) string { return e.safeFindingField(value, 2048) })
		findings = append(findings, Finding{
			ID:          e.safeFindingField(nucleiResult.TemplateID, 256),
			Title:       e.safeFindingField(title, 500),
			Description: e.safeFindingBlock(description, 4000),
			Severity:    severity,
			Type:        e.safeFindingField(nucleiResult.Type, 80),
			Target:      e.safeFindingField(nucleiResult.Host, 500),
			URL:         e.safeFindingURL(nucleiResult.MatchedAt),
			Evidence:    e.safeFindingBlock(strings.Join(nucleiResult.ExtractedResults, ", "), 32<<10),
			Request:     e.safeFindingBlock(nucleiResult.Request, 256<<10),
			Response:    e.safeFindingBlock(nucleiResult.Response, 256<<10),
			CVE:         e.safeFindingField(cve, 80),
			Tags:        safeTags,
			References:  safeReferences,
			Timestamp:   e.safeFindingField(nucleiResult.Timestamp, 80),
			Metadata: map[string]string{
				"matcher": e.safeFindingField(nucleiResult.MatcherName, 256),
				"curl":    e.safeFindingBlock(nucleiResult.CURLCommand, 16<<10),
				"tool":    "nuclei",
			},
		})
	}
	e.log.Debugf("Nuclei parsed %d findings", len(findings))
	var outputErrors []error
	if scanErr := scanner.Err(); scanErr != nil {
		outputErrors = append(outputErrors, fmt.Errorf("failed to parse nuclei output: %w", scanErr))
	}
	if malformedLines > 0 {
		outputErrors = append(outputErrors, fmt.Errorf("nuclei emitted %d malformed JSON result line(s)", malformedLines))
	}
	if outputTruncated {
		outputErrors = append(outputErrors, fmt.Errorf("nuclei result output exceeded the %d-byte capture limit", toolStdoutLimit))
	}
	if stderrBuf.Truncated() {
		outputErrors = append(outputErrors, fmt.Errorf("nuclei diagnostic output exceeded the %d-byte capture limit", toolStderrLimit))
	}
	if err != nil {
		detail := e.safeToolDiagnostic(stderrBuf.String())
		if detail != "" {
			outputErrors = append(outputErrors, fmt.Errorf("nuclei failed after %d partial finding(s): %w: %s", len(findings), err, detail))
		} else {
			outputErrors = append(outputErrors, fmt.Errorf("nuclei failed after %d partial finding(s): %w", len(findings), err))
		}
	}
	return findings, errors.Join(outputErrors...)
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
	var partialFindings []Finding

	for attempt := 1; attempt <= maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return partialFindings, ctx.Err()
		default:
		}

		findings, err := fn(ctx)
		if err == nil {
			return append(partialFindings, findings...), nil
		}
		if len(findings) > 0 {
			partialFindings = append(partialFindings, findings...)
		}

		lastErr = err
		// A target that failed scope/public-address validation must not become
		// eligible merely because a retry observes a different DNS answer.
		if errors.Is(err, errExternalTargetRejected) {
			return partialFindings, err
		}

		if attempt < maxRetries {
			// Exponential backoff: 2s, 4s, 8s...
			wait := time.Duration(1<<uint(attempt)) * time.Second
			if wait > 30*time.Second {
				wait = 30 * time.Second
			}
			log.Warnf("%s attempt %d/%d failed (%v) — retrying in %s", toolName, attempt, maxRetries, err, wait)

			select {
			case <-ctx.Done():
				return partialFindings, ctx.Err()
			case <-time.After(wait):
			}
		}
	}

	return partialFindings, fmt.Errorf("%s failed after %d attempts: %w", toolName, maxRetries, lastErr)
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

// ResolveHttpxBinary finds the ProjectDiscovery httpx binary.
// The system may have a Python-based `httpx` CLI at /usr/local/bin/httpx that
// conflicts with ProjectDiscovery's httpx. We detect the correct one by
// preferring Go bin paths, then falling back to PATH resolution.
func ResolveHttpxBinary() (string, bool) {
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
		if isProjectDiscoveryHttpx(p) {
			return p, true
		}
	}
	if p, err := exec.LookPath("httpx"); err == nil {
		if isProjectDiscoveryHttpx(p) {
			return p, true
		}
	}
	return "", false
}

func isProjectDiscoveryHttpx(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Mode()&0111 == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "-version")
	cmd.Env = config.ExternalToolEnvironment()
	// ProjectDiscovery httpx prints its banner (including "projectdiscovery.io")
	// and version line to STDERR, not stdout. Capture both and check the combined
	// output — reading stdout alone made this detector always fail, so a correctly
	// installed httpx was reported "missing" and every scan aborted at preflight.
	stdout := newBoundedCapture(toolStderrLimit)
	stderr := newBoundedCapture(toolStderrLimit)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = runExternalCommand(cmd)
	combined := strings.ToLower(stdout.String() + "\n" + stderr.String())
	return err == nil && strings.Contains(combined, "projectdiscovery")
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
	httpxBin, ok := ResolveHttpxBinary()
	if !ok {
		return nil, nil, fmt.Errorf("ProjectDiscovery httpx binary not found")
	}
	e.log.Debugf("Httpx binary: %s", httpxBin)
	e.log.Debugf("Httpx scanning %d targets", len(targets))

	// Write targets to temp file
	tmpFile, err := os.CreateTemp("", "httpx-targets-*.txt")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if err := writeTargetLines(tmpFile, targets); err != nil {
		return nil, nil, fmt.Errorf("httpx %w", err)
	}

	args := []string{
		"-l", tmpFile.Name(),
		"-json",
		"-silent",
		"-td",
		"-t", fmt.Sprintf("%d", e.conservativeConcurrency(100)),
		"-rl", fmt.Sprintf("%d", e.boundedRateLimit(0)),
	}
	if e.cfg.Scanning.Tools.Httpx.StatusCode {
		args = append(args, "-sc")
	}
	if e.cfg.Scanning.Tools.Httpx.FollowRedirects {
		args = append(args, "-fhr")
	}
	args = e.withoutExternalToolAuth(args)

	cmd := exec.CommandContext(ctx, httpxBin, args...)
	cmd.Env = config.ExternalToolEnvironment()

	stdoutBuf := newBoundedCapture(toolStdoutLimit)
	stderrBuf := newBoundedCapture(toolStderrLimit)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	if validationErr := e.ensureExternalTargets(ctx, targets); validationErr != nil {
		return nil, nil, fmt.Errorf("httpx pre-execution target validation: %w", validationErr)
	}
	err = runExternalCommand(cmd)
	if err != nil {
		e.log.Debugf("Httpx finished with error: %v", err)
		if stderrBuf.Len() > 0 {
			e.log.Debugf("Httpx stderr: %s", e.safeToolDiagnostic(stderrBuf.String()))
		}
	}

	// Parse results
	seen := make(map[string]bool) // deduplicate live hosts
	malformedLines := 0
	scanner := bufio.NewScanner(strings.NewReader(stdoutBuf.String()))
	scanner.Buffer(make([]byte, 64*1024), toolLineLimit)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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
			malformedLines++
			continue
		}
		if strings.TrimSpace(httpxResult.URL) == "" {
			malformedLines++
			continue
		}

		// Collect live host URL (any HTTP response = live)
		if safeURL := e.safeFindingURL(httpxResult.URL); safeURL != "" && !seen[safeURL] {
			seen[safeURL] = true
			liveHosts = append(liveHosts, safeURL)
		}

		// httpx is a discovery/fingerprinting input. Status codes and technology
		// names alone are not vulnerabilities and must not enter the report.
	}

	var outputErrors []error
	if err != nil {
		detail := e.safeToolDiagnostic(stderrBuf.String())
		if detail != "" {
			outputErrors = append(outputErrors, fmt.Errorf("httpx failed: %w: %s", err, detail))
		} else {
			outputErrors = append(outputErrors, fmt.Errorf("httpx failed: %w", err))
		}
	}
	if parseErr := scanner.Err(); parseErr != nil {
		outputErrors = append(outputErrors, fmt.Errorf("failed to parse httpx output: %w", parseErr))
	}
	if malformedLines > 0 {
		outputErrors = append(outputErrors, fmt.Errorf("httpx emitted %d malformed JSON result line(s)", malformedLines))
	}
	if stdoutBuf.Truncated() {
		outputErrors = append(outputErrors, fmt.Errorf("httpx result output exceeded the %d-byte capture limit", toolStdoutLimit))
	}
	if stderrBuf.Truncated() {
		outputErrors = append(outputErrors, fmt.Errorf("httpx diagnostic output exceeded the %d-byte capture limit", toolStderrLimit))
	}
	return findings, liveHosts, errors.Join(outputErrors...)
}

func (e *Engine) runNmap(ctx context.Context, targets []string) ([]Finding, error) {
	findings, _, _, err := e.runNmapWithStats(ctx, targets)
	return findings, err
}

func (e *Engine) runNmapWithStats(ctx context.Context, targets []string) ([]Finding, int, int, error) {

	var findings []Finding
	var scanErrors []error
	scanned := 0
	failed := 0

	// Validate and filter targets
	targets = validateSubdomains(targets)

	if len(targets) == 0 {
		e.log.Debug("Nmap: no valid targets after filtering")
		return findings, scanned, failed, nil
	}

	e.log.Debugf("Nmap scanning %d targets", len(targets))

	for i, target := range targets {
		if err := ctx.Err(); err != nil {
			remaining := len(targets) - i
			failed += remaining
			scanErrors = append(scanErrors, fmt.Errorf("%d nmap target(s) not scanned: %w", remaining, err))
			break
		}
		var args []string

		// Fix: -F and -p are mutually exclusive in nmap
		if e.cfg.Scanning.Tools.Nmap.Ports != "" {
			args = append(args, "-p", e.cfg.Scanning.Tools.Nmap.Ports)
		} else if e.cfg.Scanning.Tools.Nmap.FastScan {
			args = append(args, "-F")
		}

		args = append(args,
			"--open",
			"-T3",
			"--max-rate", fmt.Sprintf("%d", e.boundedRateLimit(0)),
			"--max-parallelism", fmt.Sprintf("%d", e.conservativeConcurrency(32)),
			target,
		)

		cmd := exec.CommandContext(ctx, "nmap", args...)
		cmd.Env = config.ExternalToolEnvironment()
		stdoutBuf := newBoundedCapture(toolStdoutLimit)
		stderrBuf := newBoundedCapture(toolStderrLimit)
		cmd.Stdout = stdoutBuf
		cmd.Stderr = stderrBuf

		if validationErr := e.ensureExternalTargets(ctx, []string{target}); validationErr != nil {
			failed++
			scanErrors = append(scanErrors, fmt.Errorf("host %q: nmap pre-execution target validation: %w", externalTargetHost(target), validationErr))
			continue
		}
		commandErr := runExternalCommand(cmd)
		var targetErrors []error
		if commandErr != nil {
			detail := e.safeToolDiagnostic(stderrBuf.String())
			if detail != "" {
				e.log.Debugf("Nmap scan failed for %s: %v (stderr: %s)", target, commandErr, detail)
				targetErrors = append(targetErrors, fmt.Errorf("command failed: %w: %s", commandErr, detail))
			} else {
				e.log.Debugf("Nmap scan failed for %s: %v", target, commandErr)
				targetErrors = append(targetErrors, fmt.Errorf("command failed: %w", commandErr))
			}
		}

		// Parse open ports
		scanner := bufio.NewScanner(strings.NewReader(stdoutBuf.String()))
		scanner.Buffer(make([]byte, 64*1024), toolLineLimit)
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
					Evidence:    e.safeToolDiagnostic(line),
				})
			}
		}
		if scanErr := scanner.Err(); scanErr != nil {
			targetErrors = append(targetErrors, fmt.Errorf("failed to parse nmap output: %w", scanErr))
		}
		if stdoutBuf.Truncated() {
			targetErrors = append(targetErrors, fmt.Errorf("result output exceeded the %d-byte capture limit", toolStdoutLimit))
		}
		if stderrBuf.Truncated() {
			targetErrors = append(targetErrors, fmt.Errorf("diagnostic output exceeded the %d-byte capture limit", toolStderrLimit))
		}
		if len(targetErrors) > 0 {
			failed++
			scanErrors = append(scanErrors, fmt.Errorf("%s: %w", target, errors.Join(targetErrors...)))
			continue
		}
		scanned++
	}
	if len(scanErrors) > 0 {
		return findings, scanned, failed, errors.Join(scanErrors...)
	}

	return findings, scanned, failed, nil
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

// prioritizeNucleiTargets returns deduplicated full URLs ordered by hostname
// importance and capped at max. When the target count is already within budget
// the slice is returned unchanged.
func prioritizeNucleiTargets(targets []string, max int) []string {
	if max <= 0 || len(targets) <= max {
		return targets
	}
	hostnames := prioritizeTargets(validateSubdomains(targets))
	order := make(map[string]int, len(hostnames))
	for i, h := range hostnames {
		order[strings.ToLower(h)] = i
	}
	type scored struct {
		url   string
		score int
	}
	items := make([]scored, 0, len(targets))
	for _, u := range targets {
		s, ok := order[strings.ToLower(extractHostname(u))]
		if !ok {
			s = 999
		}
		items = append(items, scored{u, s})
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].score < items[j].score
	})
	prioritized := make([]string, 0, max)
	for _, item := range items {
		prioritized = append(prioritized, item.url)
	}
	return prioritized[:max]
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
		return nil, fmt.Errorf("dalfox not installed (run ./install.sh)")
	}

	// Write URLs to temp file
	tmpFile, err := os.CreateTemp("", "dalfox-urls-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if err := writeTargetLines(tmpFile, urls); err != nil {
		return nil, fmt.Errorf("dalfox %w", err)
	}

	e.log.Debugf("Dalfox scanning %d parameterized URLs", len(urls))

	workers := e.conservativeConcurrency(10)
	rateLimit := e.boundedRateLimit(0)
	delayMillis := dalfoxDelayMillis(workers, rateLimit)

	// Dalfox has no requests/second flag. Bound its worker pool and derive a
	// per-worker delay whose aggregate upper bound respects scanning.rate_limit.
	args := []string{
		"file", tmpFile.Name(),
		"--silence",
		"--no-color",
		"--format", "json",
		"--timeout", "10",
		"--delay", fmt.Sprintf("%d", delayMillis),
		"--worker", fmt.Sprintf("%d", workers),
		"--only-poc", "r", // Only report reflected XSS PoC
	}

	// Add blind XSS callback if configured
	if e.cfg.Scanning.Tools.Dalfox.BlindURL != "" {
		if err := validateBlindCallbackForExecution(ctx, e.cfg.Scanning.Tools.Dalfox.BlindURL, scopepolicy.PublicOriginOptions{}); err != nil {
			return nil, err
		}
		args = append(args, "-b", e.cfg.Scanning.Tools.Dalfox.BlindURL)
	}
	args = e.withoutExternalToolAuth(args)

	cmd := exec.CommandContext(ctx, "dalfox", args...)
	cmd.Env = config.ExternalToolEnvironment()

	stdoutBuf := newBoundedCapture(toolStdoutLimit)
	stderrBuf := newBoundedCapture(toolStderrLimit)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	if validationErr := e.ensureExternalTargets(ctx, urls); validationErr != nil {
		return nil, fmt.Errorf("dalfox pre-execution target validation: %w", validationErr)
	}
	err = runExternalCommand(cmd)
	if err != nil {
		// Dalfox may return non-zero even with results
		e.log.Debugf("Dalfox finished with error (may be normal): %v", err)
		if stderrBuf.Len() > 0 {
			e.log.Debugf("Dalfox stderr: %s", e.safeToolDiagnostic(stderrBuf.String()))
		}
	}

	// Parse JSON output (one JSON object per line)
	malformedLines := 0
	scanner := bufio.NewScanner(strings.NewReader(stdoutBuf.String()))
	scanner.Buffer(make([]byte, 64*1024), toolLineLimit)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var dalfoxResult struct {
			Type       string `json:"type"`
			Severity   string `json:"severity"`
			PoCType    string `json:"poc_type"`
			PoCURL     string `json:"data"`
			Param      string `json:"param"`
			InjectType string `json:"inject_type"`
			CWE        string `json:"cwe"`
			MessageStr string `json:"message_str"`
		}

		if err := json.Unmarshal([]byte(line), &dalfoxResult); err != nil {
			malformedLines++
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
		safeParam := e.safeFindingField(dalfoxResult.Param, 120)
		safeInjectType := e.safeFindingField(dalfoxResult.InjectType, 120)
		safePOCType := e.safeFindingField(dalfoxResult.PoCType, 80)
		safePOCURL := e.safeFindingURL(dalfoxResult.PoCURL)
		title := "XSS"
		if safeInjectType != "" {
			title = fmt.Sprintf("XSS (%s)", safeInjectType)
		}
		if safeParam != "" {
			title = fmt.Sprintf("%s in param '%s'", title, safeParam)
		}

		finding := Finding{
			ID:          truncateToolField(fmt.Sprintf("dalfox-xss-%s", safeParam), 256),
			Title:       truncateToolField(title, 500),
			Description: fmt.Sprintf("Reflected XSS vulnerability found by parameter fuzzing. Parameter: %s", safeParam),
			Severity:    severity,
			Type:        "xss",
			URL:         safePOCURL,
			Evidence:    safePOCURL,
			CWE:         "CWE-79",
			Tags:        []string{"xss", "dalfox", "parameter-fuzzing"},
			Metadata: map[string]string{
				"inject_type": safeInjectType,
				"param":       safeParam,
				"poc_type":    safePOCType,
				"tool":        "dalfox",
			},
			Timestamp: time.Now().Format(time.RFC3339),
		}

		findings = append(findings, finding)
	}
	var outputErrors []error
	if scanErr := scanner.Err(); scanErr != nil {
		outputErrors = append(outputErrors, fmt.Errorf("failed to parse dalfox output: %w", scanErr))
	}
	if malformedLines > 0 {
		outputErrors = append(outputErrors, fmt.Errorf("dalfox emitted %d malformed JSON result line(s)", malformedLines))
	}
	if stdoutBuf.Truncated() {
		outputErrors = append(outputErrors, fmt.Errorf("dalfox result output exceeded the %d-byte capture limit", toolStdoutLimit))
	}
	if stderrBuf.Truncated() {
		outputErrors = append(outputErrors, fmt.Errorf("dalfox diagnostic output exceeded the %d-byte capture limit", toolStderrLimit))
	}
	if err != nil {
		detail := e.safeToolDiagnostic(stderrBuf.String())
		if detail != "" {
			outputErrors = append(outputErrors, fmt.Errorf("dalfox failed after %d partial finding(s): %w: %s", len(findings), err, detail))
		} else {
			outputErrors = append(outputErrors, fmt.Errorf("dalfox failed after %d partial finding(s): %w", len(findings), err))
		}
	}

	return findings, errors.Join(outputErrors...)
}

// validateBlindCallbackForExecution performs a fresh all-answer DNS check just
// before Dalfox receives the callback. It never reflects the configured URL in
// diagnostics. This cannot control how a remote target later resolves the
// callback, so restrictive egress and explicit OAST authorization remain
// required.
func validateBlindCallbackForExecution(ctx context.Context, raw string, options scopepolicy.PublicOriginOptions) error {
	policy, err := scopepolicy.NewPublicOriginPolicy(raw, options)
	if err != nil {
		return errors.New("dalfox blind callback failed public-origin validation")
	}
	if err := policy.ValidateURL(ctx, raw); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return errors.New("dalfox blind callback failed public DNS validation")
	}
	return nil
}
