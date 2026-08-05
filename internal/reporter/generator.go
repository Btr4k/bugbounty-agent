package reporter

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/Btr4k/bugbounty-agent/internal/analyzer"
	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/recon"
	"github.com/Btr4k/bugbounty-agent/internal/redaction"
	"github.com/Btr4k/bugbounty-agent/internal/scanner"
)

type Generator struct {
	cfg *config.Config
	log *logger.Logger
}

func NewGenerator(cfg *config.Config, log *logger.Logger) *Generator {
	return &Generator{
		cfg: cfg,
		log: log,
	}
}

// Generate creates a professional bug bounty report
func (g *Generator) Generate(reconResults *recon.Results, scanResults *scanner.Results, analysis *analyzer.Analysis) (string, error) {
	if g == nil || g.cfg == nil {
		return "", fmt.Errorf("report generator requires a non-nil config")
	}
	if reconResults == nil || scanResults == nil || analysis == nil {
		return "", fmt.Errorf("report generation requires non-nil recon, scan, and analysis results")
	}
	if err := EnsurePrivateDirectory(g.cfg.Reporting.OutputDir); err != nil {
		return "", fmt.Errorf("failed to prepare output directory: %w", err)
	}

	content := g.generateMarkdownReport(reconResults, scanResults, analysis)
	timestamp := time.Now().UTC().Format("2006-01-02_15-04-05.000000000")
	var outputPath string
	for attempt := 0; attempt < 10; attempt++ {
		suffix := ""
		if attempt > 0 {
			suffix = fmt.Sprintf("-%d", attempt)
		}
		filename := fmt.Sprintf("bug_bounty_report_%s%s.md", timestamp, suffix)
		outputPath = filepath.Join(g.cfg.Reporting.OutputDir, filename)
		err := WritePrivateFileAtomic(outputPath, []byte(content))
		if err == nil {
			break
		}
		if !os.IsExist(err) || attempt == 9 {
			return "", fmt.Errorf("failed to write report: %w", err)
		}
	}

	if g.log != nil {
		g.log.Infof("Report generated successfully: %s", g.safeLog(outputPath))
	}
	return outputPath, nil
}

// EnsurePrivateDirectory creates a missing report directory privately or
// verifies an existing one. It never changes permissions on a pre-existing
// path: --output may point at /tmp, a shared mount, or another operator-owned
// directory whose mode HawkEye has no authority to rewrite implicitly.
func EnsurePrivateDirectory(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("output directory is empty")
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("output path must be a real directory, not a symlink or file")
	}
	if permissions := info.Mode().Perm(); permissions != 0o700 {
		return fmt.Errorf("output directory permissions are %o; use a dedicated directory and run chmod 700 %s", permissions, path)
	}
	return nil
}

// WritePrivateFileAtomic durably writes content to a private temporary file,
// then atomically publishes it without replacing an existing path. The
// temporary file lives beside the destination so the final hard-link publish
// cannot cross filesystems. Generate retries with a unique suffix on collision.
func WritePrivateFileAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".hawkeye-private-*.tmp")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if tempPath != "" {
			_ = os.Remove(tempPath)
		}
	}()

	if err := file.Chmod(0600); err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true

	// link(2) is an atomic no-replace publish: it fails with EEXIST if another
	// writer already owns the destination and exposes only fully-written data.
	if err := os.Link(tempPath, path); err != nil {
		return err
	}
	if err := os.Remove(tempPath); err != nil {
		return err
	}
	tempPath = ""

	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := dirFile.Sync(); err != nil {
		_ = dirFile.Close()
		return err
	}
	return dirFile.Close()
}

func (g *Generator) generateMarkdownReport(reconResults *recon.Results, scanResults *scanner.Results, analysis *analyzer.Analysis) string {
	var report strings.Builder

	confirmedFindings := confirmedOnly(analysis.ValidatedFindings)
	counts := countFindings(confirmedFindings, analysis.ManualReview, analysis.FalsePositives)
	target := g.safeInline(strings.Join(g.cfg.Target.Domains, ", "))
	coverage := assessCoverage(reconResults, scanResults, analysis)

	// Header
	report.WriteString(fmt.Sprintf("# Bug Bounty Report — %s\n\n", target))
	report.WriteString(fmt.Sprintf("**Date**: %s  \n", time.Now().Format("2006-01-02 15:04")))
	report.WriteString(fmt.Sprintf("**Target**: %s  \n", target))
	report.WriteString(fmt.Sprintf("**Subdomains Found**: %d  \n", len(reconResults.Subdomains)))
	report.WriteString(fmt.Sprintf("**URLs Discovered**: %d  \n", len(reconResults.URLs)))
	report.WriteString(fmt.Sprintf("**Reconnaissance Complete**: %t  \n", reconResults.Complete))
	report.WriteString(fmt.Sprintf("**Vulnerability Scan Complete**: %t  \n", scanResults.Complete))
	report.WriteString(fmt.Sprintf("**Raw Tool Candidates (Pre-Validation)**: %d  \n", len(scanResults.Findings)))
	report.WriteString(fmt.Sprintf("**Confirmed Findings**: %d  \n", counts.Confirmed))
	report.WriteString(fmt.Sprintf("**Manual Review Candidates**: %d  \n", counts.ManualReview))
	report.WriteString(fmt.Sprintf("**Rejected / Not Reportable**: %d  \n", counts.Rejected))
	report.WriteString(fmt.Sprintf("**Coverage Grade**: %s  \n", coverage.Grade))
	report.WriteString(fmt.Sprintf("**Negative Result Confidence**: %s  \n\n", coverage.NegativeConfidence))

	// Executive Summary with Risk Score
	// Weight JS-analysis-only findings at 50% to prevent inflated scores.
	riskScore := 0
	for _, vf := range confirmedFindings {
		weight := 1.0
		if vf.Type == "js-analysis" {
			weight = 0.5
		}
		switch strings.ToLower(vf.Severity) {
		case "critical":
			riskScore += int(10 * weight)
		case "high":
			riskScore += int(5 * weight)
		case "medium":
			riskScore += int(2 * weight)
		case "low":
			riskScore += int(1 * weight)
		}
	}
	riskLevel := "🟢 Low Observed Risk"
	if counts.Critical > 0 {
		riskLevel = "🔴 Critical Risk"
	} else if counts.High > 0 {
		riskLevel = "🟠 High Risk"
	} else if counts.Medium > 0 {
		riskLevel = "🟡 Medium Risk"
	} else if riskScore == 0 && counts.Confirmed == 0 {
		riskLevel = coverage.ZeroFindingRiskLevel
	} else if coverage.Grade == "Insufficient" {
		riskLevel = "⚪ Insufficient Coverage — Low Observed Severity"
	} else if coverage.Grade == "Limited" {
		riskLevel = "⚪ Limited Coverage — Low Observed Severity"
	}

	report.WriteString("## Executive Summary\n\n")
	report.WriteString(fmt.Sprintf("**Overall Risk Level**: %s (score: %d)  \n", riskLevel, riskScore))
	if !reconResults.Complete || !scanResults.Complete {
		report.WriteString("**Coverage Qualifier**: Partial / inconclusive; confirmed severity remains valid but absence claims do not.  \n")
	}
	report.WriteString(fmt.Sprintf("**Confirmed Findings**: %d  \n", counts.Confirmed))
	report.WriteString(fmt.Sprintf("**Manual Review Candidates**: %d  \n", counts.ManualReview))
	report.WriteString(fmt.Sprintf("**Rejected / Not Reportable**: %d  \n", counts.Rejected))
	report.WriteString(fmt.Sprintf("**Attack Surface**: %d subdomains discovered  \n\n", len(reconResults.Subdomains)))
	if counts.Confirmed == 0 && coverage.NegativeConfidence != "high" {
		report.WriteString(fmt.Sprintf("> ⚠️ **No confirmed findings were observed, but coverage is %s.** Treat this as a limited negative result, not proof that the target is secure.  \n\n", strings.ToLower(coverage.Grade)))
	}
	if !scanResults.Complete && len(scanResults.Findings) == 0 {
		report.WriteString("> ⚠️ **No vulnerability candidates were produced by an incomplete scan.** This is a coverage failure, not evidence that the target is secure.  \n\n")
	}
	if len(reconResults.FailedTools)+len(scanResults.FailedTools) > 0 {
		report.WriteString("**Failed Optional Tools**: ")
		failed := append([]string(nil), reconResults.FailedTools...)
		failed = append(failed, scanResults.FailedTools...)
		report.WriteString(g.safeInline(strings.Join(failed, ", ")) + "  \n\n")
	}

	if counts.Critical > 0 {
		report.WriteString("> ⚠️ **CRITICAL FINDINGS DETECTED** — Immediate remediation recommended.  \n\n")
	}

	report.WriteString("## Candidate Disposition\n\n")
	report.WriteString("| Stage / outcome | Count |\n|---|---:|\n")
	report.WriteString(fmt.Sprintf("| Raw tool candidates (pre-validation) | %d |\n", len(scanResults.Findings)))
	report.WriteString(fmt.Sprintf("| Confirmed findings | %d |\n", counts.Confirmed))
	report.WriteString(fmt.Sprintf("| Manual review required | %d |\n", counts.ManualReview))
	report.WriteString(fmt.Sprintf("| Rejected / not reportable | %d |\n\n", counts.Rejected))
	report.WriteString("> Raw candidates are pre-validation observations. Confirmed, manual-review, and rejected counts are post-validation outcomes; do not add the raw row to the outcome rows.\n\n")

	// Scan Coverage — transparency about what was assessed and how completely.
	report.WriteString("## Scan Coverage\n\n")
	report.WriteString("| Metric | Value |\n|---|---|\n")
	report.WriteString(fmt.Sprintf("| Unique hosts discovered | %d |\n", coverage.UniqueHosts))
	report.WriteString(fmt.Sprintf("| Unique routes discovered | %d |\n", coverage.UniqueRoutes))
	report.WriteString(fmt.Sprintf("| Unique route/query-key pairs discovered | %d |\n", coverage.UniqueQueryKeys))
	report.WriteString(fmt.Sprintf("| Unique JS resources analyzed | %d |\n", coverage.UniqueJSFiles))
	if coverage.ScanWorkKnown {
		report.WriteString(fmt.Sprintf("| Scanner work items attempted | %d |\n", coverage.AttemptedWorkItems))
		report.WriteString(fmt.Sprintf("| Scanner work items completed | %d |\n", coverage.CompletedWorkItems))
		report.WriteString(fmt.Sprintf("| Scanner work items skipped by caps | %d |\n", coverage.SkippedWorkItems))
		report.WriteString(fmt.Sprintf("| Scanner work items failed / incomplete | %d |\n", coverage.FailedWorkItems))
		report.WriteString(fmt.Sprintf("| Substantive vulnerability-scanner items attempted | %d |\n", coverage.SubstantiveAttempted))
		report.WriteString(fmt.Sprintf("| Substantive vulnerability-scanner items completed | %d |\n", coverage.SubstantiveCompleted))
	} else {
		report.WriteString("| Scanner work-item coverage | not recorded |\n")
	}
	report.WriteString(fmt.Sprintf("| Raw tool candidates (pre-validation) | %d |\n", len(scanResults.Findings)))
	report.WriteString(fmt.Sprintf("| Confirmed findings | %d |\n", counts.Confirmed))
	report.WriteString(fmt.Sprintf("| Manual review required | %d |\n", counts.ManualReview))
	report.WriteString(fmt.Sprintf("| Rejected / not reportable | %d |\n", counts.Rejected))
	report.WriteString(fmt.Sprintf("| Coverage grade | %s |\n", coverage.Grade))
	report.WriteString(fmt.Sprintf("| Negative-result confidence | %s |\n", coverage.NegativeConfidence))
	report.WriteString(fmt.Sprintf("| Reconnaissance complete | %s |\n", completeMark(reconResults.Complete)))
	report.WriteString(fmt.Sprintf("| Vulnerability scan complete | %s |\n", completeMark(scanResults.Complete)))
	failed := append([]string(nil), reconResults.FailedTools...)
	failed = append(failed, scanResults.FailedTools...)
	if len(failed) > 0 {
		report.WriteString(fmt.Sprintf("| Failed / partial tools | %s |\n", g.safeTable(strings.Join(failed, ", "))))
	}
	report.WriteString("\n")
	if len(failed) > 0 {
		report.WriteString("> ⚠️ One or more tools did not complete. Missing coverage is **not** evidence that the target is secure — re-run or investigate the failed tools.\n\n")
	}
	if len(coverage.Notes) > 0 {
		report.WriteString("**Coverage Notes**:\n")
		for _, note := range coverage.Notes {
			report.WriteString(fmt.Sprintf("- %s\n", note))
		}
		report.WriteString("\n")
	}

	// Severity Summary
	report.WriteString("## Summary\n\n")
	report.WriteString("| Severity | Count |\n")
	report.WriteString("|----------|-------|\n")
	if counts.Critical > 0 {
		report.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", counts.Critical))
	}
	if counts.High > 0 {
		report.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", counts.High))
	}
	if counts.Medium > 0 {
		report.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", counts.Medium))
	}
	if counts.Low > 0 {
		report.WriteString(fmt.Sprintf("| 🟢 Low | %d |\n", counts.Low))
	}
	report.WriteString("\n")

	// Submission-ready findings first. Low-value informational items remain
	// visible, but they no longer compete with reportable bug bounty material.
	severities := []struct {
		name  string
		emoji string
	}{
		{"critical", "🔴"},
		{"high", "🟠"},
		{"medium", "🟡"},
	}

	findingIndex := 1
	if len(g.filterSubmissionReady(confirmedFindings)) > 0 {
		report.WriteString("## Submission Ready Findings\n\n")
		report.WriteString("> These findings have captured evidence and enough impact to be considered for a bug bounty submission.\n\n")
		for _, sev := range severities {
			filtered := g.filterBySeverity(confirmedFindings, sev.name)
			if len(filtered) == 0 {
				continue
			}

			report.WriteString(fmt.Sprintf("### %s %s Severity\n\n", sev.emoji, cases.Title(language.English).String(sev.name)))

			for _, f := range filtered {
				report.WriteString(g.formatFinding(findingIndex, f))
				findingIndex++
			}
		}
	}

	lowValue := g.filterLowValue(confirmedFindings)
	if len(lowValue) > 0 {
		report.WriteString("## Low Value / Informational\n\n")
		report.WriteString("> These findings are technically valid but usually need stronger chained impact before submission.\n\n")
		for _, f := range lowValue {
			report.WriteString(g.formatFinding(findingIndex, f))
			findingIndex++
		}
	}

	if len(analysis.ManualReview) > 0 {
		report.WriteString("## Manual Review Required\n\n")
		report.WriteString("> These candidates are not confirmed vulnerabilities. Collect the missing evidence before submission.\n\n")
		for _, finding := range analysis.ManualReview {
			report.WriteString(g.formatFinding(findingIndex, finding))
			findingIndex++
		}
	}

	if len(analysis.FalsePositives) > 0 {
		report.WriteString("## Rejected / Not Reportable\n\n")
		report.WriteString("> These candidates were rejected by deterministic validation or AI review and should not be submitted as-is.\n\n")
		report.WriteString("| Candidate | URL | Reason |\n|---|---|---|\n")
		for _, finding := range analysis.FalsePositives {
			reason := finding.AIAnalysis
			if reason == "" {
				reason = "Rejected during validation"
			}
			report.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
				g.safeTable(finding.Title),
				g.safeTable(finding.URL),
				g.safeTable(g.truncate(g.cfg.Redact(reason), 180)),
			))
		}
		report.WriteString("\n")
	}

	// Subdomains discovered
	if len(reconResults.Subdomains) > 0 {
		report.WriteString("## Subdomains Discovered\n\n")
		g.writeCodeBlock(&report, "", strings.Join(reconResults.Subdomains, "\n"), 0)
		report.WriteString("\n")
	}

	// Footer
	report.WriteString("---\n\n")
	report.WriteString("*Generated by Bug Bounty AI Agent*\n")

	return report.String()
}

func (g *Generator) formatFinding(index int, finding analyzer.ValidatedFinding) string {
	var details strings.Builder

	emoji := g.getSeverityEmoji(finding.Severity)
	details.WriteString(fmt.Sprintf("### %d. %s %s\n\n", index, emoji, g.safeInline(finding.Title)))

	// Metadata table — compact, scannable header for the finding.
	details.WriteString("| Field | Value |\n|---|---|\n")
	details.WriteString(fmt.Sprintf("| **Severity** | %s |\n", g.safeTable(strings.ToUpper(finding.Severity))))
	details.WriteString(fmt.Sprintf("| **Confidence** | %.2f |\n", finding.Confidence))
	if finding.Decision != "" {
		details.WriteString(fmt.Sprintf("| **Decision** | %s |\n", g.safeTable(finding.Decision)))
	}
	if finding.Type != "" {
		details.WriteString(fmt.Sprintf("| **Type** | %s |\n", g.safeTable(finding.Type)))
	}
	if finding.URL != "" {
		details.WriteString(fmt.Sprintf("| **URL** | %s |\n", g.safeTable(finding.URL)))
	}
	if finding.CVE != "" {
		details.WriteString(fmt.Sprintf("| **CVE** | %s |\n", g.safeTable(finding.CVE)))
	}
	if finding.CVSS > 0 {
		details.WriteString(fmt.Sprintf("| **CVSS** | %.1f |\n", finding.CVSS))
	}
	if finding.CWE != "" {
		details.WriteString(fmt.Sprintf("| **CWE** | %s |\n", g.safeTable(finding.CWE)))
	}
	if finding.BugBountyValue != "" {
		details.WriteString(fmt.Sprintf("| **Bug Bounty Value** | %s |\n", g.safeTable(finding.BugBountyValue)))
	}
	if len(finding.UnverifiedScannerMetadata) > 0 {
		details.WriteString("\n**Unverified Scanner/Template Metadata** (context only, not proof):\n")
		for _, claim := range finding.UnverifiedScannerMetadata {
			details.WriteString(fmt.Sprintf("- %s\n", g.safeInline(claim)))
		}
	}

	// Narrative sections — the substance of a professional report. These come
	// from the AI validation pass and were previously discarded.
	g.writeSection(&details, "Description", finding.Description, 0)
	g.writeSection(&details, "Analysis", finding.AIAnalysis, 0)
	g.writeSection(&details, "Impact", finding.ImpactAssessment, 0)
	g.writeSection(&details, "Security Context", finding.CybersecurityContext, 0)
	g.writeSection(&details, "Remediation", finding.Remediation, 0)

	// Evidence blocks.
	if finding.Evidence != "" {
		details.WriteString("\n**Evidence**:\n")
		g.writeCodeBlock(&details, "", g.safeFindingEvidence(finding), 500)
	}
	if finding.Request != "" {
		details.WriteString("\n**Captured Request**:\n")
		g.writeCodeBlock(&details, "http", finding.Request, 1500)
	}
	if finding.Response != "" {
		details.WriteString("\n**Captured Response**:\n")
		g.writeCodeBlock(&details, "http", finding.Response, 1500)
	}

	if len(finding.EvidenceRefs) > 0 {
		details.WriteString("\n**Evidence References**:\n")
		for _, ref := range finding.EvidenceRefs {
			details.WriteString(fmt.Sprintf("- %s\n", g.safeInline(ref)))
		}
	}
	if len(finding.MissingEvidence) > 0 {
		details.WriteString("\n**Missing Evidence**:\n")
		for _, missing := range finding.MissingEvidence {
			details.WriteString(fmt.Sprintf("- %s\n", g.safeInline(missing)))
		}
	}

	// Only include a tool-captured reproduction command. An AI-generated command
	// is guidance, not proof that the vulnerability was reproduced.
	if g.cfg.Reporting.IncludePOC && finding.Metadata["curl"] != "" {
		details.WriteString("\n**PoC (tool-captured)**:\n")
		g.writeCodeBlock(&details, "", finding.Metadata["curl"], 500)
	}

	if len(finding.References) > 0 {
		details.WriteString("\n**References**:\n")
		for _, ref := range finding.References {
			details.WriteString(fmt.Sprintf("- %s\n", g.safeInline(ref)))
		}
	}

	details.WriteString("\n---\n\n")
	return details.String()
}

// writeSection writes a bold-labelled paragraph when the body is non-empty.
// A limit of 0 means no truncation.
func (g *Generator) writeSection(b *strings.Builder, label, body string, limit int) {
	body = g.safeBlock(body)
	if body == "" {
		return
	}
	if limit > 0 {
		body = g.truncate(body, limit)
	}
	b.WriteString(fmt.Sprintf("\n**%s**: %s\n", label, body))
}

// writeCodeBlock renders untrusted text inside a fence longer than any backtick
// run in the content. This prevents evidence or tool output from closing the
// block and injecting new report sections.
func (g *Generator) writeCodeBlock(b *strings.Builder, language, body string, limit int) {
	body = g.safeEvidence(body)
	if limit > 0 {
		body = g.truncate(body, limit)
	}
	fence := safeFence(body)
	b.WriteString(fence)
	b.WriteString(language)
	b.WriteString("\n")
	b.WriteString(body)
	b.WriteString("\n")
	b.WriteString(fence)
	b.WriteString("\n")
}

// truncate cuts s to at most n runes, appending an ellipsis when shortened.
func (g *Generator) truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func (g *Generator) filterBySeverity(findings []analyzer.ValidatedFinding, severity string) []analyzer.ValidatedFinding {
	var filtered []analyzer.ValidatedFinding
	for _, f := range findings {
		if strings.ToLower(f.Severity) == severity && f.IsValid && g.severityAllowed(severity) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func (g *Generator) filterSubmissionReady(findings []analyzer.ValidatedFinding) []analyzer.ValidatedFinding {
	var filtered []analyzer.ValidatedFinding
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical", "high", "medium":
			if f.IsValid && g.severityAllowed(f.Severity) {
				filtered = append(filtered, f)
			}
		}
	}
	return filtered
}

func (g *Generator) filterLowValue(findings []analyzer.ValidatedFinding) []analyzer.ValidatedFinding {
	var filtered []analyzer.ValidatedFinding
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "low", "info", "informational":
			if f.IsValid && g.severityAllowed(f.Severity) {
				filtered = append(filtered, f)
			}
		}
	}
	return filtered
}

func (g *Generator) safeInline(s string) string {
	s = g.safeEvidence(s)
	s = strings.Join(strings.Fields(s), " ")
	return escapeMarkdown(s)
}

func (g *Generator) safeTable(s string) string {
	return g.safeInline(s)
}

func (g *Generator) safeBlock(s string) string {
	s = strings.TrimSpace(g.safeEvidence(s))
	return escapeMarkdown(s)
}

// safeEvidence removes both configured secrets and credentials discovered at
// runtime. Replacement markers preserve only the detector type while retaining
// line feeds needed by captured HTTP exchanges and code evidence.
func (g *Generator) safeEvidence(s string) string {
	s = redaction.SanitizeURLsInText(s)
	return redaction.MaskMultiline(g.cfg.Redact(s))
}

// safeLog is the single-line counterpart to safeEvidence. Zap's console
// encoder writes message text verbatim, so paths and other operator-controlled
// strings must have controls and configured credentials removed before logging.
func (g *Generator) safeLog(s string) string {
	s = redaction.SanitizeURLsInText(s)
	return redaction.Mask(g.cfg.Redact(s))
}

// safeFindingEvidence fails closed for JavaScript secret candidates. AI-only
// detections can be opaque values that no format regex recognizes; once the
// pipeline has classified such a value as a credential candidate, the report
// must mask the complete value rather than wait for a second detector.
func (g *Generator) safeFindingEvidence(finding analyzer.ValidatedFinding) string {
	value := g.cfg.Redact(redaction.SanitizeURLsInText(finding.Evidence))
	source := strings.ToLower(finding.Metadata["source"])
	if strings.EqualFold(finding.Type, "js-analysis") || source == "regex-js-scanner" || source == "ai-js-analysis" {
		return redaction.MaskDetectorEvidence(value, finding.Metadata["pattern"]).Text
	}
	return redaction.MaskMultiline(value)
}

var markdownEscaper = strings.NewReplacer(
	"\\", "\\\\",
	"&", "&amp;",
	"`", "\\`",
	"*", "\\*",
	"_", "\\_",
	"{", "\\{",
	"}", "\\}",
	"[", "\\[",
	"]", "\\]",
	"<", "&lt;",
	">", "\\>",
	"#", "\\#",
	"!", "\\!",
	"|", "\\|",
	"~", "\\~",
)

func escapeMarkdown(s string) string {
	s = markdownEscaper.Replace(s)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		trimmed := line[indent:]
		if strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "+ ") || orderedListMarker(trimmed) {
			lines[i] = line[:indent] + "\\" + trimmed
		}
	}
	return strings.Join(lines, "\n")
}

func orderedListMarker(s string) bool {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i > 0 && i+1 < len(s) && (s[i] == '.' || s[i] == ')') && s[i+1] == ' '
}

func safeFence(s string) string {
	maxRun := 0
	current := 0
	for _, r := range s {
		if r == '`' {
			current++
			if current > maxRun {
				maxRun = current
			}
		} else {
			current = 0
		}
	}
	if maxRun < 3 {
		maxRun = 2
	}
	return strings.Repeat("`", maxRun+1)
}

func (g *Generator) severityAllowed(severity string) bool {
	if len(g.cfg.Reporting.SeverityFilter) == 0 {
		return true
	}
	for _, allowed := range g.cfg.Reporting.SeverityFilter {
		if strings.EqualFold(allowed, severity) {
			return true
		}
	}
	return false
}

func completeMark(complete bool) string {
	if complete {
		return "✅ yes"
	}
	return "⚠️ partial"
}

type findingCounts struct {
	Confirmed    int
	ManualReview int
	Rejected     int
	Critical     int
	High         int
	Medium       int
	Low          int
	Info         int
}

func confirmedOnly(findings []analyzer.ValidatedFinding) []analyzer.ValidatedFinding {
	confirmed := make([]analyzer.ValidatedFinding, 0, len(findings))
	for _, finding := range findings {
		decision := strings.ToLower(strings.TrimSpace(finding.Decision))
		if !finding.IsValid || decision != "confirmed" {
			continue
		}
		confirmed = append(confirmed, finding)
	}
	return confirmed
}

func countFindings(confirmed, manualReview, rejected []analyzer.ValidatedFinding) findingCounts {
	counts := findingCounts{
		Confirmed:    len(confirmed),
		ManualReview: len(manualReview),
		Rejected:     len(rejected),
	}
	for _, finding := range confirmed {
		switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
		case "critical":
			counts.Critical++
		case "high":
			counts.High++
		case "medium":
			counts.Medium++
		case "low":
			counts.Low++
		default:
			counts.Info++
		}
	}
	return counts
}

type coverageAssessment struct {
	Grade                    string
	NegativeConfidence       string
	ZeroFindingRiskLevel     string
	UniqueHosts              int
	UniqueRoutes             int
	UniqueQueryKeys          int
	UniqueJSFiles            int
	AttemptedWorkItems       int
	CompletedWorkItems       int
	SkippedWorkItems         int
	FailedWorkItems          int
	SubstantiveAttempted     int
	SubstantiveCompleted     int
	ScanWorkKnown            bool
	StrongNegativeConclusion bool
	Notes                    []string
}

func assessCoverage(reconResults *recon.Results, scanResults *scanner.Results, analysis *analyzer.Analysis) coverageAssessment {
	surface := measureUniqueSurface(reconResults)
	score := 0
	notes := make([]string, 0)

	switch {
	case surface.Hosts >= 100:
		score += 2
	case surface.Hosts >= 25:
		score++
	}

	switch {
	case surface.Routes >= 1000:
		score += 3
	case surface.Routes >= 250:
		score += 2
	case surface.Routes >= 75:
		score++
	default:
		notes = append(notes, "Unique route discovery is shallow; endpoint and parameter coverage may be incomplete.")
	}

	switch {
	case surface.QueryKeys >= 100:
		score += 2
	case surface.QueryKeys >= 25:
		score++
	default:
		notes = append(notes, "Few or no unique route/query-key pairs were discovered, limiting injection and reflected-XSS coverage.")
	}

	switch {
	case surface.JSFiles >= 20:
		score += 2
	case surface.JSFiles >= 5:
		score++
	default:
		notes = append(notes, "JavaScript coverage is low; client-side endpoints and secrets may be under-sampled.")
	}

	allToolsComplete := reconResults.Complete && scanResults.Complete && len(reconResults.FailedTools)+len(scanResults.FailedTools) == 0
	if allToolsComplete {
		score++
	} else {
		score -= 2
		notes = append(notes, "One or more enabled tools did not complete, so negative results have reduced confidence.")
	}

	grade := "Insufficient"
	switch {
	case score >= 8:
		grade = "Deep"
	case score >= 5:
		grade = "Moderate"
	case score >= 3:
		grade = "Limited"
	}

	attemptedWork := scanResults.Stats.TotalAttempted
	completedWork := scanResults.Stats.TotalScanned
	skippedWork := scanResults.Stats.TotalSkipped
	failedWork := scanResults.Stats.TotalFailed
	scanWorkKnown := attemptedWork > 0 || completedWork > 0 || skippedWork > 0 || failedWork > 0
	fullMeasuredWorkCoverage := scanWorkKnown && attemptedWork > 0 && completedWork == attemptedWork && skippedWork == 0 && failedWork == 0
	substantiveAttempted := scanResults.Stats.SubstantiveAttempted
	substantiveCompleted := scanResults.Stats.SubstantiveScanned
	fullSubstantiveCoverage := substantiveAttempted > 0 &&
		substantiveCompleted == substantiveAttempted &&
		scanResults.Stats.SubstantiveSkipped == 0 &&
		scanResults.Stats.SubstantiveFailed == 0
	discoveredTargets := surface.Hosts

	switch {
	case discoveredTargets == 0:
		grade = capCoverageGrade(grade, "Insufficient")
		notes = append(notes, "No in-scope targets were available to the scanner; a negative result cannot be generalized.")
	case !scanWorkKnown:
		grade = capCoverageGrade(grade, "Limited")
		notes = append(notes, "The scanner did not record attempted/completed work items; coverage and negative confidence are capped conservatively.")
	case !fullMeasuredWorkCoverage:
		eligibleWork := attemptedWork + skippedWork
		if eligibleWork <= 0 || completedWork*2 < eligibleWork {
			grade = capCoverageGrade(grade, "Insufficient")
		} else {
			grade = capCoverageGrade(grade, "Limited")
		}
		notes = append(notes, fmt.Sprintf("The scanner completed %d of %d attempted work item(s), with %d failed/incomplete and %d skipped by caps.", completedWork, attemptedWork, failedWork, skippedWork))
	}
	if !fullSubstantiveCoverage {
		grade = capCoverageGrade(grade, "Limited")
		if substantiveAttempted == 0 {
			grade = capCoverageGrade(grade, "Insufficient")
			notes = append(notes, "No substantive Nuclei or Dalfox work item completed; Httpx/Nmap activity alone cannot support a negative vulnerability claim.")
		} else {
			notes = append(notes, fmt.Sprintf("Substantive vulnerability scanners completed %d of %d attempted work item(s), with %d failed and %d skipped.", substantiveCompleted, substantiveAttempted, scanResults.Stats.SubstantiveFailed, scanResults.Stats.SubstantiveSkipped))
		}
	}
	manualReviewCount := 0
	if analysis != nil {
		manualReviewCount = len(analysis.ManualReview)
	}
	if manualReviewCount > 0 {
		grade = capCoverageGrade(grade, "Limited")
		notes = append(notes, fmt.Sprintf("%d unresolved manual-review candidate(s) prevent a strong negative conclusion.", manualReviewCount))
	}
	if !allToolsComplete {
		grade = capCoverageGrade(grade, "Limited")
	}

	strongNegativeConclusion := grade == "Deep" && allToolsComplete &&
		fullMeasuredWorkCoverage && fullSubstantiveCoverage && manualReviewCount == 0
	moderateNegativeConclusion := grade == "Moderate" && allToolsComplete &&
		fullMeasuredWorkCoverage && fullSubstantiveCoverage && manualReviewCount == 0

	negativeConfidence := "n/a"
	zeroFindingRisk := "⚪ Negative Result Not Applicable"
	if len(confirmedOnly(analysis.ValidatedFindings)) == 0 {
		switch {
		case strongNegativeConclusion:
			negativeConfidence = "high"
			zeroFindingRisk = "⚪ No Confirmed Findings (Deep Measured Coverage)"
		case moderateNegativeConclusion:
			negativeConfidence = "medium"
			zeroFindingRisk = "⚪ No Confirmed Findings (Moderate Measured Coverage)"
		case grade == "Insufficient":
			negativeConfidence = "low"
			zeroFindingRisk = "⚪ No Confirmed Findings (Insufficient Coverage)"
		default:
			negativeConfidence = "low"
			zeroFindingRisk = "⚪ No Confirmed Findings (Limited Coverage)"
		}
		if negativeConfidence == "high" {
			notes = append(notes, "High negative-result confidence describes recorded scan breadth only; it is not proof that the target is secure.")
		}
	}

	return coverageAssessment{
		Grade:                    grade,
		NegativeConfidence:       negativeConfidence,
		ZeroFindingRiskLevel:     zeroFindingRisk,
		UniqueHosts:              surface.Hosts,
		UniqueRoutes:             surface.Routes,
		UniqueQueryKeys:          surface.QueryKeys,
		UniqueJSFiles:            surface.JSFiles,
		AttemptedWorkItems:       attemptedWork,
		CompletedWorkItems:       completedWork,
		SkippedWorkItems:         skippedWork,
		FailedWorkItems:          failedWork,
		SubstantiveAttempted:     substantiveAttempted,
		SubstantiveCompleted:     substantiveCompleted,
		ScanWorkKnown:            scanWorkKnown,
		StrongNegativeConclusion: strongNegativeConclusion,
		Notes:                    notes,
	}
}

// SupportsNegativeConclusion is the shared policy used by both the Markdown
// report and the CLI summary. A clean terminal negative requires the exact same
// deep, measured, failure-free coverage that earns high negative confidence in
// the report.
func SupportsNegativeConclusion(reconResults *recon.Results, scanResults *scanner.Results, analysis *analyzer.Analysis) bool {
	if reconResults == nil || scanResults == nil || analysis == nil {
		return false
	}
	return assessCoverage(reconResults, scanResults, analysis).StrongNegativeConclusion
}

func capCoverageGrade(grade, maximum string) string {
	rank := map[string]int{"Insufficient": 0, "Limited": 1, "Moderate": 2, "Deep": 3}
	if rank[grade] > rank[maximum] {
		return maximum
	}
	return grade
}

type uniqueSurface struct {
	Hosts     int
	Routes    int
	QueryKeys int
	JSFiles   int
}

// measureUniqueSurface deliberately ignores query values. Crawlers commonly
// collect hundreds of value variants for one route; counting those variants as
// independent coverage would manufacture confidence without testing more
// attack surface.
func measureUniqueSurface(results *recon.Results) uniqueSurface {
	hosts := make(map[string]struct{})
	routes := make(map[string]struct{})
	queryKeys := make(map[string]struct{})
	jsFiles := make(map[string]struct{})

	for _, rawHost := range results.Subdomains {
		clean := redaction.SanitizeURL("https://" + strings.TrimSpace(rawHost))
		parsed, err := url.Parse(clean)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		hosts[strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))] = struct{}{}
	}

	addURL := func(raw string, javascript bool) {
		clean := redaction.SanitizeURL(raw)
		parsed, err := url.Parse(clean)
		if err != nil || parsed.Hostname() == "" {
			return
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "http" && scheme != "https" {
			return
		}
		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		if host == "" {
			return
		}
		hosts[host] = struct{}{}
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		// Scheme and port identify independently reachable services. Query values
		// and fragments never enter this route key.
		route := scheme + "://" + host
		if port := parsed.Port(); port != "" {
			route += ":" + port
		}
		route += path
		routes[route] = struct{}{}
		if javascript {
			jsFiles[route] = struct{}{}
		}

		for _, segment := range strings.FieldsFunc(parsed.RawQuery, func(r rune) bool {
			return r == '&' || r == ';'
		}) {
			key := segment
			if equals := strings.IndexByte(key, '='); equals >= 0 {
				key = key[:equals]
			}
			decoded, err := url.QueryUnescape(key)
			if err != nil || strings.TrimSpace(decoded) == "" {
				continue
			}
			queryKeys[route+"\x00"+decoded] = struct{}{}
		}
	}

	for _, raw := range results.URLs {
		addURL(raw, false)
	}
	for _, file := range results.JSFiles {
		addURL(file.URL, true)
	}

	return uniqueSurface{
		Hosts:     len(hosts),
		Routes:    len(routes),
		QueryKeys: len(queryKeys),
		JSFiles:   len(jsFiles),
	}
}

func (g *Generator) getSeverityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🟢"
	default:
		return "ℹ️"
	}
}
