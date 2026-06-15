package reporter

import (
	"fmt"
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
	if err := os.MkdirAll(g.cfg.Reporting.OutputDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("bug_bounty_report_%s.md", timestamp)
	outputPath := filepath.Join(g.cfg.Reporting.OutputDir, filename)

	content := g.generateMarkdownReport(reconResults, scanResults, analysis)

	if err := os.WriteFile(outputPath, []byte(content), 0600); err != nil {
		return "", fmt.Errorf("failed to write report: %w", err)
	}

	g.log.Infof("Report generated successfully: %s", outputPath)
	return outputPath, nil
}

func (g *Generator) generateMarkdownReport(reconResults *recon.Results, scanResults *scanner.Results, analysis *analyzer.Analysis) string {
	var report strings.Builder

	target := strings.Join(g.cfg.Target.Domains, ", ")

	// Header
	report.WriteString(fmt.Sprintf("# Bug Bounty Report — %s\n\n", target))
	report.WriteString(fmt.Sprintf("**Date**: %s  \n", time.Now().Format("2006-01-02 15:04")))
	report.WriteString(fmt.Sprintf("**Target**: %s  \n", target))
	report.WriteString(fmt.Sprintf("**Subdomains Found**: %d  \n", len(reconResults.Subdomains)))
	report.WriteString(fmt.Sprintf("**URLs Discovered**: %d  \n", len(reconResults.URLs)))
	report.WriteString(fmt.Sprintf("**Reconnaissance Complete**: %t  \n", reconResults.Complete))
	report.WriteString(fmt.Sprintf("**Vulnerability Scan Complete**: %t  \n", scanResults.Complete))
	report.WriteString(fmt.Sprintf("**Raw Tool Candidates**: %d  \n", len(scanResults.Findings)))
	report.WriteString(fmt.Sprintf("**Confirmed Findings**: %d  \n", len(analysis.ValidatedFindings)))
	report.WriteString(fmt.Sprintf("**Manual Review Candidates**: %d  \n\n", len(analysis.ManualReview)))

	// Executive Summary with Risk Score
	// Weight JS-analysis-only findings at 50% to prevent inflated scores.
	riskScore := 0
	for _, vf := range analysis.ValidatedFindings {
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
	riskLevel := "🟢 Low Risk"
	if !reconResults.Complete || !scanResults.Complete {
		riskLevel = "⚪ Partial Assessment"
	} else if riskScore >= 30 {
		riskLevel = "🔴 Critical Risk"
	} else if riskScore >= 15 {
		riskLevel = "🟠 High Risk"
	} else if riskScore >= 5 {
		riskLevel = "🟡 Medium Risk"
	}

	report.WriteString("## Executive Summary\n\n")
	report.WriteString(fmt.Sprintf("**Overall Risk Level**: %s (score: %d)  \n", riskLevel, riskScore))
	report.WriteString(fmt.Sprintf("**Validation-Pipeline Findings**: %d high-signal findings  \n", analysis.Stats.Validated))
	report.WriteString(fmt.Sprintf("**Manual Review Candidates**: %d  \n", analysis.Stats.ManualReview))
	report.WriteString(fmt.Sprintf("**False Positives Filtered**: %d  \n", analysis.Stats.FalsePositives))
	report.WriteString(fmt.Sprintf("**Attack Surface**: %d subdomains discovered  \n\n", len(reconResults.Subdomains)))
	if !scanResults.Complete && len(scanResults.Findings) == 0 {
		report.WriteString("> ⚠️ **No vulnerability candidates were produced by an incomplete scan.** This is a coverage failure, not evidence that the target is secure.  \n\n")
	}
	if len(reconResults.FailedTools)+len(scanResults.FailedTools) > 0 {
		report.WriteString("**Failed Optional Tools**: ")
		failed := append([]string(nil), reconResults.FailedTools...)
		failed = append(failed, scanResults.FailedTools...)
		report.WriteString(strings.Join(failed, ", ") + "  \n\n")
	}

	if analysis.Stats.Critical > 0 {
		report.WriteString("> ⚠️ **CRITICAL FINDINGS DETECTED** — Immediate remediation recommended.  \n\n")
	}

	// Severity Summary
	report.WriteString("## Summary\n\n")
	report.WriteString("| Severity | Count |\n")
	report.WriteString("|----------|-------|\n")
	if analysis.Stats.Critical > 0 {
		report.WriteString(fmt.Sprintf("| 🔴 Critical | %d |\n", analysis.Stats.Critical))
	}
	if analysis.Stats.High > 0 {
		report.WriteString(fmt.Sprintf("| 🟠 High | %d |\n", analysis.Stats.High))
	}
	if analysis.Stats.Medium > 0 {
		report.WriteString(fmt.Sprintf("| 🟡 Medium | %d |\n", analysis.Stats.Medium))
	}
	if analysis.Stats.Low > 0 {
		report.WriteString(fmt.Sprintf("| 🟢 Low | %d |\n", analysis.Stats.Low))
	}
	report.WriteString("\n")

	// Findings by severity (Critical → High → Medium → Low)
	// Skip info entirely
	severities := []struct {
		name  string
		emoji string
	}{
		{"critical", "🔴"},
		{"high", "🟠"},
		{"medium", "🟡"},
		{"low", "🟢"},
	}

	findingIndex := 1
	for _, sev := range severities {
		filtered := g.filterBySeverity(analysis.ValidatedFindings, sev.name)
		if len(filtered) == 0 {
			continue
		}

		report.WriteString(fmt.Sprintf("## %s %s Severity\n\n", sev.emoji, cases.Title(language.English).String(sev.name)))

		for _, f := range filtered {
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

	// Subdomains discovered
	if len(reconResults.Subdomains) > 0 {
		report.WriteString("## Subdomains Discovered\n\n")
		report.WriteString("```\n")
		for _, sub := range reconResults.Subdomains {
			report.WriteString(sub + "\n")
		}
		report.WriteString("```\n\n")
	}

	// Footer
	report.WriteString("---\n\n")
	report.WriteString("*Generated by Bug Bounty AI Agent*\n")

	return report.String()
}

func (g *Generator) formatFinding(index int, finding analyzer.ValidatedFinding) string {
	var details strings.Builder

	emoji := g.getSeverityEmoji(finding.Severity)
	details.WriteString(fmt.Sprintf("### %d. %s %s\n\n", index, emoji, finding.Title))

	if finding.URL != "" {
		details.WriteString(fmt.Sprintf("- **URL**: `%s`\n", g.cfg.Redact(finding.URL)))
	}
	details.WriteString(fmt.Sprintf("- **Severity**: %s\n", strings.ToUpper(finding.Severity)))
	if finding.Decision != "" {
		details.WriteString(fmt.Sprintf("- **Decision**: %s\n", finding.Decision))
	}
	if finding.Type != "" {
		details.WriteString(fmt.Sprintf("- **Type**: %s\n", finding.Type))
	}
	details.WriteString(fmt.Sprintf("- **Validation Confidence**: %.2f\n", finding.Confidence))
	if finding.CVE != "" {
		details.WriteString(fmt.Sprintf("- **CVE**: %s\n", finding.CVE))
	}
	if finding.CVSS > 0 {
		details.WriteString(fmt.Sprintf("- **CVSS**: %.1f\n", finding.CVSS))
	}

	// Evidence
	if finding.Evidence != "" {
		evidence := g.cfg.Redact(finding.Evidence)
		if len(evidence) > 300 {
			evidence = evidence[:300] + "..."
		}
		details.WriteString(fmt.Sprintf("\n**Evidence**:\n```\n%s\n```\n", evidence))
	}
	if finding.Request != "" {
		request := g.cfg.Redact(finding.Request)
		if len(request) > 800 {
			request = request[:800] + "..."
		}
		details.WriteString(fmt.Sprintf("\n**Captured Request**:\n```http\n%s\n```\n", request))
	}
	if finding.Response != "" {
		response := g.cfg.Redact(finding.Response)
		if len(response) > 800 {
			response = response[:800] + "..."
		}
		details.WriteString(fmt.Sprintf("\n**Captured Response**:\n```http\n%s\n```\n", response))
	}

	// AI Analysis (brief)
	if finding.AIAnalysis != "" {
		analysis := g.cfg.Redact(finding.AIAnalysis)
		if len(analysis) > 200 {
			analysis = analysis[:200] + "..."
		}
		details.WriteString(fmt.Sprintf("\n**Analysis**: %s\n", analysis))
	}
	if len(finding.EvidenceRefs) > 0 {
		details.WriteString("\n**Evidence References**:\n")
		for _, ref := range finding.EvidenceRefs {
			details.WriteString(fmt.Sprintf("- %s\n", g.cfg.Redact(ref)))
		}
	}
	if len(finding.MissingEvidence) > 0 {
		details.WriteString("\n**Missing Evidence**:\n")
		for _, missing := range finding.MissingEvidence {
			details.WriteString(fmt.Sprintf("- %s\n", g.cfg.Redact(missing)))
		}
	}

	// Only include a tool-captured reproduction command. An AI-generated command
	// is guidance, not proof that the vulnerability was reproduced.
	if g.cfg.Reporting.IncludePOC && finding.Metadata["curl"] != "" {
		poc := g.cfg.Redact(finding.Metadata["curl"])
		if len(poc) > 300 {
			poc = poc[:300] + "..."
		}
		details.WriteString(fmt.Sprintf("\n**PoC**:\n```\n%s\n```\n", poc))
	}

	details.WriteString("\n---\n\n")
	return details.String()
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
