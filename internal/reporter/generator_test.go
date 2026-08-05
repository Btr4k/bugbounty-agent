package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/analyzer"
	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/recon"
	"github.com/Btr4k/bugbounty-agent/internal/scanner"
)

func TestGenerateRejectsNilInputs(t *testing.T) {
	generator := NewGenerator(&config.Config{Reporting: config.ReportingConfig{OutputDir: t.TempDir()}}, nil)
	if _, err := generator.Generate(nil, &scanner.Results{}, &analyzer.Analysis{}); err == nil {
		t.Fatal("nil recon results must be rejected")
	}
	if _, err := (*Generator)(nil).Generate(&recon.Results{}, &scanner.Results{}, &analyzer.Analysis{}); err == nil {
		t.Fatal("nil generator must be rejected")
	}
}

func TestGenerateIncludesOnlyValidatedFindingsAndUsesPrivatePermissions(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	outputDir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const querySecret = "opaque-query-secret-123"
	cfg := &config.Config{
		Target:         config.TargetConfig{Domains: []string{"example.com"}},
		Authentication: config.AuthenticationConfig{Headers: map[string]string{"Authorization": "Bearer secret-session-value"}},
		Reporting:      config.ReportingConfig{OutputDir: outputDir, IncludePOC: true},
	}
	validated := analyzer.ValidatedFinding{
		Finding: scanner.Finding{
			Title:    "Validated finding",
			Severity: "high",
			URL:      "https://example.com/search?token=" + querySecret + "#private",
			Request:  "GET /download?signature=" + querySecret + " HTTP/1.1\r\nAuthorization: Bearer secret-session-value",
			Response: "HTTP/1.1 200 OK\r\n\r\nsensitive proof",
			Metadata: map[string]string{"curl": "curl -H 'Authorization: Bearer secret-session-value' 'https://example.com/search?token=" + querySecret + "#private'"},
		},
		IsValid:        true,
		Decision:       "confirmed",
		Confidence:     0.95,
		EvidenceRefs:   []string{"captured response"},
		ProofOfConcept: "AI-generated command that must not be shown",
		UnverifiedScannerMetadata: []string{
			"CVE (scanner/template claim, not independently verified): CVE-2099-0001",
		},
	}
	manual := analyzer.ValidatedFinding{
		Finding:         scanner.Finding{Title: "Needs control request", Severity: "medium", Evidence: "candidate evidence"},
		Decision:        "manual-review",
		Confidence:      0.8,
		MissingEvidence: []string{"control request"},
	}
	raw := scanner.Finding{Title: "Unvalidated raw finding", Severity: "critical", URL: "https://example.com"}

	path, err := NewGenerator(cfg, log).Generate(
		&recon.Results{
			Subdomains:  []string{"example.com"},
			Complete:    false,
			FailedTools: []string{"certificate-transparency"},
		},
		&scanner.Results{Findings: []scanner.Finding{raw}, Complete: true},
		&analyzer.Analysis{
			ValidatedFindings: []analyzer.ValidatedFinding{validated},
			ManualReview:      []analyzer.ValidatedFinding{manual},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "Validated finding") {
		t.Fatal("validated finding missing from report")
	}
	if strings.Contains(string(content), "Unvalidated raw finding") {
		t.Fatal("unvalidated finding leaked into report")
	}
	if strings.Contains(string(content), "AI-generated command") {
		t.Fatal("AI-generated PoC leaked into report")
	}
	if !strings.Contains(string(content), "curl -H") || !strings.Contains(string(content), "https://example.com") {
		t.Fatal("redacted tool-captured reproduction command missing from report")
	}
	if !strings.Contains(string(content), "**Confidence** | 0.95") ||
		!strings.Contains(string(content), "Captured Request") ||
		!strings.Contains(string(content), "Captured Response") ||
		!strings.Contains(string(content), "Submission Ready Findings") ||
		!strings.Contains(string(content), "Manual Review Required") ||
		!strings.Contains(string(content), "Coverage Qualifier") ||
		!strings.Contains(string(content), "certificate-transparency") {
		t.Fatal("report must include confidence, captured exchange, and manual review")
	}
	if strings.Contains(string(content), "secret-session-value") || !strings.Contains(string(content), "[REDACTED]") {
		t.Fatal("authentication secret leaked or was not visibly redacted")
	}
	if strings.Contains(string(content), querySecret) || strings.Contains(string(content), "#private") {
		t.Fatal("URL query or fragment secret leaked into report")
	}
	if !strings.Contains(string(content), "token=") || !strings.Contains(string(content), "signature=") {
		t.Fatal("sanitized report should preserve query parameter names")
	}
	if !strings.Contains(string(content), "Unverified Scanner/Template Metadata") ||
		!strings.Contains(string(content), "CVE-2099-0001") ||
		!strings.Contains(string(content), "not independently verified") {
		t.Fatal("scanner/template metadata was not explicitly labelled as unverified")
	}
	dirInfo, err := os.Stat(outputDir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("report directory permissions = %o, want 700", dirInfo.Mode().Perm())
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("report permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestGenerateRefusesBroadExistingOutputDirectoryWithoutChangingIt(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	outputDir := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(outputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(outputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Reporting: config.ReportingConfig{OutputDir: outputDir}}
	_, err := NewGenerator(cfg, log).Generate(&recon.Results{}, &scanner.Results{}, &analyzer.Analysis{})
	if err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("broad output directory was not rejected: %v", err)
	}
	info, statErr := os.Stat(outputDir)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("pre-existing directory mode was changed to %o", info.Mode().Perm())
	}
}

func TestGenerateLabelsZeroFindingsWithLimitedCoverage(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	outputDir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(outputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Target:    config.TargetConfig{Domains: []string{"example.com"}},
		Reporting: config.ReportingConfig{OutputDir: outputDir},
	}

	reconResults := &recon.Results{
		Subdomains: make([]string, 62),
		URLs: []string{
			"https://example.com/",
			"https://example.com/search?q=test",
			"https://api.example.com/users",
		},
		JSFiles:  make([]recon.JSFile, 11),
		Complete: true,
	}
	for i := range reconResults.Subdomains {
		reconResults.Subdomains[i] = fmt.Sprintf("s%d.example.com", i)
	}
	for i := range reconResults.JSFiles {
		reconResults.JSFiles[i].URL = fmt.Sprintf("https://static.example.com/assets/%d.js?v=ignored", i)
	}

	path, err := NewGenerator(cfg, log).Generate(
		reconResults,
		&scanner.Results{
			Complete: true,
			Stats: scanner.ScanStats{
				TotalAttempted:       len(reconResults.Subdomains),
				TotalScanned:         len(reconResults.Subdomains),
				SubstantiveAttempted: len(reconResults.Subdomains),
				SubstantiveScanned:   len(reconResults.Subdomains),
			},
		},
		&analyzer.Analysis{},
	)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	report := string(content)
	if !strings.Contains(report, "No Confirmed Findings (Limited Coverage)") ||
		!strings.Contains(report, "**Coverage Grade**: Limited") ||
		!strings.Contains(report, "**Negative Result Confidence**: low") ||
		!strings.Contains(report, "Unique route/query-key pairs discovered | 1") ||
		!strings.Contains(report, "not proof that the target is secure") {
		t.Fatalf("limited zero-finding report did not communicate coverage uncertainty:\n%s", report)
	}
}

func TestMeasureUniqueSurfaceIgnoresQueryValuesFragmentsAndDuplicates(t *testing.T) {
	metrics := measureUniqueSurface(&recon.Results{
		Subdomains: []string{"example.com", "EXAMPLE.COM", "example.com."},
		URLs: []string{
			"https://example.com/search?q=one#top",
			"https://example.com/search?q=two#bottom",
			"https://example.com/static/app.js?v=1",
			"https://example.com/static/app.js?v=2",
			"https://example.com/no-query",
		},
		JSFiles: []recon.JSFile{
			{URL: "https://example.com/static/app.js?v=1"},
			{URL: "https://example.com/static/app.js?v=2#copy"},
		},
	})
	if metrics.Hosts != 1 || metrics.Routes != 3 || metrics.QueryKeys != 2 || metrics.JSFiles != 1 {
		t.Fatalf("unexpected unique surface metrics: %#v", metrics)
	}
}

func TestQueryValueVariantsCannotManufactureDeepCoverage(t *testing.T) {
	urls := make([]string, 1000)
	jsFiles := make([]recon.JSFile, 20)
	for i := range urls {
		urls[i] = fmt.Sprintf("https://example.com/search?q=value-%d#fragment-%d", i, i)
	}
	for i := range jsFiles {
		jsFiles[i].URL = fmt.Sprintf("https://example.com/assets/%d.js?cache=%d", i, i)
	}
	reconResults := &recon.Results{
		Subdomains: []string{"example.com"},
		URLs:       urls,
		JSFiles:    jsFiles,
		Complete:   true,
	}
	scanResults := &scanner.Results{
		Complete: true,
		Stats: scanner.ScanStats{
			TotalAttempted:       1,
			TotalScanned:         1,
			SubstantiveAttempted: 1,
			SubstantiveScanned:   1,
		},
	}
	assessment := assessCoverage(reconResults, scanResults, &analyzer.Analysis{})
	if assessment.Grade == "Deep" || assessment.NegativeConfidence == "high" || assessment.StrongNegativeConclusion {
		t.Fatalf("query-value variants manufactured strong coverage: %#v", assessment)
	}
}

func TestInsufficientCoverageNeverReportsLowRisk(t *testing.T) {
	g := &Generator{cfg: &config.Config{Target: config.TargetConfig{Domains: []string{"example.com"}}}}
	confirmed := analyzer.ValidatedFinding{
		Finding:  scanner.Finding{Title: "Low-severity observation", Severity: "low"},
		IsValid:  true,
		Decision: "confirmed",
	}

	report := g.generateMarkdownReport(
		&recon.Results{Subdomains: []string{"example.com"}, Complete: true},
		&scanner.Results{Complete: true},
		&analyzer.Analysis{ValidatedFindings: []analyzer.ValidatedFinding{confirmed}},
	)

	if strings.Contains(report, "Low Risk") || strings.Contains(report, "Low Observed Risk") {
		t.Fatalf("insufficient coverage was mislabeled as low risk:\n%s", report)
	}
	if !strings.Contains(report, "Insufficient Coverage — Low Observed Severity") {
		t.Fatalf("expected a coverage-limited observed-severity label:\n%s", report)
	}
}

func TestPartialCoverageNeverReportsLowRisk(t *testing.T) {
	g := &Generator{cfg: &config.Config{Target: config.TargetConfig{Domains: []string{"example.com"}}}}
	confirmed := analyzer.ValidatedFinding{
		Finding:  scanner.Finding{Title: "Low-severity observation", Severity: "low"},
		IsValid:  true,
		Decision: "confirmed",
	}

	report := g.generateMarkdownReport(
		&recon.Results{Subdomains: []string{"example.com"}, Complete: false},
		&scanner.Results{Complete: true},
		&analyzer.Analysis{ValidatedFindings: []analyzer.ValidatedFinding{confirmed}},
	)

	if strings.Contains(report, "Low Risk") || strings.Contains(report, "Low Observed Risk") {
		t.Fatalf("partial coverage was mislabeled as low risk:\n%s", report)
	}
	if !strings.Contains(report, "Coverage Qualifier") {
		t.Fatalf("expected an explicit partial-assessment label:\n%s", report)
	}
}

func TestNegativeConfidenceRequiresScannerReportedCoverage(t *testing.T) {
	subdomains := make([]string, 100)
	urls := make([]string, 1000)
	for i := range subdomains {
		subdomains[i] = fmt.Sprintf("s%d.example.com", i)
	}
	for i := range urls {
		urls[i] = fmt.Sprintf("https://s%d.example.com/api/item?id=%d", i%100, i)
	}
	reconResults := &recon.Results{
		Subdomains: subdomains,
		URLs:       urls,
		JSFiles:    make([]recon.JSFile, 20),
		Complete:   true,
	}
	for i := range reconResults.JSFiles {
		reconResults.JSFiles[i].URL = fmt.Sprintf("https://static.example.com/assets/%d.js", i)
	}
	analysis := &analyzer.Analysis{}

	unknown := assessCoverage(reconResults, &scanner.Results{Complete: true}, analysis)
	if unknown.Grade != "Insufficient" || unknown.NegativeConfidence != "low" || unknown.ScanWorkKnown {
		t.Fatalf("unmeasured scan coverage must be capped conservatively: %#v", unknown)
	}

	partial := assessCoverage(reconResults, &scanner.Results{
		Complete: true,
		Stats:    scanner.ScanStats{TotalAttempted: len(subdomains), TotalScanned: 10},
	}, analysis)
	if partial.Grade != "Insufficient" || partial.NegativeConfidence != "low" {
		t.Fatalf("partial measured scan coverage must remain conservative: %#v", partial)
	}

	measured := assessCoverage(reconResults, &scanner.Results{
		Complete: true,
		Stats: scanner.ScanStats{
			TotalAttempted:       len(subdomains),
			TotalScanned:         len(subdomains),
			SubstantiveAttempted: len(subdomains),
			SubstantiveScanned:   len(subdomains),
		},
	}, analysis)
	if measured.Grade != "Deep" || measured.NegativeConfidence != "high" || !measured.ScanWorkKnown {
		t.Fatalf("measured complete scan coverage was not used: %#v", measured)
	}
}

func TestConfirmedCriticalSeveritySurvivesPartialCoverage(t *testing.T) {
	g := &Generator{cfg: &config.Config{Target: config.TargetConfig{Domains: []string{"example.com"}}}}
	critical := analyzer.ValidatedFinding{
		Finding:  scanner.Finding{Title: "Confirmed critical issue", Severity: "critical"},
		IsValid:  true,
		Decision: "confirmed",
	}

	report := g.generateMarkdownReport(
		&recon.Results{Subdomains: []string{"example.com"}, Complete: false},
		&scanner.Results{Complete: false},
		&analyzer.Analysis{ValidatedFindings: []analyzer.ValidatedFinding{critical}},
	)

	if !strings.Contains(report, "**Overall Risk Level**: 🔴 Critical Risk") {
		t.Fatalf("partial coverage suppressed a confirmed critical severity:\n%s", report)
	}
	if !strings.Contains(report, "**Coverage Qualifier**: Partial / inconclusive") {
		t.Fatalf("partial coverage qualifier missing from critical report:\n%s", report)
	}
}

func TestManualReviewBlocksStrongNegativeConclusion(t *testing.T) {
	reconResults := deepReconCoverageFixture()
	manual := analyzer.ValidatedFinding{
		Finding:  scanner.Finding{Title: "Unresolved candidate", Severity: "high"},
		Decision: "manual-review",
	}
	assessment := assessCoverage(reconResults, &scanner.Results{
		Complete: true,
		Stats: scanner.ScanStats{
			TotalAttempted:       100,
			TotalScanned:         100,
			SubstantiveAttempted: 100,
			SubstantiveScanned:   100,
		},
	}, &analyzer.Analysis{ManualReview: []analyzer.ValidatedFinding{manual}})

	if assessment.Grade != "Limited" || assessment.NegativeConfidence != "low" {
		t.Fatalf("manual review must cap a negative conclusion: %#v", assessment)
	}
	if !strings.Contains(strings.Join(assessment.Notes, " "), "prevent a strong negative conclusion") {
		t.Fatalf("manual-review limitation was not explained: %#v", assessment.Notes)
	}
}

func TestHttpxOnlyCoverageIsInsufficientForNegativeConclusion(t *testing.T) {
	assessment := assessCoverage(deepReconCoverageFixture(), &scanner.Results{
		Complete: true,
		Stats: scanner.ScanStats{
			TotalAttempted: 100,
			TotalScanned:   100,
			// No substantive Nuclei or Dalfox work was attempted. These totals
			// therefore model complete Httpx/Nmap-only activity.
		},
	}, &analyzer.Analysis{})

	if assessment.Grade != "Insufficient" || assessment.NegativeConfidence != "low" {
		t.Fatalf("non-substantive scanner activity supported a strong negative: %#v", assessment)
	}
	if !strings.Contains(strings.Join(assessment.Notes, " "), "Httpx/Nmap activity alone") {
		t.Fatalf("missing explanation for non-substantive coverage: %#v", assessment.Notes)
	}
}

func deepReconCoverageFixture() *recon.Results {
	subdomains := make([]string, 100)
	urls := make([]string, 1000)
	for i := range subdomains {
		subdomains[i] = fmt.Sprintf("s%d.example.com", i)
	}
	for i := range urls {
		urls[i] = fmt.Sprintf("https://s%d.example.com/api/item?id=%d", i%100, i)
	}
	result := &recon.Results{
		Subdomains: subdomains,
		URLs:       urls,
		JSFiles:    make([]recon.JSFile, 20),
		Complete:   true,
	}
	for i := range result.JSFiles {
		result.JSFiles[i].URL = fmt.Sprintf("https://static.example.com/assets/%d.js", i)
	}
	return result
}

func TestCandidateDispositionUsesActualSlicesNotCachedStats(t *testing.T) {
	g := &Generator{cfg: &config.Config{Target: config.TargetConfig{Domains: []string{"example.com"}}}}
	confirmed := analyzer.ValidatedFinding{
		Finding:  scanner.Finding{Title: "Confirmed", Severity: "high"},
		IsValid:  true,
		Decision: "confirmed",
	}
	manual := analyzer.ValidatedFinding{Finding: scanner.Finding{Title: "Manual"}, Decision: "manual-review"}
	rejected := analyzer.ValidatedFinding{Finding: scanner.Finding{Title: "Rejected"}, Decision: "rejected"}

	report := g.generateMarkdownReport(
		&recon.Results{Subdomains: []string{"example.com"}, Complete: true},
		&scanner.Results{Findings: []scanner.Finding{{Title: "raw-1"}, {Title: "raw-2"}}, Complete: true},
		&analyzer.Analysis{
			ValidatedFindings: []analyzer.ValidatedFinding{confirmed},
			ManualReview:      []analyzer.ValidatedFinding{manual},
			FalsePositives:    []analyzer.ValidatedFinding{rejected},
			Stats: analyzer.Statistics{
				Validated:      99,
				ManualReview:   98,
				FalsePositives: 97,
			},
		},
	)

	for _, expected := range []string{
		"| Raw tool candidates (pre-validation) | 2 |",
		"| Confirmed findings | 1 |",
		"| Manual review required | 1 |",
		"| Rejected / not reportable | 1 |",
	} {
		if !strings.Contains(report, expected) {
			t.Errorf("candidate disposition missing %q:\n%s", expected, report)
		}
	}
	if strings.Contains(report, "| 99 |") || strings.Contains(report, "| 98 |") || strings.Contains(report, "| 97 |") {
		t.Fatalf("stale cached analysis stats leaked into report:\n%s", report)
	}
}

func TestOnlyExplicitConfirmedDecisionsAreReportedAsConfirmed(t *testing.T) {
	g := &Generator{cfg: &config.Config{Target: config.TargetConfig{Domains: []string{"example.com"}}}}
	findings := []analyzer.ValidatedFinding{
		{Finding: scanner.Finding{Title: "Explicitly confirmed", Severity: "high"}, IsValid: true, Decision: "confirmed"},
		{Finding: scanner.Finding{Title: "Missing decision", Severity: "critical"}, IsValid: true},
		{Finding: scanner.Finding{Title: "Manual record", Severity: "critical"}, IsValid: true, Decision: "manual-review"},
		{Finding: scanner.Finding{Title: "Forged decision", Severity: "critical"}, IsValid: true, Decision: "confirmed|forged"},
		{Finding: scanner.Finding{Title: "Invalid record", Severity: "critical"}, Decision: "confirmed"},
	}

	report := g.generateMarkdownReport(
		&recon.Results{Subdomains: []string{"example.com"}, Complete: true},
		&scanner.Results{Findings: []scanner.Finding{{Title: "UNVALIDATED-RAW-DETAIL"}}, Complete: true},
		&analyzer.Analysis{ValidatedFindings: findings},
	)

	if !strings.Contains(report, "Explicitly confirmed") || !strings.Contains(report, "**Confirmed Findings**: 1") {
		t.Fatalf("explicit confirmation was not reported correctly:\n%s", report)
	}
	for _, forbidden := range []string{"UNVALIDATED-RAW-DETAIL", "Missing decision", "Manual record", "Forged decision", "Invalid record"} {
		if strings.Contains(report, forbidden) {
			t.Errorf("non-confirmed record %q was rendered as a confirmed finding:\n%s", forbidden, report)
		}
	}
}

func TestReportMasksDiscoveredCredentialsWithReviewMetadata(t *testing.T) {
	g := &Generator{cfg: &config.Config{
		Target:    config.TargetConfig{Domains: []string{"example.com"}},
		Reporting: config.ReportingConfig{IncludePOC: true},
	}}
	const discovered = "AKIAIOSFODNN7EXAMPLE"
	finding := analyzer.ValidatedFinding{
		Finding: scanner.Finding{
			Title:       "Exposed AWS credential",
			Description: "The scanner observed " + discovered,
			Severity:    "high",
			Type:        "js-analysis",
			Evidence:    discovered,
			Request:     "GET /app.js HTTP/1.1\r\nX-Debug-Key: " + discovered,
			Response:    "HTTP/1.1 200 OK\r\n\r\nconst key = '" + discovered + "'",
			Metadata:    map[string]string{"curl": "curl -H 'X-Key: " + discovered + "' https://example.com/app.js"},
		},
		IsValid:  true,
		Decision: "confirmed",
	}

	report := g.generateMarkdownReport(
		&recon.Results{Subdomains: []string{"example.com"}, Complete: true},
		&scanner.Results{Complete: true},
		&analyzer.Analysis{ValidatedFindings: []analyzer.ValidatedFinding{finding}},
	)

	if strings.Contains(report, discovered) {
		t.Fatalf("discovered credential leaked into report:\n%s", report)
	}
	for _, metadata := range []string{"type=aws_access_key"} {
		if !strings.Contains(report, metadata) {
			t.Errorf("safe review metadata %q missing after credential masking:\n%s", metadata, report)
		}
	}
	for _, forbidden := range []string{"fingerprint=", "last4="} {
		if strings.Contains(report, forbidden) {
			t.Errorf("report exposed correlation metadata %q:\n%s", forbidden, report)
		}
	}
}

func TestReportMasksOpaqueAIOnlySecretCandidate(t *testing.T) {
	g := &Generator{cfg: &config.Config{}}
	const opaque = "opaque-vendor-secret-with-no-known-prefix"
	finding := analyzer.ValidatedFinding{
		Finding: scanner.Finding{
			Title:    "AI secret candidate",
			Type:     "js-analysis",
			Evidence: opaque,
			Metadata: map[string]string{"source": "ai-js-analysis"},
		},
		Decision: "manual-review",
	}

	rendered := g.formatFinding(1, finding)
	if strings.Contains(rendered, opaque) {
		t.Fatalf("opaque AI-only credential leaked into report: %s", rendered)
	}
	if !strings.Contains(rendered, "type=generic_secret") {
		t.Fatalf("safe generic credential marker missing: %s", rendered)
	}
}

func TestSafeLogRemovesConfiguredSecretsAndTerminalControls(t *testing.T) {
	const secret = "opaque-configured-path-secret"
	g := &Generator{cfg: &config.Config{
		Authentication: config.AuthenticationConfig{Headers: map[string]string{"X-Session": secret}},
	}}
	got := g.safeLog("reports/" + secret + "\nforged\x1b[31m/report.md")
	if strings.Contains(got, secret) || strings.ContainsAny(got, "\n\r\x1b") {
		t.Fatalf("unsafe report path survived log sanitization: %q", got)
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("configured secret was not visibly redacted: %q", got)
	}
}

func TestWritePrivateFileAtomicRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.md")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateFileAtomic(path, []byte("new")); !os.IsExist(err) {
		t.Fatalf("WritePrivateFileAtomic() error = %v, want an exists error", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0644 {
		t.Fatalf("existing report permissions changed to %o", info.Mode().Perm())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old" {
		t.Fatalf("existing report content = %q, want %q", content, "old")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "report.md" {
		t.Fatalf("temporary artifacts remained after collision: %#v", entries)
	}
}

func TestWritePrivateFileAtomicPublishesPrivateCompleteFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.md")
	content := []byte("complete report")

	if err := WritePrivateFileAtomic(path, content); err != nil {
		t.Fatal(err)
	}
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(written) != string(content) {
		t.Fatalf("report content = %q, want %q", written, content)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("report permissions = %o, want 600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "report.md" {
		t.Fatalf("temporary artifacts remained after publish: %#v", entries)
	}
}

func TestReportSanitizesControlsAndUntrustedMarkdown(t *testing.T) {
	g := &Generator{cfg: &config.Config{
		Target:    config.TargetConfig{Domains: []string{"example.com\n# forged-target\x00"}},
		Reporting: config.ReportingConfig{IncludePOC: true},
	}}
	malicious := analyzer.ValidatedFinding{
		Finding: scanner.Finding{
			Title:       "Finding\n# forged-heading | [click](javascript:alert(1))\x00",
			Description: "# injected\n<script>alert(1)</script>\x1b[31m",
			Severity:    "high",
			URL:         "https://example.com/x|fake\nrow",
			Evidence:    "proof\n```\n# outside-fence\x00",
			Request:     "GET / HTTP/1.1\r\nX-Test: ok\x00",
			Metadata:    map[string]string{"curl": "curl example.com\n```\n# forged-poc"},
		},
		IsValid:      true,
		Decision:     "confirmed",
		EvidenceRefs: []string{"captured\n# forged-ref"},
	}

	report := g.generateMarkdownReport(
		&recon.Results{Subdomains: []string{"example.com\n```\n# forged-subdomain"}, Complete: true},
		&scanner.Results{Complete: true},
		&analyzer.Analysis{ValidatedFindings: []analyzer.ValidatedFinding{malicious}},
	)

	for _, forbidden := range []string{"\x00", "\x1b", "\r", "\n# forged-heading", "\n# forged-target", "<script>", "[click](javascript:"} {
		if strings.Contains(report, forbidden) {
			t.Errorf("unsafe report content %q survived sanitization:\n%s", forbidden, report)
		}
	}
	for _, expected := range []string{"\\# forged-heading", "\\[click\\](javascript:alert(1))", "&lt;script\\>", "````\nproof\n```"} {
		if !strings.Contains(report, expected) {
			t.Errorf("expected sanitized representation %q:\n%s", expected, report)
		}
	}
}
