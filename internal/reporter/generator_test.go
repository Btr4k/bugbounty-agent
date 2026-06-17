package reporter

import (
	"os"
	"strings"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/analyzer"
	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/recon"
	"github.com/Btr4k/bugbounty-agent/internal/scanner"
)

func TestGenerateIncludesOnlyValidatedFindingsAndUsesPrivatePermissions(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	cfg := &config.Config{
		Target:         config.TargetConfig{Domains: []string{"example.com"}},
		Authentication: config.AuthenticationConfig{Headers: map[string]string{"Authorization": "Bearer secret-session-value"}},
		Reporting:      config.ReportingConfig{OutputDir: t.TempDir(), IncludePOC: true},
	}
	validated := analyzer.ValidatedFinding{
		Finding: scanner.Finding{
			Title:    "Validated finding",
			Severity: "high",
			URL:      "https://example.com",
			Request:  "GET / HTTP/1.1\r\nAuthorization: Bearer secret-session-value",
			Response: "HTTP/1.1 200 OK\r\n\r\nsensitive proof",
			Metadata: map[string]string{"curl": "curl -H 'Authorization: Bearer secret-session-value' https://example.com"},
		},
		IsValid:        true,
		Decision:       "confirmed",
		Confidence:     0.95,
		EvidenceRefs:   []string{"captured response"},
		ProofOfConcept: "AI-generated command that must not be shown",
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
		!strings.Contains(string(content), "Partial Assessment") ||
		!strings.Contains(string(content), "certificate-transparency") {
		t.Fatal("report must include confidence, captured exchange, and manual review")
	}
	if strings.Contains(string(content), "secret-session-value") || !strings.Contains(string(content), "[REDACTED]") {
		t.Fatal("authentication secret leaked or was not visibly redacted")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("report permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestGenerateLabelsZeroFindingsWithLimitedCoverage(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	cfg := &config.Config{
		Target:    config.TargetConfig{Domains: []string{"example.com"}},
		Reporting: config.ReportingConfig{OutputDir: t.TempDir()},
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
		reconResults.Subdomains[i] = "sub.example.com"
	}

	path, err := NewGenerator(cfg, log).Generate(
		reconResults,
		&scanner.Results{Complete: true},
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
		!strings.Contains(report, "Parameterized URLs discovered | 1") ||
		!strings.Contains(report, "not proof that the target is secure") {
		t.Fatalf("limited zero-finding report did not communicate coverage uncertainty:\n%s", report)
	}
}

func TestCountParameterizedURLsDeduplicatesFragments(t *testing.T) {
	urls := []string{
		"https://example.com/search?q=one#top",
		"https://example.com/search?q=one#bottom",
		"https://example.com/static/app.js?v=1",
		"https://example.com/no-query",
	}
	if got := countParameterizedURLs(urls); got != 2 {
		t.Fatalf("countParameterizedURLs() = %d, want 2", got)
	}
}
