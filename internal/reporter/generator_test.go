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
		Target:    config.TargetConfig{Domains: []string{"example.com"}},
		Reporting: config.ReportingConfig{OutputDir: t.TempDir(), IncludePOC: true},
	}
	validated := analyzer.ValidatedFinding{
		Finding: scanner.Finding{
			Title:    "Validated finding",
			Severity: "high",
			URL:      "https://example.com",
			Response: "HTTP/1.1 200 OK\r\n\r\nsensitive proof",
			Metadata: map[string]string{"curl": "curl https://example.com"},
		},
		IsValid:        true,
		Confidence:     0.95,
		ProofOfConcept: "AI-generated command that must not be shown",
	}
	raw := scanner.Finding{Title: "Unvalidated raw finding", Severity: "critical", URL: "https://example.com"}

	path, err := NewGenerator(cfg, log).Generate(
		&recon.Results{Subdomains: []string{"example.com"}},
		&scanner.Results{Findings: []scanner.Finding{raw}, Complete: true},
		&analyzer.Analysis{ValidatedFindings: []analyzer.ValidatedFinding{validated}},
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
	if !strings.Contains(string(content), "curl https://example.com") {
		t.Fatal("tool-captured reproduction command missing from report")
	}
	if !strings.Contains(string(content), "Validation Confidence**: 0.95") ||
		!strings.Contains(string(content), "Captured Response") {
		t.Fatal("report must include confidence and captured response")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("report permissions = %o, want 600", info.Mode().Perm())
	}
}
