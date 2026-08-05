package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/analyzer"
	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/hunter"
	"github.com/Btr4k/bugbounty-agent/internal/recon"
	"github.com/Btr4k/bugbounty-agent/internal/scanner"
)

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		{domain: "example.com", valid: true},
		{domain: "api.example.com", valid: true},
		{domain: "xn--bcher-kva.example", valid: false},
		{domain: "EXAMPLE.com", valid: true},
		{domain: "", valid: false},
		{domain: "example..com", valid: false},
		{domain: "-api.example.com", valid: false},
		{domain: "api-.example.com", valid: false},
		{domain: "localhost", valid: false},
		{domain: "example.com/path", valid: false},
		{domain: "*.example.com", valid: false},
		{domain: "com", valid: false},
		{domain: "co.uk", valid: false},
		{domain: "github.io", valid: false},
		{domain: "8.8.8.8", valid: false},
		{domain: "127.1", valid: false},
		{domain: "0177.0.0.1", valid: false},
		{domain: "2130706433", valid: false},
		{domain: "0x7f.0.0.1", valid: false},
		{domain: "example.com\nforged.example", valid: false},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			err := validateDomain(tt.domain)
			if tt.valid && err != nil {
				t.Fatalf("validateDomain(%q) unexpected error: %v", tt.domain, err)
			}
			if !tt.valid && err == nil {
				t.Fatalf("validateDomain(%q) expected error", tt.domain)
			}
		})
	}
}

func TestConfiguredTargetRulesRequireExplicitSubdomainAuthorization(t *testing.T) {
	if got := configuredTargetRules("example.com", false); !slices.Equal(got, []string{"example.com"}) {
		t.Fatalf("exact target rules = %#v", got)
	}
	if got := configuredTargetRules("example.com", true); !slices.Equal(got, []string{"example.com", "*.example.com"}) {
		t.Fatalf("subdomain target rules = %#v", got)
	}
}

func validTestConfig() *config.Config {
	return &config.Config{
		AI: config.AIConfig{
			Provider:  "deepseek",
			APIKey:    "old-deepseek-key",
			Model:     "deepseek-v4-flash",
			MaxTokens: 4000,
			BaseURL:   "https://api.deepseek.com/v1",
			Timeout:   30,
		},
		Recon:    config.ReconConfig{Timeout: 1},
		Scanning: config.ScanningConfig{Threads: 1, RateLimit: 1},
		Analysis: config.AnalysisConfig{MinConfidence: 0.85},
	}
}

func TestSaveHypothesesUsesPrivatePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "reports")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := saveHypotheses(dir, "example.com", []hunter.Hypothesis{{Target: "https://example.com/account"}}); err == nil {
		t.Fatal("saveHypotheses changed or accepted a broadly accessible existing directory")
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o755 {
		t.Fatalf("pre-existing hypotheses directory mode changed to %o", got)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path, err := saveHypotheses(dir, "example.com", []hunter.Hypothesis{{Target: "https://example.com/account"}})
	if err != nil {
		t.Fatal(err)
	}
	dirInfo, err = os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("hypotheses directory mode = %o, want 700", got)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("hypotheses file mode = %o, want 600", got)
	}
}

func TestTerminalOutputHelpersDoNotExposeEvidenceOrControls(t *testing.T) {
	secret := "token-value-that-must-not-appear"
	summary := evidenceSummary("Authorization: Bearer " + secret + "\nraw response body")
	if strings.Contains(summary, secret) || !strings.HasPrefix(summary, "[captured; withheld from terminal") {
		t.Fatalf("unsafe evidence summary: %q", summary)
	}
	if got := terminalSafe("title\x1b[31m\nforged Authorization: Bearer " + secret); strings.ContainsAny(got, "\x1b\n\r") || strings.Contains(got, secret) {
		t.Fatalf("terminal controls or credential were not removed: %q", got)
	}
	if got := terminalSafe("https://example.com/callback?token=opaque-query-value#private"); strings.Contains(got, "opaque-query-value") || strings.Contains(got, "#private") || !strings.Contains(got, "token=") {
		t.Fatalf("terminal URL query value was not sanitized: %q", got)
	}

	cfg := validTestConfig()
	cfg.Authentication.Headers = map[string]string{"X-Session": "opaque-configured-secret"}
	if got := terminalConfigSafe(cfg, "target?session=opaque-configured-secret"); strings.Contains(got, "opaque-configured-secret") || (!strings.Contains(got, "session=") && !strings.Contains(got, "[REDACTED]")) {
		t.Fatalf("configured secret was not redacted: %q", got)
	}
}

func TestSummaryClassificationUsesOnlyConfirmedFindings(t *testing.T) {
	analysis := &analyzer.Analysis{
		ValidatedFindings: []analyzer.ValidatedFinding{{
			Finding:  scanner.Finding{Severity: "low"},
			IsValid:  true,
			Decision: "confirmed",
		}},
		ManualReview: []analyzer.ValidatedFinding{{
			Finding: scanner.Finding{Severity: "critical"},
		}},
		FalsePositives: []analyzer.ValidatedFinding{{
			Finding: scanner.Finding{Severity: "critical"},
		}},
	}

	counts, classification := classifySummary(analysis, true)
	if classification != summaryLow {
		t.Fatalf("manual/rejected critical candidate changed final classification to %q", classification)
	}
	if counts.Critical != 0 || counts.Low != 1 || counts.total() != 1 {
		t.Fatalf("summary counted non-confirmed candidates: %+v", counts)
	}

	analysis.ValidatedFindings = append(analysis.ValidatedFindings, analyzer.ValidatedFinding{
		Finding:  scanner.Finding{Severity: "critical"},
		IsValid:  true,
		Decision: "confirmed",
	})
	_, classification = classifySummary(analysis, true)
	if classification != summaryCritical {
		t.Fatalf("confirmed critical finding classified as %q", classification)
	}
	_, classification = classifySummary(analysis, false)
	if classification != summaryCritical {
		t.Fatalf("partial scan suppressed confirmed critical severity as %q", classification)
	}
}

func TestSupportsNegativeConclusionRequiresCompleteSubstantiveCoverage(t *testing.T) {
	completeRecon := deepSummaryReconFixture()
	completeScan := scanner.Results{
		Complete: true,
		Stats: scanner.ScanStats{
			TotalAttempted:       100,
			TotalScanned:         100,
			SubstantiveAttempted: 100,
			SubstantiveScanned:   100,
		},
	}
	resolved := &analyzer.Analysis{}

	tests := []struct {
		name     string
		recon    recon.Results
		scan     scanner.Results
		analysis *analyzer.Analysis
		want     bool
	}{
		{name: "deep measured coverage", recon: completeRecon, scan: completeScan, analysis: resolved, want: true},
		{name: "nil analysis", recon: completeRecon, scan: completeScan, analysis: nil},
		{name: "zero target", recon: recon.Results{Complete: true}, scan: completeScan, analysis: resolved},
		{
			name:     "limited measured coverage",
			recon:    recon.Results{Subdomains: []string{"example.com"}, URLs: []string{"https://example.com/"}, Complete: true},
			scan:     scanner.Results{Complete: true, Stats: scanner.ScanStats{TotalAttempted: 1, TotalScanned: 1, SubstantiveAttempted: 1, SubstantiveScanned: 1}},
			analysis: resolved,
		},
		{name: "incomplete recon", recon: recon.Results{}, scan: completeScan, analysis: resolved},
		{name: "incomplete scan", recon: completeRecon, scan: scanner.Results{Stats: completeScan.Stats}, analysis: resolved},
		{
			name:     "no substantive attempt",
			recon:    completeRecon,
			scan:     scanner.Results{Complete: true, Stats: scanner.ScanStats{TotalAttempted: 100, TotalScanned: 100}},
			analysis: resolved,
		},
		{
			name:  "not every attempt scanned",
			recon: completeRecon,
			scan: scanner.Results{Complete: true, Stats: scanner.ScanStats{
				SubstantiveAttempted: 2,
				SubstantiveScanned:   1,
			}},
			analysis: resolved,
		},
		{
			name:  "substantive target skipped",
			recon: completeRecon,
			scan: scanner.Results{Complete: true, Stats: scanner.ScanStats{
				SubstantiveAttempted: 2,
				SubstantiveScanned:   2,
				SubstantiveSkipped:   1,
			}},
			analysis: resolved,
		},
		{
			name:  "substantive target failed",
			recon: completeRecon,
			scan: scanner.Results{Complete: true, Stats: scanner.ScanStats{
				SubstantiveAttempted: 2,
				SubstantiveScanned:   2,
				SubstantiveFailed:    1,
			}},
			analysis: resolved,
		},
		{
			name:  "manual review unresolved",
			recon: completeRecon,
			scan:  completeScan,
			analysis: &analyzer.Analysis{ManualReview: []analyzer.ValidatedFinding{{
				Finding: scanner.Finding{Severity: "medium"},
			}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := supportsNegativeConclusion(&tt.recon, &tt.scan, tt.analysis); got != tt.want {
				t.Fatalf("supportsNegativeConclusion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func deepSummaryReconFixture() recon.Results {
	result := recon.Results{
		Subdomains: make([]string, 100),
		URLs:       make([]string, 100),
		JSFiles:    make([]recon.JSFile, 20),
		Complete:   true,
	}
	for i := range result.Subdomains {
		result.Subdomains[i] = fmt.Sprintf("s%d.example.com", i)
		result.URLs[i] = fmt.Sprintf("https://s%d.example.com/api/item?id=%d", i, i)
	}
	for i := range result.JSFiles {
		result.JSFiles[i].URL = fmt.Sprintf("https://static.example.com/assets/%d.js", i)
	}
	return result
}

func TestConfirmedSeveritySurvivesInsufficientNegativeCoverage(t *testing.T) {
	analysis := &analyzer.Analysis{ValidatedFindings: []analyzer.ValidatedFinding{{
		Finding:  scanner.Finding{Severity: "critical"},
		IsValid:  true,
		Decision: "confirmed",
	}}}

	coverage := supportsNegativeConclusion(
		&recon.Results{Complete: true},
		&scanner.Results{Complete: true},
		analysis,
	)
	if coverage {
		t.Fatal("zero substantive work unexpectedly supported a negative conclusion")
	}
	counts, classification := classifySummary(analysis, coverage)
	if classification != summaryCritical || counts.Critical != 1 {
		t.Fatalf("insufficient coverage hid confirmed critical finding: classification=%q counts=%+v", classification, counts)
	}
}

func TestCheckConfigAcceptsAuthenticationConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := `ai:
  provider: deepseek
  api_key: test-key
authentication:
  allowed_hosts: ["https://app.example.com"]
  headers:
    Authorization: "Bearer test-token"
recon:
  timeout: 1
scanning:
  threads: 1
  rate_limit: 1
analysis:
  min_confidence: 0.85
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	oldCheck, oldCfg := checkConfig, cfgFile
	checkConfig, cfgFile = true, path
	t.Cleanup(func() {
		checkConfig, cfgFile = oldCheck, oldCfg
	})

	if err := runAgent(nil, nil); err != nil {
		t.Fatalf("check-config rejected compatible config: %v", err)
	}
}

func TestEnsureToolBinsOnPath(t *testing.T) {
	home := t.TempDir()
	goPath := filepath.Join(t.TempDir(), "gopath")
	t.Setenv("HOME", home)
	t.Setenv("GOPATH", goPath)
	t.Setenv("PATH", "/usr/bin")

	ensureToolBinsOnPath()

	paths := strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))
	for _, expected := range []string{
		filepath.Join(home, "go", "bin"),
		filepath.Join(home, ".local", "bin"),
		filepath.Join(goPath, "bin"),
	} {
		found := false
		for _, path := range paths {
			if path == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("PATH does not contain %q: %v", expected, paths)
		}
	}
}
