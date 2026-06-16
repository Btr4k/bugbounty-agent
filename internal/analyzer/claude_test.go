package analyzer

import (
	"context"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/scanner"
)

type fakeProvider struct {
	response string
}

func (f fakeProvider) Complete(context.Context, string, string) (string, error) {
	return f.response, nil
}
func (f fakeProvider) CompleteWithRetry(context.Context, string, string, int) (string, error) {
	return f.response, nil
}
func (f fakeProvider) ProviderName() string { return "fake" }

// failingProvider simulates an unreachable AI validator (timeout, rate limit).
type failingProvider struct{}

func (failingProvider) Complete(context.Context, string, string) (string, error) {
	return "", context.DeadlineExceeded
}
func (failingProvider) CompleteWithRetry(context.Context, string, string, int) (string, error) {
	return "", context.DeadlineExceeded
}
func (failingProvider) ProviderName() string { return "failing" }

func TestAnalyzePreservesFindingsWhenAIValidationFails(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	a := &ClaudeAnalyzer{
		cfg:    &config.Config{AI: config.AIConfig{Provider: "failing"}, Analysis: config.AnalysisConfig{MinConfidence: 0.85}},
		log:    log,
		client: failingProvider{},
	}
	results := &scanner.Results{Findings: []scanner.Finding{
		{Title: "Exposed backup", Type: "http", Severity: "medium", Response: "HTTP/1.1 200 OK"},
		{Title: "phpinfo", Type: "http", Severity: "low", Response: "HTTP/1.1 200 OK"},
	}}

	analysis, err := a.Analyze(context.Background(), results)
	if err == nil {
		t.Fatal("expected an error when the AI validator is unreachable")
	}
	// The two tool candidates must NOT vanish — they belong in manual review.
	if len(analysis.ManualReview) != 2 {
		t.Fatalf("AI-failure findings must be preserved for manual review, got %d: %#v", len(analysis.ManualReview), analysis.ManualReview)
	}
	if len(analysis.ValidatedFindings) != 0 {
		t.Fatalf("nothing should be auto-confirmed when validation fails: %#v", analysis.ValidatedFindings)
	}
}

func TestParseValidationResponseIgnoresNegativeIndex(t *testing.T) {
	a := &ClaudeAnalyzer{cfg: &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.7}}}
	original := []scanner.Finding{{Title: "real"}}
	validated, manualReview, rejected, err := a.parseValidationResponse(
		`{"findings":[{"index":-1,"is_valid":true,"confidence":1}]}`,
		original,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != 0 || len(manualReview) != 0 || len(rejected) != 0 {
		t.Fatalf("negative index should be ignored: validated=%d manual=%d rejected=%d", len(validated), len(manualReview), len(rejected))
	}
}

func TestAnalyzeJSBatchRequiresGroundedValueAndFile(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	a := &ClaudeAnalyzer{
		cfg: &config.Config{AI: config.AIConfig{Provider: "fake"}},
		log: log,
		client: fakeProvider{response: `{"findings":[
			{"type":"secret","value":"real-secret-value","file_url":"https://example.com/app.js","severity":"high"},
			{"type":"secret","value":"invented-secret","file_url":"https://example.com/app.js","severity":"critical"},
			{"type":"secret","value":"real-secret-value","file_url":"https://evil.test/app.js","severity":"critical"},
			{"type":"endpoint","value":"/api/admin","file_url":"https://example.com/app.js","severity":"high"}
		]}`},
	}
	files := []struct {
		URL     string
		Content string
		Size    int
		Source  string
	}{{URL: "https://example.com/app.js", Content: `const secret = "real-secret-value"; const path="/api/admin";`}}

	findings, err := a.analyzeJSBatch(context.Background(), files)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Evidence != "real-secret-value" {
		t.Fatalf("expected only grounded sensitive finding, got %#v", findings)
	}
}

func TestAnalyzeRoutesAIOnlyJSFindingsToManualReview(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	a := &ClaudeAnalyzer{
		cfg:    &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.85}},
		log:    log,
		client: fakeProvider{},
	}
	results := &scanner.Results{Findings: []scanner.Finding{
		{
			Title:    "AI-only candidate",
			Type:     "js-analysis",
			Severity: "high",
			Evidence: "possible-secret-value",
			Metadata: map[string]string{"source": "ai-js-analysis"},
		},
		{
			Title:    "Regex-confirmed candidate",
			Type:     "js-analysis",
			Severity: "high",
			Evidence: "confirmed-secret-value",
			Metadata: map[string]string{"source": "regex-js-scanner"},
		},
	}}

	analysis, err := a.Analyze(context.Background(), results)
	if err != nil {
		t.Fatal(err)
	}
	if len(analysis.ManualReview) != 1 || analysis.ManualReview[0].Title != "AI-only candidate" {
		t.Fatalf("AI-only JS finding must require manual review: %#v", analysis.ManualReview)
	}
	if len(analysis.ValidatedFindings) != 1 || analysis.ValidatedFindings[0].Title != "Regex-confirmed candidate" {
		t.Fatalf("regex-grounded JS finding must remain confirmed: %#v", analysis.ValidatedFindings)
	}
}

func TestAnalyzeBatchRejectsIncompleteAdjudication(t *testing.T) {
	a := &ClaudeAnalyzer{
		cfg:    &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.7}},
		client: fakeProvider{response: `{"findings":[]}`},
	}
	_, _, _, err := a.analyzeBatch(context.Background(), []scanner.Finding{{Title: "candidate"}})
	if err == nil {
		t.Fatal("expected incomplete AI adjudication to fail")
	}
}

func TestParseValidationResponseRejectsHTTPFindingWithoutCapturedResponse(t *testing.T) {
	a := &ClaudeAnalyzer{cfg: &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.85}}}
	original := []scanner.Finding{{
		Title: "Authentication bypass",
		Type:  "http",
		URL:   "https://example.com/bypass",
		Metadata: map[string]string{
			"curl": "curl https://example.com/bypass",
		},
	}}
	validated, manualReview, rejected, err := a.parseValidationResponse(
		`{"findings":[{"index":0,"is_valid":true,"confidence":0.99,"analysis":"likely valid","proof_of_concept":"curl https://example.com/bypass"}]}`,
		original,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != 0 || len(manualReview) != 0 || len(rejected) != 1 {
		t.Fatalf("finding without captured response must be rejected: validated=%d manual=%d rejected=%d", len(validated), len(manualReview), len(rejected))
	}
}

func TestParseValidationResponseRequiresReportableConfidence(t *testing.T) {
	a := &ClaudeAnalyzer{cfg: &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.7}}}
	original := []scanner.Finding{{Title: "candidate", Evidence: "machine evidence"}}
	validated, manualReview, rejected, err := a.parseValidationResponse(
		`{"findings":[{"index":0,"is_valid":true,"confidence":0.8}]}`,
		original,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != 0 || len(manualReview) != 1 || len(rejected) != 0 {
		t.Fatalf("confidence below 0.85 must require manual confirmation: validated=%d manual=%d rejected=%d", len(validated), len(manualReview), len(rejected))
	}
}

func TestParseValidationResponsePreservesStructuredDecisionAndEvidence(t *testing.T) {
	a := &ClaudeAnalyzer{cfg: &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.85}}}
	original := []scanner.Finding{{Title: "candidate", Evidence: "captured proof"}}
	validated, manualReview, rejected, err := a.parseValidationResponse(
		`{"findings":[{"index":0,"decision":"manual-review","confidence":0.95,"evidence_refs":["captured proof"],"missing_evidence":["control request"]}]}`,
		original,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != 0 || len(manualReview) != 1 || len(rejected) != 0 {
		t.Fatalf("unexpected decision routing: validated=%d manual=%d rejected=%d", len(validated), len(manualReview), len(rejected))
	}
	if len(manualReview[0].EvidenceRefs) != 1 || len(manualReview[0].MissingEvidence) != 1 {
		t.Fatalf("structured evidence fields missing: %#v", manualReview[0])
	}
}

func TestParseValidationResponseRejectsProtectedTraceAXD(t *testing.T) {
	a := &ClaudeAnalyzer{cfg: &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.85}}}
	original := []scanner.Finding{{
		Title:    "ASP.NET Trace.AXD - Exposure",
		Type:     "http",
		Severity: "low",
		URL:      "https://crm.example.com/Trace.axd",
		Response: "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<title>Trace Error</title>",
	}}
	validated, manualReview, rejected, err := a.parseValidationResponse(
		`{"findings":[{"index":0,"decision":"manual-review","confidence":0.0,"analysis":"possible exposure"}]}`,
		original,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != 0 || len(manualReview) != 0 || len(rejected) != 1 {
		t.Fatalf("protected Trace.axd must be rejected: validated=%d manual=%d rejected=%d", len(validated), len(manualReview), len(rejected))
	}
	if rejected[0].BugBountyValue != "none" {
		t.Fatalf("protected Trace.axd should have no bounty value: %#v", rejected[0])
	}
}

func TestParseValidationResponsePromotesSensitiveMiniProfilerExposure(t *testing.T) {
	a := &ClaudeAnalyzer{cfg: &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.85}}}
	original := []scanner.Finding{{
		Title:    "Umbraco Mini Profiler - Exposure",
		Type:     "http",
		Severity: "low",
		URL:      "https://example.com/mini-profiler-resources/results",
		Response: "HTTP/1.1 200 OK\r\nX-Powered-By: ASP.NET\r\n\r\n<title>StartupProfiler - Profiling Results</title> Umbraco MiniProfiler SQL SELECT",
	}}
	validated, manualReview, rejected, err := a.parseValidationResponse(
		`{"findings":[{"index":0,"decision":"confirmed","confidence":0.95,"analysis":"exposed profiler","bug_bounty_value":"low"}]}`,
		original,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != 1 || len(manualReview) != 0 || len(rejected) != 0 {
		t.Fatalf("sensitive MiniProfiler exposure must remain confirmed: validated=%d manual=%d rejected=%d", len(validated), len(manualReview), len(rejected))
	}
	if validated[0].Severity != "medium" || validated[0].BugBountyValue != "medium" {
		t.Fatalf("MiniProfiler exposure should be promoted to medium value: %#v", validated[0])
	}
}
