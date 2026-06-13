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

func TestParseValidationResponseIgnoresNegativeIndex(t *testing.T) {
	a := &ClaudeAnalyzer{cfg: &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.7}}}
	original := []scanner.Finding{{Title: "real"}}
	validated, rejected, err := a.parseValidationResponse(
		`{"findings":[{"index":-1,"is_valid":true,"confidence":1}]}`,
		original,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != 0 || len(rejected) != 0 {
		t.Fatalf("negative index should be ignored: validated=%d rejected=%d", len(validated), len(rejected))
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

func TestAnalyzeBatchRejectsIncompleteAdjudication(t *testing.T) {
	a := &ClaudeAnalyzer{
		cfg:    &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.7}},
		client: fakeProvider{response: `{"findings":[]}`},
	}
	_, _, err := a.analyzeBatch(context.Background(), []scanner.Finding{{Title: "candidate"}})
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
	validated, rejected, err := a.parseValidationResponse(
		`{"findings":[{"index":0,"is_valid":true,"confidence":0.99,"analysis":"likely valid","proof_of_concept":"curl https://example.com/bypass"}]}`,
		original,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != 0 || len(rejected) != 1 {
		t.Fatalf("finding without captured response must be rejected: validated=%d rejected=%d", len(validated), len(rejected))
	}
}

func TestParseValidationResponseRequiresReportableConfidence(t *testing.T) {
	a := &ClaudeAnalyzer{cfg: &config.Config{Analysis: config.AnalysisConfig{MinConfidence: 0.7}}}
	original := []scanner.Finding{{Title: "candidate", Evidence: "machine evidence"}}
	validated, rejected, err := a.parseValidationResponse(
		`{"findings":[{"index":0,"is_valid":true,"confidence":0.8}]}`,
		original,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated) != 0 || len(rejected) != 1 {
		t.Fatalf("confidence below 0.85 must require manual confirmation: validated=%d rejected=%d", len(validated), len(rejected))
	}
}
