package hunter

import (
	"context"
	"strings"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/recon"
)

// fakeProvider returns a canned response and records the prompt it received.
type fakeProvider struct {
	response   string
	lastPrompt string
	err        error
}

func (f *fakeProvider) Complete(_ context.Context, _, userPrompt string) (string, error) {
	f.lastPrompt = userPrompt
	return f.response, f.err
}
func (f *fakeProvider) CompleteWithRetry(ctx context.Context, s, u string, _ int) (string, error) {
	return f.Complete(ctx, s, u)
}
func (f *fakeProvider) ProviderName() string { return "fake" }

func testCfg() *config.Config {
	return &config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com"}},
		Hunter: config.HunterConfig{Enabled: true, MaxHypotheses: 40, MaxEndpoints: 120},
	}
}

func testRecon() *recon.Results {
	return &recon.Results{
		Subdomains: []string{"api.example.com", "evil.com"}, // evil.com is out of scope
		URLs: []string{
			"https://api.example.com/orders?order_id=100&token=abc",
			"https://api.example.com/profile", // plain path
			"https://out-of-scope.test/x?id=1",
		},
		Endpoints:    []string{"https://api.example.com/admin"},
		Technologies: []recon.Technology{{Name: "nginx", Version: "1.25"}},
		JSFiles:      []recon.JSFile{{URL: "https://api.example.com/app.js"}},
	}
}

func TestBuildSurfaceRespectsScope(t *testing.T) {
	cfg := testCfg()
	e := NewEngineWithProvider(cfg, logger.New(false), &fakeProvider{response: `{"hypotheses":[]}`})
	_, err := e.Generate(context.Background(), testRecon())
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	// Inspect the prompt actually sent to the model.
	fp := e.provider.(*fakeProvider)
	if strings.Contains(fp.lastPrompt, "out-of-scope.test") || strings.Contains(fp.lastPrompt, "evil.com") {
		t.Fatalf("out-of-scope host leaked into prompt:\n%s", fp.lastPrompt)
	}
	if !strings.Contains(fp.lastPrompt, "order_id") {
		t.Fatalf("expected parameterized URL params in prompt, got:\n%s", fp.lastPrompt)
	}
	if !strings.Contains(fp.lastPrompt, "api.example.com/admin") {
		t.Fatalf("expected in-scope endpoint in prompt")
	}
}

func TestGenerateFiltersOffScopeTargetsAndRanks(t *testing.T) {
	resp := `Here you go:
{"hypotheses":[
  {"class":"idor","target":"https://api.example.com/orders?order_id=100","parameter":"order_id","rationale":"sequential id","suggested_test":"swap id","severity":"high","confidence":0.6},
  {"class":"ssrf","target":"https://evil.com/x","parameter":"url","rationale":"off scope","suggested_test":"n/a","severity":"critical","confidence":0.9},
  {"class":"access-control","target":"https://api.example.com/admin","parameter":"","rationale":"admin path","suggested_test":"access without auth","severity":"critical","confidence":0.5}
]}`
	e := NewEngineWithProvider(testCfg(), logger.New(false), &fakeProvider{response: resp})
	hyps, err := e.Generate(context.Background(), testRecon())
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if len(hyps) != 2 {
		t.Fatalf("expected 2 in-scope hypotheses (off-scope evil.com dropped), got %d", len(hyps))
	}
	// Critical must rank above high.
	if hyps[0].Severity != "critical" || hyps[0].Class != "access-control" {
		t.Fatalf("ranking wrong: got %+v", hyps[0])
	}
	for _, h := range hyps {
		if strings.Contains(h.Target, "evil.com") {
			t.Fatalf("off-scope target survived filtering: %s", h.Target)
		}
	}
}

func TestParseHypothesesBadJSON(t *testing.T) {
	if _, err := parseHypotheses("no json here"); err == nil {
		t.Fatal("expected error on non-JSON response")
	}
}

func TestEmptySurfaceSkips(t *testing.T) {
	e := NewEngineWithProvider(testCfg(), logger.New(false), &fakeProvider{response: `{"hypotheses":[]}`})
	hyps, err := e.Generate(context.Background(), &recon.Results{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(hyps) != 0 {
		t.Fatalf("expected no hypotheses for empty surface")
	}
}

func TestGroundingObservedVsInferred(t *testing.T) {
	// order_id + admin path exist in testRecon() surface; foo_id does not.
	resp := `{"hypotheses":[
  {"class":"idor","target":"https://api.example.com/orders?order_id=100","parameter":"order_id","rationale":"seq","suggested_test":"swap","severity":"high","confidence":0.8,"grounding":"observed"},
  {"class":"idor","target":"https://api.example.com/profile","parameter":"foo_id","rationale":"guess","suggested_test":"swap","severity":"critical","confidence":0.95,"grounding":"observed"},
  {"class":"access-control","target":"https://api.example.com/admin","parameter":"","rationale":"admin","suggested_test":"access","severity":"high","confidence":0.5,"grounding":"observed"}
]}`
	e := NewEngineWithProvider(testCfg(), logger.New(false), &fakeProvider{response: resp})
	hyps, err := e.Generate(context.Background(), testRecon())
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	byParam := map[string]Hypothesis{}
	for _, h := range hyps {
		byParam[h.Parameter] = h
	}
	if g := byParam["order_id"].Grounding; g != "observed" {
		t.Fatalf("order_id should be observed (param seen in surface), got %q", g)
	}
	if h := byParam["foo_id"]; h.Grounding != "inferred" {
		t.Fatalf("foo_id should be inferred (param NOT in surface), got %q", h.Grounding)
	} else if h.Confidence > inferredConfidenceCap {
		t.Fatalf("inferred confidence must be capped at %.2f, got %.2f", inferredConfidenceCap, h.Confidence)
	}
	if g := byParam[""].Grounding; g != "observed" {
		t.Fatalf("admin path is an observed endpoint, host-only lead should be observed, got %q", g)
	}
	// Observed leads must rank above the inferred one despite its higher raw confidence.
	if hyps[0].Grounding != "observed" {
		t.Fatalf("observed lead must rank first, got %+v", hyps[0])
	}
	if last := hyps[len(hyps)-1]; last.Parameter != "foo_id" {
		t.Fatalf("inferred (foo_id) should rank last, got %q", last.Parameter)
	}
}

func TestSplitParams(t *testing.T) {
	got := splitParams("exam_id, user_id")
	if len(got) != 2 || got[0] != "exam_id" || got[1] != "user_id" {
		t.Fatalf("splitParams wrong: %v", got)
	}
}

func TestNormalizeParameterPlaceholders(t *testing.T) {
	for _, in := range []string{"", "none", "None", "N/A", "-", "null", "nil", "لا يوجد"} {
		if got := normalizeParameter(in); got != "" {
			t.Fatalf("normalizeParameter(%q) = %q, want empty", in, got)
		}
	}
	if got := normalizeParameter(" order_id "); got != "order_id" {
		t.Fatalf("real param mangled: %q", got)
	}
}

func TestNoneParamOnObservedPathStaysObserved(t *testing.T) {
	// /profile is an observed plain path in testRecon(); param "none" must not
	// force the lead to inferred.
	resp := `{"hypotheses":[
  {"class":"info-disclosure","target":"https://api.example.com/profile","parameter":"none","rationale":"x","suggested_test":"y","severity":"medium","confidence":0.5,"grounding":"observed"}
]}`
	e := NewEngineWithProvider(testCfg(), logger.New(false), &fakeProvider{response: resp})
	hyps, err := e.Generate(context.Background(), testRecon())
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if len(hyps) != 1 {
		t.Fatalf("expected 1 hypothesis, got %d", len(hyps))
	}
	if hyps[0].Parameter != "" {
		t.Fatalf("param 'none' should normalize to empty, got %q", hyps[0].Parameter)
	}
	if hyps[0].Grounding != "observed" {
		t.Fatalf("observed path with no real param should stay observed, got %q", hyps[0].Grounding)
	}
	if hyps[0].Confidence != 0.5 {
		t.Fatalf("observed lead confidence must not be capped, got %.2f", hyps[0].Confidence)
	}
}

func TestBareHostTargetSurvives(t *testing.T) {
	// Model echoes an in-scope subdomain WITHOUT a scheme — it must not be dropped.
	resp := `{"hypotheses":[
  {"class":"access-control","target":"api.example.com","parameter":"","rationale":"x","suggested_test":"y","severity":"high","confidence":0.3,"grounding":"inferred"}
]}`
	e := NewEngineWithProvider(testCfg(), logger.New(false), &fakeProvider{response: resp})
	hyps, err := e.Generate(context.Background(), testRecon())
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}
	if len(hyps) != 1 {
		t.Fatalf("bare-host in-scope target was dropped; got %d hypotheses", len(hyps))
	}
	if hyps[0].Target != "https://api.example.com" {
		t.Fatalf("target not normalized with scheme: %q", hyps[0].Target)
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"  api.example.com ":      "https://api.example.com",
		"https://api.example.com": "https://api.example.com",
		"http://x.example.com/p":  "http://x.example.com/p",
		"":                        "",
	}
	for in, want := range cases {
		if got := normalizeTarget(in); got != want {
			t.Fatalf("normalizeTarget(%q)=%q want %q", in, got, want)
		}
	}
}
