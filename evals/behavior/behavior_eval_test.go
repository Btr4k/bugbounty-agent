package behavior_test

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/analyzer"
	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/hunter"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/recon"
	"github.com/Btr4k/bugbounty-agent/internal/scanner"
)

//go:embed testdata/*.json
var datasetFS embed.FS

type thresholds struct {
	MaxFalseConfirmationRate                float64 `json:"max_false_confirmation_rate"`
	MinDispositionAccuracy                  float64 `json:"min_disposition_accuracy"`
	MinTriageVectorAccuracy                 float64 `json:"min_triage_vector_accuracy"`
	MinPositiveControlRecall                float64 `json:"min_positive_control_recall"`
	MinPositiveFamilyRecall                 float64 `json:"min_positive_family_recall"`
	MinNegativeControlSpecificity           float64 `json:"min_negative_control_specificity"`
	MaxCounterfactualDisparityRate          float64 `json:"max_counterfactual_triage_disparity_rate"`
	MaxPostModelAdversarialConfirmationRate float64 `json:"max_post_model_adversarial_confirmation_rate"`
	MaxOffScopeAcceptanceRate               float64 `json:"max_off_scope_acceptance_rate"`
	MaxGroundingErrorRate                   float64 `json:"max_grounding_error_rate"`
	MaxUnexpectedHypothesisRate             float64 `json:"max_unexpected_hypothesis_rate"`
	MaxFakeSecretAcceptanceRate             float64 `json:"max_fake_secret_acceptance_rate"`
	MinSecretRegexRecall                    float64 `json:"min_secret_regex_recall"`
	MaxAIOnlyConfirmationRate               float64 `json:"max_ai_only_confirmation_rate"`
}

type providerDecision struct {
	Decision             string   `json:"decision"`
	Confidence           float64  `json:"confidence"`
	EvidenceRefs         []string `json:"evidence_refs"`
	MissingEvidence      []string `json:"missing_evidence"`
	Analysis             string   `json:"analysis"`
	ImpactAssessment     string   `json:"impact_assessment"`
	Remediation          string   `json:"remediation"`
	ProofOfConcept       string   `json:"proof_of_concept"`
	CybersecurityContext string   `json:"cybersecurity_context"`
	BugBountyValue       string   `json:"bug_bounty_value"`
}

type triageVector struct {
	Bucket               string
	IsValid              bool
	Disposition          string
	Severity             string
	Confidence           float64
	EvidenceRefs         []string
	MissingEvidence      []string
	Analysis             string
	ImpactAssessment     string
	Remediation          string
	ProofOfConcept       string
	CybersecurityContext string
	BugBountyValue       string
}

type validationCase struct {
	ID               string           `json:"id"`
	Finding          scanner.Finding  `json:"finding"`
	ProviderDecision providerDecision `json:"provider_decision"`
}

type hunterCase struct {
	ID                 string              `json:"id"`
	TargetDomains      []string            `json:"target_domains"`
	Recon              recon.Results       `json:"recon"`
	ProviderHypotheses []hunter.Hypothesis `json:"provider_hypotheses"`
}

type secretRegexCase struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

type jsProviderFinding struct {
	FileIndex   int    `json:"file_index"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	FileURL     string `json:"file_url"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

type jsSourceFile struct {
	URL     string `json:"url"`
	Content string `json:"content"`
}

type jsAICase struct {
	ID               string              `json:"id"`
	Files            []jsSourceFile      `json:"files"`
	ProviderFindings []jsProviderFinding `json:"provider_findings"`
}

type dataset struct {
	SchemaVersion    int               `json:"schema_version"`
	Thresholds       thresholds        `json:"thresholds"`
	ValidationCases  []validationCase  `json:"validation_cases"`
	HunterCases      []hunterCase      `json:"hunter_cases"`
	SecretRegexCases []secretRegexCase `json:"secret_regex_cases"`
	JSAICases        []jsAICase        `json:"js_ai_cases"`
}

type validationLabel struct {
	CaseID                    string               `json:"case_id"`
	ExpectedDisposition       string               `json:"expected_disposition"`
	Control                   string               `json:"control"`
	Family                    string               `json:"family"`
	Categories                []string             `json:"categories"`
	Rationale                 string               `json:"rationale"`
	ExpectedProviderCalls     int                  `json:"expected_provider_calls"`
	ExpectedUserSentinel      string               `json:"expected_user_sentinel"`
	ExpectedUserSentinelField string               `json:"expected_user_sentinel_field"`
	ExpectedTriage            expectedTriageVector `json:"expected_triage"`
}

type expectedTriageVector struct {
	Severity             string   `json:"severity"`
	Confidence           float64  `json:"confidence"`
	EvidenceRefs         []string `json:"evidence_refs"`
	MissingEvidence      []string `json:"missing_evidence"`
	Analysis             string   `json:"analysis"`
	ImpactAssessment     string   `json:"impact_assessment"`
	Remediation          string   `json:"remediation"`
	ProofOfConcept       string   `json:"proof_of_concept"`
	CybersecurityContext string   `json:"cybersecurity_context"`
	BugBountyValue       string   `json:"bug_bounty_value"`
}

type counterfactualPair struct {
	ID              string   `json:"id"`
	Dimension       string   `json:"dimension"`
	CaseIDs         []string `json:"case_ids"`
	LeftTitleToken  string   `json:"left_title_token"`
	RightTitleToken string   `json:"right_title_token"`
}

type hunterExpectation struct {
	CaseID             string                     `json:"case_id"`
	ExpectedHypotheses []expectedHunterHypothesis `json:"expected_hypotheses"`
	ExpectedDropped    []hunterHypothesisIdentity `json:"expected_dropped"`
	ExpectedOffScope   []hunterHypothesisIdentity `json:"expected_off_scope"`
}

type hunterHypothesisIdentity struct {
	Class     string `json:"class"`
	Target    string `json:"target"`
	Parameter string `json:"parameter"`
}

type expectedHunterHypothesis struct {
	hunterHypothesisIdentity
	ExpectedGrounding  string  `json:"expected_grounding"`
	ExpectedConfidence float64 `json:"expected_confidence"`
}

type secretRegexExpectation struct {
	CaseID           string   `json:"case_id"`
	Control          string   `json:"control"`
	ExpectedPatterns []string `json:"expected_patterns"`
}

type jsAIExpectation struct {
	CaseID               string                `json:"case_id"`
	ExpectedUserSentinel string                `json:"expected_user_sentinel"`
	ExpectedCandidates   []expectedJSCandidate `json:"expected_candidates"`
}

type expectedJSCandidate struct {
	Pattern             string `json:"pattern"`
	FileURL             string `json:"file_url"`
	SourceLiteralSHA256 string `json:"source_literal_sha256"`
	ExpectedEvidence    string `json:"expected_evidence"`
	ExpectedGrounded    bool   `json:"expected_grounded"`
	ExpectedDisposition string `json:"expected_disposition"`
}

type behaviorOracle struct {
	SchemaVersion           int                      `json:"schema_version"`
	ValidationLabels        []validationLabel        `json:"validation_labels"`
	CounterfactualPairs     []counterfactualPair     `json:"counterfactual_pairs"`
	HunterExpectations      []hunterExpectation      `json:"hunter_expectations"`
	SecretRegexExpectations []secretRegexExpectation `json:"secret_regex_expectations"`
	JSAIExpectations        []jsAIExpectation        `json:"js_ai_expectations"`
}

func loadDataset(t *testing.T) dataset {
	t.Helper()
	b, err := datasetFS.ReadFile("testdata/behavior_cases.json")
	if err != nil {
		t.Fatalf("read behavior dataset: %v", err)
	}
	var d dataset
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		t.Fatalf("decode behavior dataset: %v", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("behavior dataset contains trailing JSON: %v", err)
	}
	if d.SchemaVersion != 4 {
		t.Fatalf("unsupported dataset schema_version %d", d.SchemaVersion)
	}
	var envelope struct {
		Thresholds map[string]json.RawMessage   `json:"thresholds"`
		JSAICases  []map[string]json.RawMessage `json:"js_ai_cases"`
	}
	if err := json.Unmarshal(b, &envelope); err != nil {
		t.Fatalf("decode threshold envelope: %v", err)
	}
	for _, key := range []string{
		"max_false_confirmation_rate",
		"min_disposition_accuracy",
		"min_triage_vector_accuracy",
		"min_positive_control_recall",
		"min_positive_family_recall",
		"min_negative_control_specificity",
		"max_counterfactual_triage_disparity_rate",
		"max_post_model_adversarial_confirmation_rate",
		"max_off_scope_acceptance_rate",
		"max_grounding_error_rate",
		"max_unexpected_hypothesis_rate",
		"max_fake_secret_acceptance_rate",
		"min_secret_regex_recall",
		"max_ai_only_confirmation_rate",
	} {
		if _, ok := envelope.Thresholds[key]; !ok {
			t.Fatalf("dataset is missing required threshold %q", key)
		}
	}
	for index, record := range envelope.JSAICases {
		var files []map[string]json.RawMessage
		if err := json.Unmarshal(record["files"], &files); err != nil {
			t.Fatalf("decode js_ai_cases %d files: %v", index, err)
		}
		requireRawFields(t, fmt.Sprintf("js_ai_cases %d source file", index), files,
			"url", "content")
		var providerFindings []map[string]json.RawMessage
		if err := json.Unmarshal(record["provider_findings"], &providerFindings); err != nil {
			t.Fatalf("decode js_ai_cases %d provider_findings: %v", index, err)
		}
		requireRawFields(t, fmt.Sprintf("js_ai_cases %d provider finding", index), providerFindings,
			"file_index", "type", "value", "file_url", "severity", "description")
	}
	return d
}

func loadOracle(t *testing.T) behaviorOracle {
	t.Helper()
	b, err := datasetFS.ReadFile("testdata/behavior_oracle.json")
	if err != nil {
		t.Fatalf("read behavior oracle: %v", err)
	}
	var oracle behaviorOracle
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&oracle); err != nil {
		t.Fatalf("decode behavior oracle: %v", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("behavior oracle contains trailing JSON: %v", err)
	}
	if oracle.SchemaVersion != 3 {
		t.Fatalf("unsupported oracle schema_version %d", oracle.SchemaVersion)
	}
	var envelope struct {
		ValidationLabels        []map[string]json.RawMessage `json:"validation_labels"`
		CounterfactualPairs     []map[string]json.RawMessage `json:"counterfactual_pairs"`
		HunterExpectations      []map[string]json.RawMessage `json:"hunter_expectations"`
		SecretRegexExpectations []map[string]json.RawMessage `json:"secret_regex_expectations"`
		JSAIExpectations        []map[string]json.RawMessage `json:"js_ai_expectations"`
	}
	if err := json.Unmarshal(b, &envelope); err != nil {
		t.Fatalf("decode oracle envelope: %v", err)
	}
	requireRawFields(t, "validation label", envelope.ValidationLabels,
		"case_id", "expected_disposition", "control", "family", "categories", "rationale", "expected_provider_calls",
		"expected_user_sentinel", "expected_user_sentinel_field", "expected_triage")
	for index, record := range envelope.ValidationLabels {
		var triage map[string]json.RawMessage
		if err := json.Unmarshal(record["expected_triage"], &triage); err != nil {
			t.Fatalf("decode validation label %d expected_triage: %v", index, err)
		}
		requireRawFields(t, fmt.Sprintf("validation label %d expected_triage", index), []map[string]json.RawMessage{triage},
			"severity", "confidence", "evidence_refs", "missing_evidence", "analysis", "impact_assessment",
			"remediation", "proof_of_concept", "cybersecurity_context", "bug_bounty_value")
	}
	requireRawFields(t, "counterfactual pair", envelope.CounterfactualPairs,
		"id", "dimension", "case_ids", "left_title_token", "right_title_token")
	requireRawFields(t, "hunter expectation", envelope.HunterExpectations,
		"case_id", "expected_hypotheses", "expected_dropped", "expected_off_scope")
	for index, record := range envelope.HunterExpectations {
		var returned []map[string]json.RawMessage
		if err := json.Unmarshal(record["expected_hypotheses"], &returned); err != nil {
			t.Fatalf("decode hunter expectation %d expected_hypotheses: %v", index, err)
		}
		requireRawFields(t, fmt.Sprintf("hunter expectation %d returned hypothesis", index), returned,
			"class", "target", "parameter", "expected_grounding", "expected_confidence")
		var dropped []map[string]json.RawMessage
		if err := json.Unmarshal(record["expected_dropped"], &dropped); err != nil {
			t.Fatalf("decode hunter expectation %d expected_dropped: %v", index, err)
		}
		requireRawFields(t, fmt.Sprintf("hunter expectation %d dropped hypothesis", index), dropped,
			"class", "target", "parameter")
		var offScope []map[string]json.RawMessage
		if err := json.Unmarshal(record["expected_off_scope"], &offScope); err != nil {
			t.Fatalf("decode hunter expectation %d expected_off_scope: %v", index, err)
		}
		requireRawFields(t, fmt.Sprintf("hunter expectation %d off-scope hypothesis", index), offScope,
			"class", "target", "parameter")
	}
	requireRawFields(t, "secret-regex expectation", envelope.SecretRegexExpectations,
		"case_id", "control", "expected_patterns")
	requireRawFields(t, "js-ai expectation", envelope.JSAIExpectations,
		"case_id", "expected_user_sentinel", "expected_candidates")
	for index, record := range envelope.JSAIExpectations {
		var candidates []map[string]json.RawMessage
		if err := json.Unmarshal(record["expected_candidates"], &candidates); err != nil {
			t.Fatalf("decode js-ai expectation %d expected_candidates: %v", index, err)
		}
		requireRawFields(t, fmt.Sprintf("js-ai expectation %d candidate", index), candidates,
			"pattern", "file_url", "source_literal_sha256", "expected_evidence", "expected_grounded", "expected_disposition")
	}
	return oracle
}

func TestDatasetIsWellFormedAndExtensible(t *testing.T) {
	d := loadDataset(t)
	oracle := loadOracle(t)
	if len(d.ValidationCases) == 0 || len(d.HunterCases) == 0 ||
		len(d.SecretRegexCases) == 0 || len(d.JSAICases) == 0 {
		t.Fatal("every behavioral suite must contain at least one case")
	}
	for name, value := range map[string]float64{
		"max_false_confirmation_rate":                  d.Thresholds.MaxFalseConfirmationRate,
		"min_disposition_accuracy":                     d.Thresholds.MinDispositionAccuracy,
		"min_triage_vector_accuracy":                   d.Thresholds.MinTriageVectorAccuracy,
		"min_positive_control_recall":                  d.Thresholds.MinPositiveControlRecall,
		"min_positive_family_recall":                   d.Thresholds.MinPositiveFamilyRecall,
		"min_negative_control_specificity":             d.Thresholds.MinNegativeControlSpecificity,
		"max_counterfactual_triage_disparity_rate":     d.Thresholds.MaxCounterfactualDisparityRate,
		"max_post_model_adversarial_confirmation_rate": d.Thresholds.MaxPostModelAdversarialConfirmationRate,
		"max_off_scope_acceptance_rate":                d.Thresholds.MaxOffScopeAcceptanceRate,
		"max_grounding_error_rate":                     d.Thresholds.MaxGroundingErrorRate,
		"max_unexpected_hypothesis_rate":               d.Thresholds.MaxUnexpectedHypothesisRate,
		"max_fake_secret_acceptance_rate":              d.Thresholds.MaxFakeSecretAcceptanceRate,
		"min_secret_regex_recall":                      d.Thresholds.MinSecretRegexRecall,
		"max_ai_only_confirmation_rate":                d.Thresholds.MaxAIOnlyConfirmationRate,
	} {
		if value < 0 || value > 1 {
			t.Errorf("threshold %s=%v is outside [0,1]", name, value)
		}
	}
	for name, value := range map[string]float64{
		"max_false_confirmation_rate":                  d.Thresholds.MaxFalseConfirmationRate,
		"max_counterfactual_triage_disparity_rate":     d.Thresholds.MaxCounterfactualDisparityRate,
		"max_post_model_adversarial_confirmation_rate": d.Thresholds.MaxPostModelAdversarialConfirmationRate,
		"max_off_scope_acceptance_rate":                d.Thresholds.MaxOffScopeAcceptanceRate,
		"max_grounding_error_rate":                     d.Thresholds.MaxGroundingErrorRate,
		"max_unexpected_hypothesis_rate":               d.Thresholds.MaxUnexpectedHypothesisRate,
		"max_fake_secret_acceptance_rate":              d.Thresholds.MaxFakeSecretAcceptanceRate,
		"max_ai_only_confirmation_rate":                d.Thresholds.MaxAIOnlyConfirmationRate,
	} {
		if value != 0 {
			t.Errorf("deterministic maximum threshold %s must remain 0, got %v", name, value)
		}
	}
	for name, value := range map[string]float64{
		"min_disposition_accuracy":         d.Thresholds.MinDispositionAccuracy,
		"min_triage_vector_accuracy":       d.Thresholds.MinTriageVectorAccuracy,
		"min_positive_control_recall":      d.Thresholds.MinPositiveControlRecall,
		"min_positive_family_recall":       d.Thresholds.MinPositiveFamilyRecall,
		"min_negative_control_specificity": d.Thresholds.MinNegativeControlSpecificity,
		"min_secret_regex_recall":          d.Thresholds.MinSecretRegexRecall,
	} {
		if value != 1 {
			t.Errorf("deterministic minimum threshold %s must remain 1, got %v", name, value)
		}
	}

	seen := map[string]string{}
	register := func(kind, id string) {
		t.Helper()
		if strings.TrimSpace(id) == "" {
			t.Fatalf("%s contains an empty case id", kind)
		}
		if previous, ok := seen[id]; ok {
			t.Fatalf("duplicate case id %q in %s and %s", id, previous, kind)
		}
		seen[id] = kind
	}
	validationCases := make(map[string]validationCase, len(d.ValidationCases))
	for _, c := range d.ValidationCases {
		register("validation_cases", c.ID)
		validationCases[c.ID] = c
	}
	for _, c := range d.HunterCases {
		register("hunter_cases", c.ID)
	}
	for _, c := range d.SecretRegexCases {
		register("secret_regex_cases", c.ID)
	}
	for _, c := range d.JSAICases {
		register("js_ai_cases", c.ID)
	}

	labels := make(map[string]validationLabel, len(oracle.ValidationLabels))
	positive, negative := 0, 0
	positiveFamilies := map[string]struct{}{}
	negativeFamilies := map[string]struct{}{}
	for _, label := range oracle.ValidationLabels {
		if _, duplicate := labels[label.CaseID]; duplicate {
			t.Errorf("duplicate validation oracle label for %q", label.CaseID)
			continue
		}
		labels[label.CaseID] = label
		if _, ok := validationCases[label.CaseID]; !ok {
			t.Errorf("validation oracle references unknown case %q", label.CaseID)
		}
		switch label.ExpectedDisposition {
		case "confirmed", "manual-review", "rejected":
		default:
			t.Errorf("%s has invalid oracle disposition %q", label.CaseID, label.ExpectedDisposition)
		}
		switch label.Control {
		case "positive":
			positive++
			positiveFamilies[label.Family] = struct{}{}
			if label.ExpectedDisposition != "confirmed" {
				t.Errorf("positive control %q must expect confirmed, got %q", label.CaseID, label.ExpectedDisposition)
			}
		case "negative":
			negative++
			negativeFamilies[label.Family] = struct{}{}
			if label.ExpectedDisposition == "confirmed" {
				t.Errorf("negative control %q cannot expect confirmed", label.CaseID)
			}
		default:
			t.Errorf("%s has invalid control label %q", label.CaseID, label.Control)
		}
		if strings.TrimSpace(label.Family) == "" {
			t.Errorf("validation oracle %q has no independent evidence family", label.CaseID)
		}
		if strings.TrimSpace(label.Rationale) == "" {
			t.Errorf("validation oracle %q has no rationale", label.CaseID)
		}
		if len(label.Categories) == 0 {
			t.Errorf("validation oracle %q has no metric category", label.CaseID)
		}
		seenCategories := map[string]struct{}{}
		for _, category := range label.Categories {
			if strings.TrimSpace(category) == "" {
				t.Errorf("validation oracle %q has an empty metric category", label.CaseID)
			}
			if _, duplicate := seenCategories[category]; duplicate {
				t.Errorf("validation oracle %q repeats category %q", label.CaseID, category)
			}
			seenCategories[category] = struct{}{}
		}
		if label.ExpectedProviderCalls < 0 || label.ExpectedProviderCalls > 1 {
			t.Errorf("validation oracle %q expected_provider_calls must be 0 or 1", label.CaseID)
		}
		stimulus, stimulusOK := validationCases[label.CaseID]
		if !stimulusOK {
			continue
		}
		if label.ExpectedProviderCalls == 0 {
			if label.ExpectedUserSentinel != "" || label.ExpectedUserSentinelField != "" {
				t.Errorf("validation oracle %q has a request sentinel despite expecting no provider call", label.CaseID)
			}
		} else {
			if len(label.ExpectedUserSentinel) < 12 {
				t.Errorf("validation oracle %q request sentinel is empty or too short to be case-specific", label.CaseID)
			}
			source, ok := validationSentinelSource(stimulus.Finding, label.ExpectedUserSentinelField)
			if !ok {
				t.Errorf("validation oracle %q has invalid sentinel field %q", label.CaseID, label.ExpectedUserSentinelField)
			} else if count := strings.Count(source, label.ExpectedUserSentinel); count != 1 {
				t.Errorf("validation oracle %q sentinel occurs %d times in finding.%s, want exactly 1",
					label.CaseID, count, label.ExpectedUserSentinelField)
			}
		}
		triage := label.ExpectedTriage
		switch triage.Severity {
		case "critical", "high", "medium", "low", "info":
		default:
			t.Errorf("validation oracle %q has invalid triage severity %q", label.CaseID, triage.Severity)
		}
		if triage.Confidence < 0 || triage.Confidence > 1 {
			t.Errorf("validation oracle %q triage confidence is outside [0,1]", label.CaseID)
		}
		if triage.EvidenceRefs == nil || triage.MissingEvidence == nil {
			t.Errorf("validation oracle %q triage arrays must be explicit JSON arrays", label.CaseID)
		}
		if strings.TrimSpace(triage.Analysis) == "" {
			t.Errorf("validation oracle %q has no triage analysis", label.CaseID)
		}
		if triage.ProofOfConcept != "" && !strings.HasPrefix(triage.ProofOfConcept, "[MODEL-GENERATED, NOT EXECUTED] ") {
			t.Errorf("validation oracle %q contains an unlabeled model PoC", label.CaseID)
		}
		if triage.CybersecurityContext != "" && !strings.HasPrefix(triage.CybersecurityContext, "[MODEL-GENERATED, NOT INDEPENDENTLY VERIFIED] ") {
			t.Errorf("validation oracle %q contains unlabeled model cybersecurity context", label.CaseID)
		}
		if label.ExpectedDisposition == "confirmed" &&
			(strings.TrimSpace(triage.ImpactAssessment) == "" || strings.TrimSpace(triage.Remediation) == "" || strings.TrimSpace(triage.BugBountyValue) == "") {
			t.Errorf("confirmed oracle %q must define impact, remediation, and bounty value", label.CaseID)
		}
	}
	if positive == 0 || negative == 0 {
		t.Fatalf("oracle must contain labeled positive and negative controls; got positive=%d negative=%d", positive, negative)
	}
	if len(positiveFamilies) < 2 || len(negativeFamilies) < 3 {
		t.Fatalf("oracle lacks independent evidence families: positive=%d (min 2), negative=%d (min 3)",
			len(positiveFamilies), len(negativeFamilies))
	}
	for id := range validationCases {
		if _, ok := labels[id]; !ok {
			t.Errorf("validation case %q has no independent oracle label", id)
		}
	}

	assertExactOracleCoverage(t, "hunter", caseIDsFromHunter(d.HunterCases), hunterExpectationIDs(oracle.HunterExpectations))
	assertExactOracleCoverage(t, "secret-regex", caseIDsFromSecretRegex(d.SecretRegexCases), secretRegexExpectationIDs(oracle.SecretRegexExpectations))
	assertExactOracleCoverage(t, "js-ai", caseIDsFromJSAI(d.JSAICases), jsAIExpectationIDs(oracle.JSAIExpectations))
	hunterCases := make(map[string]hunterCase, len(d.HunterCases))
	for _, c := range d.HunterCases {
		hunterCases[c.ID] = c
	}
	for _, expected := range oracle.HunterExpectations {
		if len(expected.ExpectedHypotheses) == 0 {
			t.Errorf("hunter oracle %q has no expected returned hypotheses", expected.CaseID)
			continue
		}
		stimulus, stimulusOK := hunterCases[expected.CaseID]
		if !stimulusOK {
			t.Errorf("hunter oracle %q has no stimulus", expected.CaseID)
			continue
		}
		oracleKeys := map[string]string{}
		for _, hypothesis := range expected.ExpectedHypotheses {
			key, err := hunterIdentityKey(hypothesis.hunterHypothesisIdentity)
			if err != nil {
				t.Errorf("hunter oracle %q has invalid expected hypothesis: %v", expected.CaseID, err)
				continue
			}
			if previous, duplicate := oracleKeys[key]; duplicate {
				t.Errorf("hunter oracle %q repeats hypothesis %q in %s and expected_hypotheses", expected.CaseID, key, previous)
			}
			oracleKeys[key] = "expected_hypotheses"
			if hypothesis.ExpectedGrounding != "observed" && hypothesis.ExpectedGrounding != "inferred" {
				t.Errorf("hunter oracle %q has invalid grounding %q", expected.CaseID, hypothesis.ExpectedGrounding)
			}
			if hypothesis.ExpectedConfidence < 0 || hypothesis.ExpectedConfidence > 1 {
				t.Errorf("hunter oracle %q confidence is outside [0,1]", expected.CaseID)
			}
		}
		droppedKeys := map[string]struct{}{}
		for _, hypothesis := range expected.ExpectedDropped {
			key, err := hunterIdentityKey(hypothesis)
			if err != nil {
				t.Errorf("hunter oracle %q has invalid dropped hypothesis: %v", expected.CaseID, err)
				continue
			}
			if previous, duplicate := oracleKeys[key]; duplicate {
				t.Errorf("hunter oracle %q repeats hypothesis %q in %s and expected_dropped", expected.CaseID, key, previous)
			}
			oracleKeys[key] = "expected_dropped"
			droppedKeys[key] = struct{}{}
		}
		offScopeKeys := map[string]struct{}{}
		for _, hypothesis := range expected.ExpectedOffScope {
			key, err := hunterIdentityKey(hypothesis)
			if err != nil {
				t.Errorf("hunter oracle %q has invalid off-scope hypothesis: %v", expected.CaseID, err)
				continue
			}
			if _, duplicate := offScopeKeys[key]; duplicate {
				t.Errorf("hunter oracle %q repeats off-scope hypothesis %q", expected.CaseID, key)
			}
			offScopeKeys[key] = struct{}{}
			if _, dropped := droppedKeys[key]; !dropped {
				t.Errorf("hunter oracle %q labels off-scope hypothesis %q outside expected_dropped", expected.CaseID, key)
			}
			if hostAllowedByEvalOracle(hypothesis.Target, stimulus.TargetDomains) {
				t.Errorf("hunter oracle %q labels in-scope hypothesis %q as off-scope", expected.CaseID, key)
			}
		}
		providerKeys := map[string]struct{}{}
		providerOffScopeKeys := map[string]struct{}{}
		for _, hypothesis := range stimulus.ProviderHypotheses {
			key, err := hunterIdentityKey(identityFromHypothesis(hypothesis))
			if err != nil {
				t.Errorf("hunter stimulus %q has invalid hypothesis: %v", expected.CaseID, err)
				continue
			}
			if _, duplicate := providerKeys[key]; duplicate {
				t.Errorf("hunter stimulus %q repeats identity %q", expected.CaseID, key)
			}
			providerKeys[key] = struct{}{}
			if !hostAllowedByEvalOracle(hypothesis.Target, stimulus.TargetDomains) {
				providerOffScopeKeys[key] = struct{}{}
			}
		}
		if !sameStringSet(keysOfStringMap(oracleKeys), keysOfSet(providerKeys)) {
			t.Errorf("hunter oracle %q identities do not exactly cover provider hypotheses", expected.CaseID)
		}
		if !sameStringSet(keysOfSet(offScopeKeys), keysOfSet(providerOffScopeKeys)) {
			t.Errorf("hunter oracle %q off-scope identities do not exactly match evaluator-owned scope labels", expected.CaseID)
		}
	}
	regexPositive, regexNegative := 0, 0
	for _, expected := range oracle.SecretRegexExpectations {
		switch expected.Control {
		case "positive":
			regexPositive++
			if len(expected.ExpectedPatterns) == 0 {
				t.Errorf("secret-regex positive control %q has no expected pattern", expected.CaseID)
			}
		case "negative":
			regexNegative++
			if len(expected.ExpectedPatterns) != 0 {
				t.Errorf("secret-regex negative control %q expects patterns %v", expected.CaseID, expected.ExpectedPatterns)
			}
		default:
			t.Errorf("secret-regex oracle %q has invalid control %q", expected.CaseID, expected.Control)
		}
		seenPatterns := map[string]struct{}{}
		for _, pattern := range expected.ExpectedPatterns {
			if strings.TrimSpace(pattern) == "" {
				t.Errorf("secret-regex oracle %q has an empty expected pattern", expected.CaseID)
			}
			if _, duplicate := seenPatterns[pattern]; duplicate {
				t.Errorf("secret-regex oracle %q repeats pattern %q", expected.CaseID, pattern)
			}
			seenPatterns[pattern] = struct{}{}
		}
	}
	if regexPositive < 2 || regexNegative == 0 {
		t.Fatalf("secret-regex oracle requires at least 2 positive controls and 1 negative; got positive=%d negative=%d", regexPositive, regexNegative)
	}
	jsCases := make(map[string]jsAICase, len(d.JSAICases))
	for _, c := range d.JSAICases {
		jsCases[c.ID] = c
	}
	jsPositiveControls, jsNegativeControls := 0, 0
	hasIndexedPositive := false
	hasInventedLiteralNegative := false
	hasWrongIndexNegative := false
	for _, expected := range oracle.JSAIExpectations {
		stimulus, stimulusOK := jsCases[expected.CaseID]
		if !stimulusOK {
			t.Errorf("js-ai oracle %q has no stimulus", expected.CaseID)
			continue
		}
		if len(stimulus.Files) == 0 {
			t.Errorf("js-ai stimulus %q has no source files", expected.CaseID)
		}
		if len(expected.ExpectedCandidates) == 0 {
			jsNegativeControls++
		} else {
			jsPositiveControls++
		}
		if len(expected.ExpectedUserSentinel) < 12 {
			t.Errorf("js-ai oracle %q request sentinel is empty or too short to be case-specific", expected.CaseID)
		}
		sentinelOccurrences := 0
		fileURLs := map[string]struct{}{}
		for _, file := range stimulus.Files {
			if strings.TrimSpace(file.URL) == "" || strings.TrimSpace(file.Content) == "" {
				t.Errorf("js-ai stimulus %q has an empty source URL or content", expected.CaseID)
			}
			if _, duplicate := fileURLs[file.URL]; duplicate {
				t.Errorf("js-ai stimulus %q repeats source URL %q", expected.CaseID, file.URL)
			}
			fileURLs[file.URL] = struct{}{}
			sentinelOccurrences += strings.Count(file.Content, expected.ExpectedUserSentinel)
		}
		if sentinelOccurrences != 1 {
			t.Errorf("js-ai oracle %q sentinel occurs %d times in source content, want exactly 1", expected.CaseID, sentinelOccurrences)
		}
		providerByKey := make(map[string]jsProviderFinding, len(stimulus.ProviderFindings))
		for _, finding := range stimulus.ProviderFindings {
			key, err := jsProviderFindingKey(finding)
			if err != nil {
				t.Errorf("js-ai stimulus %q has invalid provider finding: %v", expected.CaseID, err)
				continue
			}
			if _, duplicate := providerByKey[key]; duplicate {
				t.Errorf("js-ai stimulus %q repeats provider identity %q", expected.CaseID, key)
			}
			providerByKey[key] = finding
			if len(expected.ExpectedCandidates) == 0 {
				valueFound := false
				valueAtClaimedURL := false
				for _, file := range stimulus.Files {
					if strings.Contains(file.Content, finding.Value) {
						valueFound = true
						if file.URL == finding.FileURL {
							valueAtClaimedURL = true
						}
					}
				}
				if !valueFound {
					hasInventedLiteralNegative = true
				}
				if finding.FileIndex >= 0 && finding.FileIndex < len(stimulus.Files) &&
					stimulus.Files[finding.FileIndex].URL != finding.FileURL && valueAtClaimedURL {
					hasWrongIndexNegative = true
				}
			}
		}
		seenCandidates := map[string]struct{}{}
		for _, candidate := range expected.ExpectedCandidates {
			key, err := expectedJSCandidateKey(candidate)
			if err != nil {
				t.Errorf("js-ai oracle %q has invalid candidate: %v", expected.CaseID, err)
				continue
			}
			if _, duplicate := seenCandidates[key]; duplicate {
				t.Errorf("js-ai oracle %q repeats candidate %q", expected.CaseID, key)
			}
			seenCandidates[key] = struct{}{}
			providerFinding, ok := providerByKey[key]
			if !ok {
				t.Errorf("js-ai oracle %q candidate %q has no uniquely identified provider finding", expected.CaseID, key)
				continue
			}
			if providerFinding.FileIndex < 0 || providerFinding.FileIndex >= len(stimulus.Files) {
				t.Errorf("js-ai oracle %q candidate %q has out-of-range provider file_index=%d", expected.CaseID, key, providerFinding.FileIndex)
				continue
			}
			if providerFinding.FileIndex > 0 {
				hasIndexedPositive = true
			}
			source := stimulus.Files[providerFinding.FileIndex]
			digest := fmt.Sprintf("%x", sha256.Sum256([]byte(providerFinding.Value)))
			if candidate.SourceLiteralSHA256 != digest {
				t.Errorf("js-ai oracle %q candidate %q source digest does not match its provider literal", expected.CaseID, key)
			}
			if !strings.HasPrefix(candidate.ExpectedEvidence, "[REDACTED type=") ||
				!strings.HasSuffix(candidate.ExpectedEvidence, "]") || !candidate.ExpectedGrounded {
				t.Errorf("js-ai oracle %q candidate %q lacks safe runtime provenance expectations", expected.CaseID, key)
			}
			if providerFinding.FileURL != source.URL || !strings.Contains(source.Content, providerFinding.Value) {
				t.Errorf("js-ai oracle %q candidate %q is not an exact literal from the claimed source file", expected.CaseID, key)
			}
			switch candidate.ExpectedDisposition {
			case "confirmed", "manual-review", "rejected":
			default:
				t.Errorf("js-ai oracle %q has invalid disposition %q", expected.CaseID, candidate.ExpectedDisposition)
			}
		}
	}
	if jsPositiveControls == 0 || jsNegativeControls == 0 {
		t.Fatalf("js-ai oracle requires positive and negative grounding controls; got positive=%d negative=%d",
			jsPositiveControls, jsNegativeControls)
	}
	if !hasIndexedPositive || !hasInventedLiteralNegative || !hasWrongIndexNegative {
		t.Fatalf("js-ai corpus lacks provenance controls: indexed_positive=%t invented_literal_negative=%t wrong_index_negative=%t",
			hasIndexedPositive, hasInventedLiteralNegative, hasWrongIndexNegative)
	}

	if len(oracle.CounterfactualPairs) == 0 {
		t.Fatal("oracle must contain at least one counterfactual pair")
	}
	pairedCases := map[string]string{}
	pairIDs := map[string]struct{}{}
	for _, pair := range oracle.CounterfactualPairs {
		if strings.TrimSpace(pair.ID) == "" || strings.TrimSpace(pair.Dimension) == "" {
			t.Errorf("counterfactual pair has empty id or dimension: %#v", pair)
			continue
		}
		if _, duplicate := pairIDs[pair.ID]; duplicate {
			t.Errorf("duplicate counterfactual pair id %q", pair.ID)
		}
		pairIDs[pair.ID] = struct{}{}
		if len(pair.CaseIDs) != 2 || pair.CaseIDs[0] == pair.CaseIDs[1] {
			t.Errorf("counterfactual pair %q must contain two distinct case ids", pair.ID)
			continue
		}
		left, leftOK := validationCases[pair.CaseIDs[0]]
		right, rightOK := validationCases[pair.CaseIDs[1]]
		if !leftOK || !rightOK {
			t.Errorf("counterfactual pair %q references an unknown case", pair.ID)
			continue
		}
		leftLabel, leftLabelOK := labels[left.ID]
		rightLabel, rightLabelOK := labels[right.ID]
		if !leftLabelOK || !rightLabelOK {
			t.Errorf("counterfactual pair %q lacks oracle labels", pair.ID)
			continue
		}
		if leftLabel.ExpectedDisposition != rightLabel.ExpectedDisposition || leftLabel.Control != rightLabel.Control || leftLabel.Family != rightLabel.Family {
			t.Errorf("counterfactual pair %q does not share one oracle class", pair.ID)
		}
		if leftLabel.ExpectedProviderCalls != rightLabel.ExpectedProviderCalls {
			t.Errorf("counterfactual pair %q has different provider-call expectations", pair.ID)
		}
		if err := validateMatchedCounterfactual(pair, left, right); err != nil {
			t.Errorf("counterfactual pair %q is not evidence-matched: %v", pair.ID, err)
		}
		for _, id := range pair.CaseIDs {
			if previous, duplicate := pairedCases[id]; duplicate {
				t.Errorf("case %q appears in counterfactual pairs %q and %q", id, previous, pair.ID)
			}
			pairedCases[id] = pair.ID
		}
	}
}

func TestClassificationControlMetrics(t *testing.T) {
	d := loadDataset(t)
	oracle := loadOracle(t)
	labels := validationLabelMap(t, oracle)
	correct := 0
	correctTriageVectors := 0
	positiveControls := 0
	positiveConfirmed := 0
	positiveFamilyPassed := map[string]bool{}
	negativeControls := 0
	negativeNotConfirmed := 0
	falseConfirmations := 0
	adversarial := 0
	adversarialConfirmations := 0

	// Compute denominators from the independent oracle, not from successful
	// fixture execution. A broken case must not make a rate look perfect through
	// an accidental zero denominator.
	for _, c := range d.ValidationCases {
		label := requireValidationLabel(t, labels, c.ID)
		switch label.Control {
		case "positive":
			positiveControls++
			positiveFamilyPassed[label.Family] = true
		case "negative":
			negativeControls++
		}
		if hasTag(label.Categories, "post-model-adversarial") {
			adversarial++
		}
	}
	if positiveControls == 0 || negativeControls == 0 || adversarial == 0 {
		t.Fatalf("metric denominators must be non-zero: positive=%d negative=%d adversarial=%d",
			positiveControls, negativeControls, adversarial)
	}

	for _, c := range d.ValidationCases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			label := requireValidationLabel(t, labels, c.ID)
			outcome := runValidationCase(t, c, label.ExpectedProviderCalls, label.ExpectedUserSentinel)
			actual := outcome.Disposition
			expectedVector := triageVectorFromLabel(label)
			if reflect.DeepEqual(normalizeTriageVector(outcome), normalizeTriageVector(expectedVector)) {
				correctTriageVectors++
			} else {
				t.Errorf("triage vector = %#v, oracle wants %#v", outcome, expectedVector)
			}
			if actual == label.ExpectedDisposition {
				correct++
			} else {
				t.Errorf("disposition = %q, oracle wants %q", actual, label.ExpectedDisposition)
			}
			switch label.Control {
			case "positive":
				if actual == "confirmed" {
					positiveConfirmed++
				} else {
					positiveFamilyPassed[label.Family] = false
				}
			case "negative":
				if actual == "confirmed" {
					falseConfirmations++
				} else {
					negativeNotConfirmed++
				}
			}
			if hasTag(label.Categories, "post-model-adversarial") && actual == "confirmed" {
				adversarialConfirmations++
			}
		})
	}

	falseConfirmationRate := ratio(t, falseConfirmations, negativeControls)
	dispositionAccuracy := ratio(t, correct, len(d.ValidationCases))
	triageVectorAccuracy := ratio(t, correctTriageVectors, len(d.ValidationCases))
	positiveControlRecall := ratio(t, positiveConfirmed, positiveControls)
	passedPositiveFamilies := 0
	for _, passed := range positiveFamilyPassed {
		if passed {
			passedPositiveFamilies++
		}
	}
	positiveFamilyRecall := ratio(t, passedPositiveFamilies, len(positiveFamilyPassed))
	negativeControlSpecificity := ratio(t, negativeNotConfirmed, negativeControls)
	postModelAdversarialConfirmationRate := ratio(t, adversarialConfirmations, adversarial)
	t.Logf("metric false_confirmation_rate=%.3f (%d/%d)", falseConfirmationRate, falseConfirmations, negativeControls)
	t.Logf("metric disposition_accuracy=%.3f (%d/%d)", dispositionAccuracy, correct, len(d.ValidationCases))
	t.Logf("metric triage_vector_accuracy=%.3f (%d/%d)", triageVectorAccuracy, correctTriageVectors, len(d.ValidationCases))
	t.Logf("metric positive_control_recall=%.3f (%d/%d)", positiveControlRecall, positiveConfirmed, positiveControls)
	t.Logf("metric positive_family_recall=%.3f (%d/%d)", positiveFamilyRecall, passedPositiveFamilies, len(positiveFamilyPassed))
	t.Logf("metric negative_control_specificity=%.3f (%d/%d)", negativeControlSpecificity, negativeNotConfirmed, negativeControls)
	t.Logf("metric post_model_adversarial_confirmation_rate=%.3f (%d/%d)", postModelAdversarialConfirmationRate, adversarialConfirmations, adversarial)

	if falseConfirmationRate > d.Thresholds.MaxFalseConfirmationRate {
		t.Errorf("false_confirmation_rate %.3f exceeds %.3f", falseConfirmationRate, d.Thresholds.MaxFalseConfirmationRate)
	}
	if dispositionAccuracy < d.Thresholds.MinDispositionAccuracy {
		t.Errorf("disposition_accuracy %.3f is below %.3f", dispositionAccuracy, d.Thresholds.MinDispositionAccuracy)
	}
	if triageVectorAccuracy < d.Thresholds.MinTriageVectorAccuracy {
		t.Errorf("triage_vector_accuracy %.3f is below %.3f", triageVectorAccuracy, d.Thresholds.MinTriageVectorAccuracy)
	}
	if positiveControlRecall < d.Thresholds.MinPositiveControlRecall {
		t.Errorf("positive_control_recall %.3f is below %.3f", positiveControlRecall, d.Thresholds.MinPositiveControlRecall)
	}
	if positiveFamilyRecall < d.Thresholds.MinPositiveFamilyRecall {
		t.Errorf("positive_family_recall %.3f is below %.3f", positiveFamilyRecall, d.Thresholds.MinPositiveFamilyRecall)
	}
	if negativeControlSpecificity < d.Thresholds.MinNegativeControlSpecificity {
		t.Errorf("negative_control_specificity %.3f is below %.3f", negativeControlSpecificity, d.Thresholds.MinNegativeControlSpecificity)
	}
	if postModelAdversarialConfirmationRate > d.Thresholds.MaxPostModelAdversarialConfirmationRate {
		t.Errorf("post_model_adversarial_confirmation_rate %.3f exceeds %.3f",
			postModelAdversarialConfirmationRate, d.Thresholds.MaxPostModelAdversarialConfirmationRate)
	}
}

func TestCounterfactualTriageParityMetric(t *testing.T) {
	d := loadDataset(t)
	oracle := loadOracle(t)
	cases := validationCaseMap(t, d.ValidationCases)
	labels := validationLabelMap(t, oracle)
	disparatePairs := 0

	for _, pair := range oracle.CounterfactualPairs {
		pair := pair
		t.Run(pair.ID, func(t *testing.T) {
			if len(pair.CaseIDs) != 2 {
				t.Fatalf("counterfactual pair has %d cases, want 2", len(pair.CaseIDs))
			}
			leftLabel := requireValidationLabel(t, labels, pair.CaseIDs[0])
			rightLabel := requireValidationLabel(t, labels, pair.CaseIDs[1])
			left := runValidationCase(t, requireValidationCase(t, cases, pair.CaseIDs[0]),
				leftLabel.ExpectedProviderCalls, leftLabel.ExpectedUserSentinel)
			right := runValidationCase(t, requireValidationCase(t, cases, pair.CaseIDs[1]),
				rightLabel.ExpectedProviderCalls, rightLabel.ExpectedUserSentinel)
			if !reflect.DeepEqual(left, right) {
				disparatePairs++
				t.Errorf("triage vector differs across %s counterfactual: %#v versus %#v", pair.Dimension, left, right)
			}
		})
	}

	disparityRate := ratio(t, disparatePairs, len(oracle.CounterfactualPairs))
	t.Logf("metric counterfactual_triage_disparity_rate=%.3f (%d/%d)", disparityRate, disparatePairs, len(oracle.CounterfactualPairs))
	if disparityRate > d.Thresholds.MaxCounterfactualDisparityRate {
		t.Errorf("counterfactual_triage_disparity_rate %.3f exceeds %.3f", disparityRate, d.Thresholds.MaxCounterfactualDisparityRate)
	}
}

func TestHunterScopeAndGroundingMetrics(t *testing.T) {
	d := loadDataset(t)
	oracle := loadOracle(t)
	expectations := hunterExpectationMap(t, oracle)
	totalExpectedReturned := 0
	totalExpectedOffScope := 0
	offScopeReturned := 0
	unexpectedReturned := 0
	totalExpectedGrounding := 0
	correctGrounding := 0

	// Oracle-derived denominators stay stable even when a pipeline regression
	// drops every item.
	for _, expected := range oracle.HunterExpectations {
		totalExpectedReturned += len(expected.ExpectedHypotheses)
		totalExpectedOffScope += len(expected.ExpectedOffScope)
		totalExpectedGrounding += len(expected.ExpectedHypotheses)
	}

	for _, c := range d.HunterCases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			expected := requireHunterExpectation(t, expectations, c.ID)
			response, err := json.Marshal(struct {
				Hypotheses []hunter.Hypothesis `json:"hypotheses"`
			}{Hypotheses: c.ProviderHypotheses})
			if err != nil {
				t.Fatal(err)
			}
			provider := &scriptedProvider{response: string(response)}
			log := logger.New(false)
			t.Cleanup(log.Close)
			engine := hunter.NewEngineWithProvider(&config.Config{
				Target: config.TargetConfig{Domains: c.TargetDomains},
				Hunter: config.HunterConfig{Enabled: true, MaxHypotheses: 100, MaxEndpoints: 100},
			}, log, provider)

			got, err := engine.Generate(context.Background(), &c.Recon)
			if err != nil {
				t.Fatalf("Generate: %v", err)
			}
			if provider.calls != 1 {
				t.Fatalf("provider calls = %d, want 1", provider.calls)
			}
			if len(got) != len(expected.ExpectedHypotheses) {
				t.Errorf("kept hypotheses = %d, oracle wants %d", len(got), len(expected.ExpectedHypotheses))
			}

			expectedByKey := make(map[string]expectedHunterHypothesis, len(expected.ExpectedHypotheses))
			for _, hypothesis := range expected.ExpectedHypotheses {
				key, err := hunterIdentityKey(hypothesis.hunterHypothesisIdentity)
				if err != nil {
					t.Fatalf("invalid oracle hypothesis: %v", err)
				}
				expectedByKey[key] = hypothesis
			}

			actualByKey := make(map[string]hunter.Hypothesis, len(got))
			for i, h := range got {
				if !hostAllowedByEvalOracle(h.Target, c.TargetDomains) {
					offScopeReturned++
				}
				key, err := hunterIdentityKey(identityFromHypothesis(h))
				if err != nil {
					t.Errorf("returned invalid hypothesis identity: %v", err)
					continue
				}
				if _, duplicate := actualByKey[key]; duplicate {
					t.Errorf("returned duplicate hypothesis identity %q", key)
				}
				actualByKey[key] = h
				if i > 0 && got[i-1].Grounding == "inferred" && h.Grounding == "observed" {
					t.Errorf("observed hypothesis ranked behind inferred hypothesis")
				}
			}

			for key, oracleHypothesis := range expectedByKey {
				actual, ok := actualByKey[key]
				if !ok {
					t.Errorf("missing oracle hypothesis %q", key)
					continue
				}
				if actual.Grounding != oracleHypothesis.ExpectedGrounding ||
					math.Abs(actual.Confidence-oracleHypothesis.ExpectedConfidence) > 1e-9 {
					t.Errorf("hypothesis %q grounding/confidence = %q/%.2f, oracle wants %q/%.2f",
						key, actual.Grounding, actual.Confidence,
						oracleHypothesis.ExpectedGrounding, oracleHypothesis.ExpectedConfidence)
					continue
				}
				correctGrounding++
			}
			for key := range actualByKey {
				if _, ok := expectedByKey[key]; !ok {
					unexpectedReturned++
					t.Errorf("returned hypothesis %q is absent from oracle", key)
				}
			}

			returnedKeys := keysOfHypothesisMap(actualByKey)
			actualDropped := make([]string, 0, len(c.ProviderHypotheses)-len(got))
			returnedSet := stringSliceSet(returnedKeys)
			for _, hypothesis := range c.ProviderHypotheses {
				key, err := hunterIdentityKey(identityFromHypothesis(hypothesis))
				if err != nil {
					t.Fatalf("invalid provider hypothesis identity: %v", err)
				}
				if _, returned := returnedSet[key]; !returned {
					actualDropped = append(actualDropped, key)
				}
			}
			expectedDropped := make([]string, 0, len(expected.ExpectedDropped))
			for _, hypothesis := range expected.ExpectedDropped {
				key, err := hunterIdentityKey(hypothesis)
				if err != nil {
					t.Fatalf("invalid dropped oracle hypothesis: %v", err)
				}
				expectedDropped = append(expectedDropped, key)
			}
			sort.Strings(actualDropped)
			sort.Strings(expectedDropped)
			if !reflect.DeepEqual(actualDropped, expectedDropped) {
				t.Errorf("dropped hypotheses = %v, oracle wants %v", actualDropped, expectedDropped)
			}
		})
	}

	offScopeAcceptanceRate := ratio(t, offScopeReturned, totalExpectedOffScope)
	groundingErrors := totalExpectedGrounding - correctGrounding
	groundingErrorRate := ratio(t, groundingErrors, totalExpectedGrounding)
	unexpectedHypothesisRate := ratio(t, unexpectedReturned, totalExpectedReturned)
	t.Logf("metric off_scope_acceptance_rate=%.3f (%d/%d)", offScopeAcceptanceRate, offScopeReturned, totalExpectedOffScope)
	t.Logf("metric grounding_error_rate=%.3f (%d/%d)", groundingErrorRate, groundingErrors, totalExpectedGrounding)
	t.Logf("metric unexpected_hypothesis_rate=%.3f (%d/%d)", unexpectedHypothesisRate, unexpectedReturned, totalExpectedReturned)
	if offScopeAcceptanceRate > d.Thresholds.MaxOffScopeAcceptanceRate {
		t.Errorf("off_scope_acceptance_rate %.3f exceeds %.3f", offScopeAcceptanceRate, d.Thresholds.MaxOffScopeAcceptanceRate)
	}
	if groundingErrorRate > d.Thresholds.MaxGroundingErrorRate {
		t.Errorf("grounding_error_rate %.3f exceeds %.3f", groundingErrorRate, d.Thresholds.MaxGroundingErrorRate)
	}
	if unexpectedHypothesisRate > d.Thresholds.MaxUnexpectedHypothesisRate {
		t.Errorf("unexpected_hypothesis_rate %.3f exceeds %.3f", unexpectedHypothesisRate, d.Thresholds.MaxUnexpectedHypothesisRate)
	}
}

func TestSecretRegexControlMetrics(t *testing.T) {
	d := loadDataset(t)
	oracle := loadOracle(t)
	expectations := secretRegexExpectationMap(t, oracle)
	negativeControls := 0
	acceptedDecoys := 0
	expectedPositivePatterns := 0
	detectedPositivePatterns := 0
	for _, expected := range oracle.SecretRegexExpectations {
		if expected.Control == "negative" {
			negativeControls++
		} else if expected.Control == "positive" {
			expectedPositivePatterns += len(expected.ExpectedPatterns)
		}
	}
	if negativeControls == 0 || expectedPositivePatterns == 0 {
		t.Fatalf("secret-regex metric denominators must be non-zero: negative=%d expected_positive_patterns=%d",
			negativeControls, expectedPositivePatterns)
	}

	for _, c := range d.SecretRegexCases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			expected := requireSecretRegexExpectation(t, expectations, c.ID)
			findings := analyzer.ScanJSWithRegex([]struct {
				URL     string
				Content string
				Size    int
				Source  string
			}{{
				URL:     "https://app.example.com/eval.js",
				Content: c.Content,
				Size:    len(c.Content),
				Source:  "eval",
			}})
			actualPatterns := regexFindingPatterns(findings)
			expectedPatterns := append([]string(nil), expected.ExpectedPatterns...)
			sort.Strings(expectedPatterns)
			if expected.Control == "negative" && len(actualPatterns) > 0 {
				acceptedDecoys++
			}
			actualSet := make(map[string]struct{}, len(actualPatterns))
			for _, pattern := range actualPatterns {
				actualSet[pattern] = struct{}{}
			}
			if expected.Control == "positive" {
				for _, pattern := range expectedPatterns {
					if _, ok := actualSet[pattern]; ok {
						detectedPositivePatterns++
					}
				}
			}
			if !sameStringSet(actualPatterns, expectedPatterns) {
				t.Errorf("detected patterns = %v, oracle wants %v (findings=%v)", actualPatterns, expectedPatterns, findingTypes(findings))
			}
			if len(findings) != len(expectedPatterns) {
				t.Errorf("finding count = %d, oracle wants %d unique findings", len(findings), len(expectedPatterns))
			}
		})
	}

	acceptanceRate := ratio(t, acceptedDecoys, negativeControls)
	recall := ratio(t, detectedPositivePatterns, expectedPositivePatterns)
	t.Logf("metric fake_secret_acceptance_rate=%.3f (%d/%d)", acceptanceRate, acceptedDecoys, negativeControls)
	t.Logf("metric secret_regex_recall=%.3f (%d/%d)", recall, detectedPositivePatterns, expectedPositivePatterns)
	if acceptanceRate > d.Thresholds.MaxFakeSecretAcceptanceRate {
		t.Errorf("fake_secret_acceptance_rate %.3f exceeds %.3f", acceptanceRate, d.Thresholds.MaxFakeSecretAcceptanceRate)
	}
	if recall < d.Thresholds.MinSecretRegexRecall {
		t.Errorf("secret_regex_recall %.3f is below %.3f", recall, d.Thresholds.MinSecretRegexRecall)
	}
}

func TestAIJavaScriptGroundingAndFinalDisposition(t *testing.T) {
	d := loadDataset(t)
	oracle := loadOracle(t)
	expectations := jsAIExpectationMap(t, oracle)
	totalExpectedCandidates := 0
	totalConfirmed := 0
	for _, expected := range oracle.JSAIExpectations {
		totalExpectedCandidates += len(expected.ExpectedCandidates)
	}

	for _, c := range d.JSAICases {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			expected := requireJSAIExpectation(t, expectations, c.ID)
			content, err := json.Marshal(struct {
				Findings []jsProviderFinding `json:"findings"`
			}{Findings: c.ProviderFindings})
			if err != nil {
				t.Fatal(err)
			}
			provider := newScriptedProvider(t, string(content), []string{expected.ExpectedUserSentinel})
			log := logger.New(false)
			t.Cleanup(log.Close)
			engine := analyzer.NewEngineWithProvider(evalConfig(), log, provider)

			files := make([]struct {
				URL     string
				Content string
				Size    int
				Source  string
			}, 0, len(c.Files))
			for _, file := range c.Files {
				files = append(files, struct {
					URL     string
					Content string
					Size    int
					Source  string
				}{URL: file.URL, Content: file.Content, Size: len(file.Content), Source: "eval"})
			}
			candidates, err := engine.AnalyzeJSFiles(context.Background(), files)
			if err != nil {
				t.Fatalf("AnalyzeJSFiles: %v", err)
			}
			expectedByKey := make(map[string]expectedJSCandidate, len(expected.ExpectedCandidates))
			for _, candidate := range expected.ExpectedCandidates {
				key, err := expectedJSCandidateKey(candidate)
				if err != nil {
					t.Fatalf("invalid JS oracle candidate: %v", err)
				}
				expectedByKey[key] = candidate
			}
			actualCandidates := make(map[string]scanner.Finding, len(candidates))
			for _, candidate := range candidates {
				key, err := jsFindingKey(candidate)
				if err != nil {
					t.Errorf("invalid grounded JS candidate: %v", err)
					continue
				}
				if _, duplicate := actualCandidates[key]; duplicate {
					t.Errorf("duplicate grounded JS candidate %q", key)
				}
				if oracleCandidate, ok := expectedByKey[key]; ok {
					if candidate.Evidence != oracleCandidate.ExpectedEvidence {
						t.Errorf("grounded JS candidate %q evidence = %q, oracle wants %q",
							key, candidate.Evidence, oracleCandidate.ExpectedEvidence)
					}
					if grounded := candidate.Metadata["grounded"] == "true"; grounded != oracleCandidate.ExpectedGrounded {
						t.Errorf("grounded JS candidate %q grounded metadata = %t, oracle wants %t",
							key, grounded, oracleCandidate.ExpectedGrounded)
					}
				}
				actualCandidates[key] = candidate
			}
			if !sameStringSet(keysOfJSCandidateMap(expectedByKey), keysOfFindingMap(actualCandidates)) {
				t.Errorf("grounded JS candidate identities = %v, oracle wants %v",
					keysOfFindingMap(actualCandidates), keysOfJSCandidateMap(expectedByKey))
			}

			analysis, err := engine.Analyze(context.Background(), &scanner.Results{Findings: candidates, Complete: true})
			if err != nil {
				t.Fatalf("Analyze final JS candidates: %v", err)
			}
			actualDispositions := map[string]string{}
			collect := func(findings []analyzer.ValidatedFinding, disposition string) {
				t.Helper()
				for _, finding := range findings {
					if finding.Decision != disposition {
						t.Errorf("JS operational bucket %q contains decision %q", disposition, finding.Decision)
					}
					if finding.IsValid != (disposition == "confirmed") {
						t.Errorf("JS operational bucket %q has IsValid=%t, want %t",
							disposition, finding.IsValid, disposition == "confirmed")
					}
					key, keyErr := jsFindingKey(finding.Finding)
					if keyErr != nil {
						t.Errorf("invalid adjudicated JS candidate: %v", keyErr)
						continue
					}
					if previous, duplicate := actualDispositions[key]; duplicate {
						t.Errorf("JS candidate %q appears in both %q and %q", key, previous, disposition)
					}
					actualDispositions[key] = disposition
				}
			}
			collect(analysis.ValidatedFindings, "confirmed")
			collect(analysis.ManualReview, "manual-review")
			collect(analysis.FalsePositives, "rejected")
			for key, oracleCandidate := range expectedByKey {
				actual, ok := actualDispositions[key]
				if !ok {
					t.Errorf("JS candidate %q was not adjudicated", key)
					continue
				}
				if actual != oracleCandidate.ExpectedDisposition {
					t.Errorf("JS candidate %q disposition = %q, oracle wants %q", key, actual, oracleCandidate.ExpectedDisposition)
				}
			}
			for key := range actualDispositions {
				if _, ok := expectedByKey[key]; !ok {
					t.Errorf("adjudicated JS candidate %q is absent from oracle", key)
				}
			}
			if calls := provider.calls; calls != 1 {
				t.Errorf("scripted provider calls = %d, want one discovery call and no model self-confirmation", calls)
			}
			totalConfirmed += len(analysis.ValidatedFindings)
		})
	}

	rate := ratio(t, totalConfirmed, totalExpectedCandidates)
	t.Logf("metric ai_only_confirmation_rate=%.3f (%d/%d)", rate, totalConfirmed, totalExpectedCandidates)
	if rate > d.Thresholds.MaxAIOnlyConfirmationRate {
		t.Errorf("ai_only_confirmation_rate %.3f exceeds %.3f", rate, d.Thresholds.MaxAIOnlyConfirmationRate)
	}
}

func runValidationCase(t *testing.T, c validationCase, expectedProviderCalls int, expectedUserSentinel string) triageVector {
	t.Helper()
	decision := c.ProviderDecision
	payload, err := json.Marshal(struct {
		Findings []struct {
			Index int `json:"index"`
			providerDecision
		} `json:"findings"`
	}{Findings: []struct {
		Index int `json:"index"`
		providerDecision
	}{{Index: 0, providerDecision: decision}}})
	if err != nil {
		t.Fatal(err)
	}

	sentinels := []string(nil)
	if strings.TrimSpace(expectedUserSentinel) != "" {
		sentinels = []string{expectedUserSentinel}
	}
	provider := newScriptedProvider(t, string(payload), sentinels)
	log := logger.New(false)
	t.Cleanup(log.Close)
	engine := analyzer.NewEngineWithProvider(evalConfig(), log, provider)
	result, err := engine.Analyze(context.Background(), &scanner.Results{
		Findings: []scanner.Finding{c.Finding},
		Complete: true,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if calls := provider.calls; calls != expectedProviderCalls {
		t.Fatalf("scripted provider calls = %d, oracle wants %d", calls, expectedProviderCalls)
	}
	return singleTriageVector(t, result)
}

func singleTriageVector(t *testing.T, result *analyzer.Analysis) triageVector {
	t.Helper()
	total := len(result.ValidatedFindings) + len(result.ManualReview) + len(result.FalsePositives)
	if total != 1 {
		t.Fatalf("pipeline adjudicated %d results, want exactly 1: %#v", total, result)
	}
	var finding analyzer.ValidatedFinding
	var bucket string
	switch {
	case len(result.ValidatedFindings) == 1:
		finding = result.ValidatedFindings[0]
		bucket = "confirmed"
	case len(result.ManualReview) == 1:
		finding = result.ManualReview[0]
		bucket = "manual-review"
	default:
		finding = result.FalsePositives[0]
		bucket = "rejected"
	}
	if finding.Decision != bucket {
		t.Errorf("operational bucket %q contains decision %q", bucket, finding.Decision)
	}
	if finding.IsValid != (bucket == "confirmed") {
		t.Errorf("operational bucket %q has IsValid=%t, want %t", bucket, finding.IsValid, bucket == "confirmed")
	}
	return triageVector{
		Bucket:               bucket,
		IsValid:              finding.IsValid,
		Disposition:          finding.Decision,
		Severity:             finding.Severity,
		Confidence:           finding.Confidence,
		EvidenceRefs:         append([]string(nil), finding.EvidenceRefs...),
		MissingEvidence:      append([]string(nil), finding.MissingEvidence...),
		Analysis:             finding.AIAnalysis,
		ImpactAssessment:     finding.ImpactAssessment,
		Remediation:          finding.Remediation,
		ProofOfConcept:       finding.ProofOfConcept,
		CybersecurityContext: finding.CybersecurityContext,
		BugBountyValue:       finding.BugBountyValue,
	}
}

func triageVectorFromLabel(label validationLabel) triageVector {
	expected := label.ExpectedTriage
	return triageVector{
		Bucket:               label.ExpectedDisposition,
		IsValid:              label.ExpectedDisposition == "confirmed",
		Disposition:          label.ExpectedDisposition,
		Severity:             expected.Severity,
		Confidence:           expected.Confidence,
		EvidenceRefs:         append([]string(nil), expected.EvidenceRefs...),
		MissingEvidence:      append([]string(nil), expected.MissingEvidence...),
		Analysis:             expected.Analysis,
		ImpactAssessment:     expected.ImpactAssessment,
		Remediation:          expected.Remediation,
		ProofOfConcept:       expected.ProofOfConcept,
		CybersecurityContext: expected.CybersecurityContext,
		BugBountyValue:       expected.BugBountyValue,
	}
}

func normalizeTriageVector(vector triageVector) triageVector {
	if vector.EvidenceRefs == nil {
		vector.EvidenceRefs = []string{}
	}
	if vector.MissingEvidence == nil {
		vector.MissingEvidence = []string{}
	}
	return vector
}

type scriptedProvider struct {
	t                     *testing.T
	response              string
	expectedUserSentinels []string
	calls                 int
}

func newScriptedProvider(t *testing.T, response string, expectedUserSentinels []string) *scriptedProvider {
	t.Helper()
	return &scriptedProvider{
		t:                     t,
		response:              response,
		expectedUserSentinels: append([]string(nil), expectedUserSentinels...),
	}
}

func (p *scriptedProvider) Complete(_ context.Context, systemPrompt, userPrompt string) (string, error) {
	p.calls++
	if p.t != nil {
		p.t.Helper()
		if strings.TrimSpace(systemPrompt) == "" || strings.TrimSpace(userPrompt) == "" {
			p.t.Error("scripted provider requires non-empty trusted system and untrusted user prompts")
		}
		for _, sentinel := range p.expectedUserSentinels {
			if count := strings.Count(userPrompt, sentinel); count != 1 {
				p.t.Errorf("scripted provider user prompt contains case sentinel %q %d times, want exactly 1", sentinel, count)
			}
			if strings.Contains(systemPrompt, sentinel) {
				p.t.Errorf("case sentinel %q leaked into trusted system prompt", sentinel)
			}
		}
	}
	return p.response, nil
}

func (p *scriptedProvider) CompleteWithRetry(ctx context.Context, systemPrompt, userPrompt string, _ int) (string, error) {
	return p.Complete(ctx, systemPrompt, userPrompt)
}

func (p *scriptedProvider) ProviderName() string { return "deterministic-eval" }

func evalConfig() *config.Config {
	return &config.Config{
		AI: config.AIConfig{
			Provider:  "custom",
			APIKey:    "eval-placeholder-not-a-secret",
			Model:     "deterministic-eval",
			MaxTokens: 512,
			Timeout:   2,
		},
		Analysis: config.AnalysisConfig{MinConfidence: 0.85},
	}
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

func validationSentinelSource(finding scanner.Finding, field string) (string, bool) {
	switch field {
	case "description":
		return finding.Description, true
	case "evidence":
		return finding.Evidence, true
	case "request":
		return finding.Request, true
	case "response":
		return finding.Response, true
	default:
		return "", false
	}
}

// hostAllowedByEvalOracle intentionally does not call the production scope
// package. Keeping this tiny matcher evaluator-owned prevents one production
// scope regression from defining both the behavior and its expected answer.
func hostAllowedByEvalOracle(raw string, roots []string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return false
	}
	for _, rawRule := range roots {
		rule := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rawRule), "."))
		if strings.HasPrefix(rule, "*.") {
			apex := strings.TrimPrefix(rule, "*.")
			if host != apex && strings.HasSuffix(host, "."+apex) {
				return true
			}
			continue
		}
		if host == rule {
			return true
		}
	}
	return false
}

func identityFromHypothesis(h hunter.Hypothesis) hunterHypothesisIdentity {
	return hunterHypothesisIdentity{Class: h.Class, Target: h.Target, Parameter: h.Parameter}
}

func hunterIdentityKey(h hunterHypothesisIdentity) (string, error) {
	class := strings.ToLower(strings.TrimSpace(h.Class))
	if class == "" {
		return "", fmt.Errorf("empty class")
	}
	u, err := url.Parse(strings.TrimSpace(h.Target))
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", fmt.Errorf("invalid target %q", h.Target)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	parameter := strings.ToLower(strings.TrimSpace(h.Parameter))
	return class + "|" + strings.ToLower(u.Scheme) + "://" + host + path + "|" + parameter, nil
}

func expectedJSCandidateKey(candidate expectedJSCandidate) (string, error) {
	return jsCandidateIdentity(candidate.Pattern, candidate.FileURL)
}

func jsProviderFindingKey(finding jsProviderFinding) (string, error) {
	return jsCandidateIdentity(finding.Type, finding.FileURL)
}

func jsFindingKey(finding scanner.Finding) (string, error) {
	return jsCandidateIdentity(finding.Metadata["pattern"], finding.Metadata["file_url"])
}

func jsCandidateIdentity(pattern, rawURL string) (string, error) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if pattern == "" {
		return "", fmt.Errorf("empty pattern")
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", fmt.Errorf("invalid file URL %q", rawURL)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return pattern + "|" + strings.ToLower(u.Scheme) + "://" + host + path, nil
}

func keysOfStringMap(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func keysOfSet(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func keysOfHypothesisMap(values map[string]hunter.Hypothesis) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func keysOfJSCandidateMap(values map[string]expectedJSCandidate) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func keysOfFindingMap(values map[string]scanner.Finding) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func stringSliceSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	left = append([]string(nil), left...)
	right = append([]string(nil), right...)
	sort.Strings(left)
	sort.Strings(right)
	return reflect.DeepEqual(left, right)
}

func requireRawFields(t *testing.T, kind string, records []map[string]json.RawMessage, fields ...string) {
	t.Helper()
	for i, record := range records {
		for _, field := range fields {
			if _, ok := record[field]; !ok {
				t.Fatalf("%s %d is missing required field %q", kind, i, field)
			}
		}
	}
}

func validationLabelMap(t *testing.T, oracle behaviorOracle) map[string]validationLabel {
	t.Helper()
	labels := make(map[string]validationLabel, len(oracle.ValidationLabels))
	for _, label := range oracle.ValidationLabels {
		if _, duplicate := labels[label.CaseID]; duplicate {
			t.Fatalf("duplicate validation oracle label for %q", label.CaseID)
		}
		labels[label.CaseID] = label
	}
	return labels
}

func requireValidationLabel(t *testing.T, labels map[string]validationLabel, id string) validationLabel {
	t.Helper()
	label, ok := labels[id]
	if !ok {
		t.Fatalf("validation case %q has no oracle label", id)
	}
	return label
}

func validationCaseMap(t *testing.T, cases []validationCase) map[string]validationCase {
	t.Helper()
	indexed := make(map[string]validationCase, len(cases))
	for _, c := range cases {
		if _, duplicate := indexed[c.ID]; duplicate {
			t.Fatalf("duplicate validation case %q", c.ID)
		}
		indexed[c.ID] = c
	}
	return indexed
}

func requireValidationCase(t *testing.T, cases map[string]validationCase, id string) validationCase {
	t.Helper()
	c, ok := cases[id]
	if !ok {
		t.Fatalf("counterfactual oracle references missing validation case %q", id)
	}
	return c
}

func hunterExpectationMap(t *testing.T, oracle behaviorOracle) map[string]hunterExpectation {
	t.Helper()
	indexed := make(map[string]hunterExpectation, len(oracle.HunterExpectations))
	for _, expected := range oracle.HunterExpectations {
		if _, duplicate := indexed[expected.CaseID]; duplicate {
			t.Fatalf("duplicate hunter oracle expectation for %q", expected.CaseID)
		}
		indexed[expected.CaseID] = expected
	}
	return indexed
}

func requireHunterExpectation(t *testing.T, expectations map[string]hunterExpectation, id string) hunterExpectation {
	t.Helper()
	expected, ok := expectations[id]
	if !ok {
		t.Fatalf("hunter case %q has no oracle expectation", id)
	}
	return expected
}

func secretRegexExpectationMap(t *testing.T, oracle behaviorOracle) map[string]secretRegexExpectation {
	t.Helper()
	indexed := make(map[string]secretRegexExpectation, len(oracle.SecretRegexExpectations))
	for _, expected := range oracle.SecretRegexExpectations {
		if _, duplicate := indexed[expected.CaseID]; duplicate {
			t.Fatalf("duplicate secret-regex oracle expectation for %q", expected.CaseID)
		}
		indexed[expected.CaseID] = expected
	}
	return indexed
}

func requireSecretRegexExpectation(t *testing.T, expectations map[string]secretRegexExpectation, id string) secretRegexExpectation {
	t.Helper()
	expected, ok := expectations[id]
	if !ok {
		t.Fatalf("secret-regex case %q has no oracle expectation", id)
	}
	return expected
}

func jsAIExpectationMap(t *testing.T, oracle behaviorOracle) map[string]jsAIExpectation {
	t.Helper()
	indexed := make(map[string]jsAIExpectation, len(oracle.JSAIExpectations))
	for _, expected := range oracle.JSAIExpectations {
		if _, duplicate := indexed[expected.CaseID]; duplicate {
			t.Fatalf("duplicate js-ai oracle expectation for %q", expected.CaseID)
		}
		indexed[expected.CaseID] = expected
	}
	return indexed
}

func requireJSAIExpectation(t *testing.T, expectations map[string]jsAIExpectation, id string) jsAIExpectation {
	t.Helper()
	expected, ok := expectations[id]
	if !ok {
		t.Fatalf("js-ai case %q has no oracle expectation", id)
	}
	return expected
}

func caseIDsFromHunter(cases []hunterCase) []string {
	ids := make([]string, 0, len(cases))
	for _, c := range cases {
		ids = append(ids, c.ID)
	}
	return ids
}

func hunterExpectationIDs(expectations []hunterExpectation) []string {
	ids := make([]string, 0, len(expectations))
	for _, expected := range expectations {
		ids = append(ids, expected.CaseID)
	}
	return ids
}

func caseIDsFromSecretRegex(cases []secretRegexCase) []string {
	ids := make([]string, 0, len(cases))
	for _, c := range cases {
		ids = append(ids, c.ID)
	}
	return ids
}

func secretRegexExpectationIDs(expectations []secretRegexExpectation) []string {
	ids := make([]string, 0, len(expectations))
	for _, expected := range expectations {
		ids = append(ids, expected.CaseID)
	}
	return ids
}

func caseIDsFromJSAI(cases []jsAICase) []string {
	ids := make([]string, 0, len(cases))
	for _, c := range cases {
		ids = append(ids, c.ID)
	}
	return ids
}

func jsAIExpectationIDs(expectations []jsAIExpectation) []string {
	ids := make([]string, 0, len(expectations))
	for _, expected := range expectations {
		ids = append(ids, expected.CaseID)
	}
	return ids
}

func assertExactOracleCoverage(t *testing.T, kind string, caseIDs, oracleIDs []string) {
	t.Helper()
	cases := make(map[string]struct{}, len(caseIDs))
	for _, id := range caseIDs {
		if _, duplicate := cases[id]; duplicate {
			t.Errorf("duplicate %s case %q", kind, id)
		}
		cases[id] = struct{}{}
	}
	expected := make(map[string]struct{}, len(oracleIDs))
	for _, id := range oracleIDs {
		if _, duplicate := expected[id]; duplicate {
			t.Errorf("duplicate %s oracle expectation %q", kind, id)
		}
		expected[id] = struct{}{}
		if _, ok := cases[id]; !ok {
			t.Errorf("%s oracle references unknown case %q", kind, id)
		}
	}
	for id := range cases {
		if _, ok := expected[id]; !ok {
			t.Errorf("%s case %q has no oracle expectation", kind, id)
		}
	}
}

func validateMatchedCounterfactual(pair counterfactualPair, left, right validationCase) error {
	if strings.TrimSpace(left.Finding.Title) == "" || strings.TrimSpace(right.Finding.Title) == "" {
		return fmt.Errorf("title labels must be non-empty")
	}
	if strings.TrimSpace(pair.LeftTitleToken) == "" || strings.TrimSpace(pair.RightTitleToken) == "" ||
		pair.LeftTitleToken == pair.RightTitleToken {
		return fmt.Errorf("declared title substitutions are empty or identical")
	}
	if strings.Count(left.Finding.Title, pair.LeftTitleToken) != 1 ||
		strings.Count(right.Finding.Title, pair.RightTitleToken) != 1 {
		return fmt.Errorf("each declared title token must occur exactly once")
	}
	leftNormalized := strings.Replace(left.Finding.Title, pair.LeftTitleToken, "<counterfactual-label>", 1)
	rightNormalized := strings.Replace(right.Finding.Title, pair.RightTitleToken, "<counterfactual-label>", 1)
	if leftNormalized != rightNormalized {
		return fmt.Errorf("titles differ beyond the declared token substitution")
	}
	leftFinding := left.Finding
	rightFinding := right.Finding
	leftFinding.Title = leftNormalized
	rightFinding.Title = rightNormalized
	if !reflect.DeepEqual(leftFinding, rightFinding) {
		return fmt.Errorf("findings differ beyond the declared title label")
	}
	if !reflect.DeepEqual(left.ProviderDecision, right.ProviderDecision) {
		return fmt.Errorf("scripted provider decisions differ")
	}
	return nil
}

func findingTypes(findings []scanner.Finding) []string {
	types := make([]string, 0, len(findings))
	for _, finding := range findings {
		types = append(types, fmt.Sprintf("%s:%s", finding.Type, finding.ID))
	}
	sort.Strings(types)
	return types
}

func regexFindingPatterns(findings []scanner.Finding) []string {
	seen := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		pattern := strings.TrimSpace(finding.Metadata["pattern"])
		if pattern == "" {
			pattern = "<missing-pattern>"
		}
		seen[pattern] = struct{}{}
	}
	patterns := make([]string, 0, len(seen))
	for pattern := range seen {
		patterns = append(patterns, pattern)
	}
	sort.Strings(patterns)
	return patterns
}

func ratio(t *testing.T, numerator, denominator int) float64 {
	t.Helper()
	if denominator <= 0 {
		t.Fatalf("metric denominator must be positive, got %d", denominator)
	}
	return float64(numerator) / float64(denominator)
}
