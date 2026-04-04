package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/A-cyb3r/hawkeye/internal/config"
	"github.com/A-cyb3r/hawkeye/internal/logger"
	"github.com/A-cyb3r/hawkeye/internal/scanner"
)

// System prompt for security analysis (shared across all providers)
const securitySystemPrompt = "أنت خبير أمن سيبراني متخصص في Bug Bounty Hunting وتحليل الثغرات الأمنية. تتمتع بمعرفة عميقة في OWASP Top 10, CVE Database, CWE, CVSS scoring. مهمتك هي تحليل نتائج الأدوات الأمنية بدقة عالية، تحديد False Positives، وتقديم تحليل احترافي مع Proof of Concept قابل للتنفيذ. أجب دائماً بصيغة JSON المطلوبة."

type ClaudeAnalyzer struct {
	cfg    *config.Config
	log    *logger.Logger
	client AIProvider
}

type Analysis struct {
	ValidatedFindings   []ValidatedFinding
	FalsePositives      []ValidatedFinding
	ValidatedCount      int
	FalsePositiveCount  int
	Stats               Statistics
	TopFindings         []ValidatedFinding
	Summary             string
	Recommendations     []string
	Timestamp           time.Time
}

type ValidatedFinding struct {
	scanner.Finding
	IsValid          bool              `json:"is_valid"`
	Confidence       float64           `json:"confidence"`
	AIAnalysis       string            `json:"ai_analysis"`
	ImpactAssessment string            `json:"impact_assessment"`
	Remediation      string            `json:"remediation"`
	ProofOfConcept   string            `json:"proof_of_concept,omitempty"`
	CybersecurityContext string        `json:"cybersecurity_context"`
	BugBountyValue   string            `json:"bug_bounty_value"`
}

type Statistics struct {
	Total     int
	Critical  int
	High      int
	Medium    int
	Low       int
	Info      int
	Validated int
	FalsePositives int
}

// NewEngine creates a new analyzer engine (public API used by main)
func NewEngine(cfg *config.Config, log *logger.Logger) *ClaudeAnalyzer {
	return NewClaudeAnalyzer(cfg, log)
}

func NewClaudeAnalyzer(cfg *config.Config, log *logger.Logger) *ClaudeAnalyzer {
	client := createAIProvider(cfg, log)
	return &ClaudeAnalyzer{
		cfg:    cfg,
		log:    log,
		client: client,
	}
}

// createAIProvider creates the appropriate AI provider based on config
func createAIProvider(cfg *config.Config, log *logger.Logger) AIProvider {
	provider := cfg.AI.Provider
	apiKey := cfg.AI.APIKey
	model := cfg.AI.Model
	maxTokens := cfg.AI.MaxTokens

	switch provider {
	case "deepseek", "openai", "openrouter", "custom":
		log.Infof("AI Provider: %s (model: %s)", provider, model)
		return NewOpenAIProvider(apiKey, model, maxTokens, cfg.AI.BaseURL, provider)
	default: // "claude" or empty
		log.Infof("AI Provider: claude (model: %s)", model)
		return NewClaudeProvider(apiKey, model, maxTokens)
	}
}

func (a *ClaudeAnalyzer) Analyze(ctx context.Context, scanResults *scanner.Results) (*Analysis, error) {
	analysis := &Analysis{
		ValidatedFindings: make([]ValidatedFinding, 0),
		FalsePositives:    make([]ValidatedFinding, 0),
		Recommendations:   make([]string, 0),
		Timestamp:         time.Now(),
	}

	// If no findings, AI has nothing to analyze — return early with clear message
	if len(scanResults.Findings) == 0 {
		a.log.Warnf("AI Analysis: no findings to analyze — scanning phase produced 0 results")
		a.log.Warnf("Possible causes: target has no live hosts, tools not installed, or target is well-secured")
		return analysis, nil
	}

	a.log.Debugf("AI Analysis: processing %d findings in batches of 5", len(scanResults.Findings))

	// Process findings in batches for efficiency
	batchSize := 5
	for i := 0; i < len(scanResults.Findings); i += batchSize {
		end := i + batchSize
		if end > len(scanResults.Findings) {
			end = len(scanResults.Findings)
		}

		batch := scanResults.Findings[i:end]
		validated, rejected, err := a.analyzeBatch(ctx, batch)
		if err != nil {
			a.log.Warnf("Failed to analyze batch %d-%d: %v", i, end, err)
			continue
		}

		analysis.ValidatedFindings = append(analysis.ValidatedFindings, validated...)
		analysis.FalsePositives = append(analysis.FalsePositives, rejected...)
	}

	// Calculate statistics
	a.calculateStatistics(analysis)

	// Get top findings
	analysis.TopFindings = a.getTopFindings(analysis.ValidatedFindings, 10)

	// Generate local summary (no API call to save tokens)
	analysis.Summary = a.generateLocalSummary(analysis)

	// Generate local recommendations (no API call to save tokens)
	analysis.Recommendations = a.generateLocalRecommendations(analysis)

	return analysis, nil
}

func (a *ClaudeAnalyzer) analyzeBatch(ctx context.Context, findings []scanner.Finding) ([]ValidatedFinding, []ValidatedFinding, error) {
	if len(findings) == 0 {
		return nil, nil, nil
	}

	// Prepare prompt for Claude
	prompt := a.buildAnalysisPrompt(findings)

	// Call AI provider with retry logic
	response, err := a.client.CompleteWithRetry(ctx, securitySystemPrompt, prompt, 3)
	if err != nil {
		return nil, nil, fmt.Errorf("Claude API call failed: %w", err)
	}

	// Parse response
	validated, rejected, err := a.parseValidationResponse(response, findings)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse validation: %w", err)
	}

	return validated, rejected, nil
}

func (a *ClaudeAnalyzer) buildAnalysisPrompt(findings []scanner.Finding) string {
	var prompt strings.Builder

	// Compact prompt to save tokens
	prompt.WriteString(`خبير أمن سيبراني. حلل الثغرات وحدد: صحة (True/False Positive)، التأثير، PoC مختصر، الحل.

النتائج:
`)

	for i, finding := range findings {
		// Truncate long descriptions/evidence to save tokens
		desc := finding.Description
		if len(desc) > 150 {
			desc = desc[:150] + "..."
		}
		evidence := finding.Evidence
		if len(evidence) > 100 {
			evidence = evidence[:100] + "..."
		}

		prompt.WriteString(fmt.Sprintf(`%d. [%s] %s | %s
URL: %s | Desc: %s | Evidence: %s

`, i+1, finding.Severity, finding.Title, finding.Type, finding.URL, desc, evidence))
	}

	prompt.WriteString(`رد JSON فقط:
{
  "findings": [
    {
      "index": 0,
      "is_valid": true/false,
      "confidence": 0.0-1.0,
      "analysis": "تحليل مختصر",
      "impact_assessment": "التأثير",
      "remediation": "الحل",
      "proof_of_concept": "PoC مختصر",
      "cybersecurity_context": "OWASP/CWE/CVE",
      "bug_bounty_value": "high/medium/low"
    }
  ]
}`)

	return prompt.String()
}

func (a *ClaudeAnalyzer) parseValidationResponse(response string, originalFindings []scanner.Finding) ([]ValidatedFinding, []ValidatedFinding, error) {
	// Extract JSON from response
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	
	if jsonStart == -1 || jsonEnd == -1 {
		return nil, nil, fmt.Errorf("no JSON found in response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]

	var parsed struct {
		Findings []struct {
			Index               int     `json:"index"`
			IsValid             bool    `json:"is_valid"`
			Confidence          float64 `json:"confidence"`
			Analysis            string  `json:"analysis"`
			ImpactAssessment    string  `json:"impact_assessment"`
			Remediation         string  `json:"remediation"`
			ProofOfConcept      string  `json:"proof_of_concept"`
			CybersecurityContext string `json:"cybersecurity_context"`
			BugBountyValue      string  `json:"bug_bounty_value"`
		} `json:"findings"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return nil, nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	validated := make([]ValidatedFinding, 0)
	rejected := make([]ValidatedFinding, 0)

	for _, f := range parsed.Findings {
		if f.Index >= len(originalFindings) {
			continue
		}

		original := originalFindings[f.Index]
		
		vf := ValidatedFinding{
			Finding:              original,
			IsValid:              f.IsValid,
			Confidence:           f.Confidence,
			AIAnalysis:           f.Analysis,
			ImpactAssessment:     f.ImpactAssessment,
			Remediation:          f.Remediation,
			ProofOfConcept:       f.ProofOfConcept,
			CybersecurityContext: f.CybersecurityContext,
			BugBountyValue:       f.BugBountyValue,
		}

		// Apply confidence threshold - validated vs rejected
		if f.Confidence >= a.cfg.Analysis.MinConfidence && f.IsValid {
			validated = append(validated, vf)
		} else {
			rejected = append(rejected, vf)
		}
	}

	return validated, rejected, nil
}

// generateLocalSummary creates summary without API call (saves tokens)
func (a *ClaudeAnalyzer) generateLocalSummary(analysis *Analysis) string {
	var summary strings.Builder

	summary.WriteString(fmt.Sprintf("تم فحص الهدف واكتشاف %d ثغرة أمنية. ", analysis.Stats.Total))

	if analysis.Stats.Critical > 0 {
		summary.WriteString(fmt.Sprintf("تحتوي على %d ثغرة حرجة، ", analysis.Stats.Critical))
	}
	if analysis.Stats.High > 0 {
		summary.WriteString(fmt.Sprintf("%d عالية، ", analysis.Stats.High))
	}
	if analysis.Stats.Medium > 0 {
		summary.WriteString(fmt.Sprintf("%d متوسطة، ", analysis.Stats.Medium))
	}
	if analysis.Stats.Low > 0 {
		summary.WriteString(fmt.Sprintf("%d منخفضة. ", analysis.Stats.Low))
	}

	summary.WriteString(fmt.Sprintf("تم التحقق من %d ثغرة بواسطة AI وفلترة %d نتيجة خاطئة.",
		analysis.Stats.Validated, analysis.Stats.FalsePositives))

	if len(analysis.TopFindings) > 0 {
		summary.WriteString("\n\nأهم الثغرات المكتشفة:\n")
		for i, f := range analysis.TopFindings {
			if i >= 3 {
				break
			}
			summary.WriteString(fmt.Sprintf("• [%s] %s\n", f.Severity, f.Title))
		}
	}

	return summary.String()
}

// generateLocalRecommendations creates recommendations without API call (saves tokens)
func (a *ClaudeAnalyzer) generateLocalRecommendations(analysis *Analysis) []string {
	recommendations := []string{}

	if analysis.Stats.Critical > 0 {
		recommendations = append(recommendations,
			"إصلاح الثغرات الحرجة فوراً - لها تأثير مباشر على الأمان")
	}

	if analysis.Stats.High > 0 {
		recommendations = append(recommendations,
			"معالجة الثغرات عالية الخطورة خلال 24-48 ساعة")
	}

	// Check for common vulnerability types
	hasXSS := false
	hasSQLi := false
	hasAuthIssues := false

	for _, f := range analysis.ValidatedFindings {
		typeStr := strings.ToLower(f.Type)
		titleStr := strings.ToLower(f.Title)

		if strings.Contains(typeStr, "xss") || strings.Contains(titleStr, "xss") {
			hasXSS = true
		}
		if strings.Contains(typeStr, "sql") || strings.Contains(titleStr, "sql") {
			hasSQLi = true
		}
		if strings.Contains(typeStr, "auth") || strings.Contains(titleStr, "auth") {
			hasAuthIssues = true
		}
	}

	if hasXSS {
		recommendations = append(recommendations,
			"تطبيق Input Validation و Output Encoding لمنع XSS")
	}
	if hasSQLi {
		recommendations = append(recommendations,
			"استخدام Prepared Statements لمنع SQL Injection")
	}
	if hasAuthIssues {
		recommendations = append(recommendations,
			"مراجعة آليات المصادقة والتفويض")
	}

	recommendations = append(recommendations,
		"إجراء فحص أمني دوري باستخدام الأدوات الآلية",
		"تحديث جميع المكتبات والأطر البرمجية للنسخ الأحدث",
		"تفعيل Security Headers (CSP, HSTS, X-Frame-Options)",
	)

	return recommendations
}

func (a *ClaudeAnalyzer) calculateStatistics(analysis *Analysis) {
	// Count validated findings (all entries here passed the IsValid && confidence check)
	for _, vf := range analysis.ValidatedFindings {
		analysis.Stats.Validated++

		switch strings.ToLower(vf.Severity) {
		case "critical":
			analysis.Stats.Critical++
		case "high":
			analysis.Stats.High++
		case "medium":
			analysis.Stats.Medium++
		case "low":
			analysis.Stats.Low++
		default:
			analysis.Stats.Info++
		}
	}

	// Count false positives from the separate slice
	analysis.Stats.FalsePositives = len(analysis.FalsePositives)

	// Total includes both validated and false positives
	analysis.Stats.Total = analysis.Stats.Validated + analysis.Stats.FalsePositives

	analysis.ValidatedCount = analysis.Stats.Validated
	analysis.FalsePositiveCount = analysis.Stats.FalsePositives
}

func (a *ClaudeAnalyzer) getTopFindings(findings []ValidatedFinding, limit int) []ValidatedFinding {
	// Sort by severity and confidence
	severityOrder := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}

	sorted := make([]ValidatedFinding, len(findings))
	copy(sorted, findings)

	// Simple bubble sort (okay for small lists)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			si := severityOrder[strings.ToLower(sorted[i].Severity)]
			sj := severityOrder[strings.ToLower(sorted[j].Severity)]
			
			if sj > si || (sj == si && sorted[j].Confidence > sorted[i].Confidence) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	if len(sorted) > limit {
		return sorted[:limit]
	}
	return sorted
}

func (a *ClaudeAnalyzer) formatTopFindings(findings []ValidatedFinding, limit int) string {
	var result strings.Builder
	
	count := len(findings)
	if count > limit {
		count = limit
	}

	for i := 0; i < count; i++ {
		f := findings[i]
		result.WriteString(fmt.Sprintf("- [%s] %s (Confidence: %.2f)\n", 
			f.Severity, f.Title, f.Confidence))
	}

	return result.String()
}

// ═══════════════════════════════════════════════════════════
// JS File Analysis with AI
// ═══════════════════════════════════════════════════════════

// JSFinding represents a finding from JS analysis
type JSFinding struct {
	Type        string `json:"type"`
	Value       string `json:"value"`
	FileURL     string `json:"file_url"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// AnalyzeJSFiles sends JS file contents to Claude for security analysis
func (a *ClaudeAnalyzer) AnalyzeJSFiles(ctx context.Context, jsFiles []struct {
	URL     string
	Content string
	Size    int
	Source  string
}) ([]scanner.Finding, error) {

	if len(jsFiles) == 0 {
		return nil, nil
	}

	// Limit to 25 files max to avoid rate limits
	if len(jsFiles) > 25 {
		jsFiles = jsFiles[:25]
	}

	var allFindings []scanner.Finding

	// Process in batches of 5 files (fewer API calls = less rate limit pressure)
	batchSize := 5
	for i := 0; i < len(jsFiles); i += batchSize {
		end := i + batchSize
		if end > len(jsFiles) {
			end = len(jsFiles)
		}

		// Rate limit: wait 65s between batches (30K tokens/min limit)
		if i > 0 {
			a.log.Infof("JS analysis: waiting 65s for API rate limit (batch %d/%d)...", (i/batchSize)+1, (len(jsFiles)+batchSize-1)/batchSize)
			select {
			case <-time.After(65 * time.Second):
			case <-ctx.Done():
				return allFindings, ctx.Err()
			}
		}

		batch := jsFiles[i:end]
		findings, err := a.analyzeJSBatch(ctx, batch)
		if err != nil {
			a.log.Warnf("JS analysis batch %d-%d failed: %v", i, end, err)
			continue
		}

		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

func (a *ClaudeAnalyzer) analyzeJSBatch(ctx context.Context, jsFiles []struct {
	URL     string
	Content string
	Size    int
	Source  string
}) ([]scanner.Finding, error) {

	var prompt strings.Builder

	// Enhanced JS analysis prompt for deep security review
	prompt.WriteString(`You are an elite bug bounty hunter analyzing JavaScript files for HIGH-VALUE security findings.

CRITICAL — Report ALL of these if found:

[API KEYS & TOKENS]
- AWS: AKIA[0-9A-Z]{16}, ASIA[0-9A-Z]{16}, aws_secret_access_key
- Google: AIza[0-9A-Za-z_-]{35}, GOCSPX-*, ya29.*, maps API keys
- Stripe: sk_live_*, pk_live_*, sk_test_*, rk_live_*
- Firebase: firebaseConfig objects, apiKey in firebase init
- GitHub: ghp_*, gho_*, ghu_*, ghs_*, github_pat_*
- Slack: xoxb-*, xoxp-*, xoxs-*, xoxa-*
- Twilio: SK[0-9a-fA-F]{32}, AC[0-9a-fA-F]{32}
- SendGrid: SG.[a-zA-Z0-9_-]{22}.[a-zA-Z0-9_-]{43}
- JWT: eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*
- Bearer/OAuth tokens, session tokens, refresh tokens
- Any string matching: *_KEY, *_SECRET, *_TOKEN, *_PASSWORD patterns

[HIDDEN ENDPOINTS & APIS]
- Internal/admin APIs: /api/admin, /api/internal, /api/v1/debug, /graphql
- Undocumented endpoints, staging/dev URLs
- WebSocket endpoints (ws://, wss://)
- API base URLs with version paths
- Hardcoded backend server IPs/hostnames

[CREDENTIALS & SECRETS]
- Hardcoded passwords, usernames, database connection strings
- URLs with embedded credentials (https://user:pass@host)
- Private keys (RSA, SSH, PGP)
- Encryption keys, salt values, IV vectors

[SENSITIVE DATA EXPOSURE]
- PII: emails, phone numbers, physical addresses in code/comments
- Internal domain names, employee names
- Debug/verbose error messages
- Source maps pointing to internal paths
- Comments with TODO/FIXME/HACK/BUG containing sensitive info

[SECURITY MISCONFIGURATIONS]
- CORS: Access-Control-Allow-Origin: * or overly permissive
- Disabled security checks (verify: false, secure: false)
- Debug mode enabled (debug: true, NODE_ENV: development)
- Hardcoded redirect URLs (open redirect potential)
- postMessage without origin validation
- innerHTML/document.write with user input (DOM XSS sinks)
- eval(), Function(), setTimeout/setInterval with string args

STRICT RULES — READ CAREFULLY:
- Report the EXACT literal string/value from the code — copy-paste it verbatim
- NEVER infer or guess a finding if you cannot quote the exact value from the snippet
- For "debug: true" — only report if you see an ACTUAL assignment like debug:true or debug=true. Do NOT report if you see if(t.debug), settings.debug&&, or similar conditional checks
- For "NODE_ENV", "verify", "secure" — only report if the EXACT key=value pair is in the snippet
- Minified vendor/library files (jQuery, lodash, Bootstrap, validate.js, slick, owl-carousel, etc.) often contain options like mobile:false, live:true, secure:false, debug:true — these are plugin configuration options, NOT security issues. Ignore them completely
- Do NOT report jQuery plugin options, WordPress config placeholders, or CSS framework settings as findings
- For endpoints, report the full URL path as it appears in the code
- Severity: critical=keys/credentials, high=real endpoints/secrets, medium=misconfig with actual value, low=info-leak

Files:
`)

	for idx, js := range jsFiles {
		content := js.Content
		if len(content) > 12000 {
			// Smart truncation: keep beginning (config/imports) + middle chunk (routes/API defs) + end (exports)
			head := content[:5000]
			mid := content[len(content)/2-1000 : len(content)/2+1000]
			tail := content[len(content)-4000:]
			content = head + "\n... [truncated] ...\n" + mid + "\n... [truncated] ...\n" + tail
		}

		prompt.WriteString(fmt.Sprintf("%d. FILE: %s\n```js\n%s\n```\n\n", idx+1, js.URL, content))
	}

	prompt.WriteString(`JSON response (file_url must match the FILE: URL above each snippet):
{
  "findings": [
    {
      "type": "aws_key|api_key|secret|jwt|credential|endpoint|pii|config",
      "value": "exact value found — not a description",
      "file_url": "https://example.com/app.js",
      "severity": "critical|high|medium|low",
      "description": "what was found and why it matters"
    }
  ]
}
Empty if nothing: {"findings": []}`)


	response, err := a.client.CompleteWithRetry(ctx, securitySystemPrompt, prompt.String(), 2)
	if err != nil {
		return nil, fmt.Errorf("AI JS analysis failed: %w", err)
	}

	// Parse response
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	if jsonStart == -1 || jsonEnd == -1 {
		return nil, fmt.Errorf("no JSON found in JS analysis response")
	}

	jsonStr := response[jsonStart : jsonEnd+1]

	var parsed struct {
		Findings []JSFinding `json:"findings"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse JS analysis JSON: %w", err)
	}

	// Convert to scanner.Finding
	var findings []scanner.Finding
	for _, jf := range parsed.Findings {
		if jf.Value == "" {
			continue
		}

		finding := scanner.Finding{
			ID:          fmt.Sprintf("js-%s", jf.Type),
			Title:       fmt.Sprintf("JS: %s", jf.Type),
			Description: jf.Description,
			Severity:    jf.Severity,
			Type:        "js-analysis",
			URL:         jf.FileURL,
			Evidence:    jf.Value,
			Metadata: map[string]string{
				"source":   "ai-js-analysis",
				"tool":     fmt.Sprintf("%s-js", a.cfg.AI.Provider),
				"file_url": jf.FileURL,
			},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// Note: Claude API client implementation is in claude_api.go
