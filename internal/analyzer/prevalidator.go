package analyzer

import (
	"strconv"
	"strings"

	"github.com/Btr4k/bugbounty-agent/internal/scanner"
)

// PreValidOutcome describes the result of deterministic pre-validation.
type PreValidOutcome int

const (
	// PreValidKeep: finding is ambiguous — pass to AI for deeper analysis.
	PreValidKeep PreValidOutcome = iota
	// PreValidReject: definite false positive — skip AI entirely.
	PreValidReject
	// PreValidDowngrade: adjust severity before passing to AI.
	PreValidDowngrade
)

// PreValidResult is returned by PreValidateFinding.
type PreValidResult struct {
	Outcome     PreValidOutcome
	NewSeverity string // only meaningful when Outcome == PreValidDowngrade
	Reason      string // human-readable explanation stored in AIAnalysis
}

// PreValidateFinding applies deterministic security rules to catch obvious false
// positives before spending AI tokens on them. Rules are based on security
// fundamentals — no guessing, no probability, only hard facts.
//
// Call this for every non-JS finding before sending to the AI batch.
func PreValidateFinding(f scanner.Finding) PreValidResult {
	if result := preValidProtectedDiagnostic(f); result.Outcome != PreValidKeep {
		return result
	}
	if result := preValidSensitiveDebugExposure(f); result.Outcome != PreValidKeep {
		return result
	}

	switch f.Type {
	case "directory-bruteforce":
		return preValidDirectory(f)
	case "ssl":
		return preValidSSL(f)
	}
	return PreValidResult{Outcome: PreValidKeep}
}

// ─── Directory / Path Discovery ──────────────────────────────────────────────

// diagnosticPaths are server/framework diagnostic endpoints. A 403/401 response
// means the server is CORRECTLY blocking access — that is secure behavior, not a
// vulnerability.  Only report these if they actually return content (200).
var diagnosticPaths = []string{
	"trace.axd", "elmah.axd",
	"server-status", "server-info",
	"_debug", "_profiler", "_debugbar",
	"phpinfo", "phpinfo.php",
}

func preValidProtectedDiagnostic(f scanner.Finding) PreValidResult {
	if !isHTTPStatus(f, 401, 403) {
		return PreValidResult{Outcome: PreValidKeep}
	}

	combined := findingText(f)
	for _, p := range diagnosticPaths {
		if strings.Contains(combined, p) {
			return PreValidResult{
				Outcome: PreValidReject,
				Reason: "Diagnostic endpoint (" + p + ") returned HTTP 401/403, which means access is blocked. " +
					"This is expected secure behavior and is not reportable without an HTTP 200 response containing sensitive content.",
			}
		}
	}

	return PreValidResult{Outcome: PreValidKeep}
}

func preValidSensitiveDebugExposure(f scanner.Finding) PreValidResult {
	if !isHTTPStatus(f, 200) {
		return PreValidResult{Outcome: PreValidKeep}
	}

	combined := findingText(f)
	debugEndpoint := containsAny(combined,
		"mini-profiler", "miniprofiler", "_profiler", "_debugbar", "debugbar",
		"phpinfo", "phpinfo()", "error_log", "stack trace", "profiling results",
	)
	if !debugEndpoint {
		return PreValidResult{Outcome: PreValidKeep}
	}

	sensitiveProof := containsAny(combined,
		"sql", "select ", "insert ", "update ", "delete ",
		"stack trace", "exception", "internal server error",
		"server variables", "environment", "document_root", "script_filename",
		"profiling results", "startuprofiler", "umbraco", "miniprofiler",
		"x-powered-by", "asp.net", "php version",
	)
	if !sensitiveProof {
		return PreValidResult{Outcome: PreValidKeep}
	}

	return PreValidResult{
		Outcome:     PreValidDowngrade,
		NewSeverity: "medium",
		Reason: "HTTP 200 debug/profiling exposure contains sensitive runtime evidence. " +
			"Treat as Medium-value bug bounty material when the response exposes profiling data, framework internals, SQL context, stack traces, or server runtime details.",
	}
}

func preValidDirectory(f scanner.Finding) PreValidResult {
	evidence := strings.ToLower(f.Evidence)
	url := strings.ToLower(f.URL)
	title := strings.ToLower(f.Title)

	// Determine HTTP status from evidence field.
	is403or401 := strings.Contains(evidence, "http 403") ||
		strings.Contains(evidence, "| 403") ||
		strings.Contains(evidence, "403 |") ||
		strings.Contains(evidence, "http 401") ||
		strings.Contains(evidence, "| 401") ||
		strings.Contains(evidence, "401 |") ||
		strings.Contains(title, "protected")

	if !is403or401 {
		return PreValidResult{Outcome: PreValidKeep}
	}

	// Rule D-1: Diagnostic path returning 403/401 = properly secured.
	for _, p := range diagnosticPaths {
		if strings.Contains(url, p) || strings.Contains(evidence, p) {
			return PreValidResult{
				Outcome: PreValidReject,
				Reason: "Diagnostic endpoint (" + p + ") returning 403/401 means " +
					"the server is CORRECTLY blocking access. " +
					"This is the expected secure behavior — access denied is not a vulnerability. " +
					"Only report this path if it returns HTTP 200 with actual content.",
			}
		}
	}

	// Rule D-2: Generic 403/401 on non-critical paths.
	// A 403 confirms the path exists but proves nothing exploitable.
	// Exception: admin/API paths are borderline — pass to AI at lower severity.
	accessControlKeywords := []string{"admin", "administrator", "graphql", "swagger", "api-docs", "actuator"}
	for _, kw := range accessControlKeywords {
		if strings.Contains(url, kw) || strings.Contains(evidence, kw) {
			return PreValidResult{
				Outcome:     PreValidDowngrade,
				NewSeverity: "low",
				Reason: "Admin/API path returning 403/401 indicates server-side access control is in place. " +
					"Downgraded to Low — the AI will verify whether authentication bypass is feasible.",
			}
		}
	}

	// Anything else with 403/401 is noise — not a finding.
	return PreValidResult{
		Outcome: PreValidReject,
		Reason: "Path returning HTTP 403/401 means access is denied. " +
			"This is the correct secure behavior and is not a vulnerability on its own. " +
			"A finding requires HTTP 200 with sensitive content.",
	}
}

// ─── SSL / TLS ───────────────────────────────────────────────────────────────

func preValidSSL(f scanner.Finding) PreValidResult {
	evidence := strings.ToLower(f.Evidence)
	title := strings.ToLower(f.Title)
	combined := evidence + " " + title

	// Rule S-1: Truly dangerous protocols — always valid, keep as-is.
	if strings.Contains(combined, "sslv3") ||
		strings.Contains(combined, "ssl 3") ||
		strings.Contains(combined, "tls 1.0") ||
		strings.Contains(combined, "tls10") ||
		strings.Contains(combined, "tls1.0") {
		return PreValidResult{Outcome: PreValidKeep}
	}

	// Rule S-2: Critically weak ciphers — always valid.
	if strings.Contains(combined, "rc4") ||
		strings.Contains(combined, "3des") ||
		strings.Contains(combined, "des-cbc") ||
		strings.Contains(combined, "export") ||
		strings.Contains(combined, "null cipher") ||
		strings.Contains(combined, "anon") {
		return PreValidResult{Outcome: PreValidKeep}
	}

	// Rule S-3: ECDHE + CBC in TLS 1.2+ is NOT critically weak.
	// ECDHE provides forward secrecy.  AES-CBC in TLS 1.2 is not vulnerable to
	// BEAST (which requires TLS 1.0) or POODLE (which requires SSL 3.0).
	// This is a configuration quality issue, not an exploitable vulnerability.
	if strings.Contains(combined, "ecdhe") && strings.Contains(combined, "cbc") {
		return PreValidResult{
			Outcome:     PreValidDowngrade,
			NewSeverity: "info",
			Reason: "TLS cipher suite using ECDHE (forward secrecy) with AES-CBC is not critically weak. " +
				"AES-CBC in TLS 1.2 is not vulnerable to BEAST or POODLE — those require TLS 1.0 / SSL 3.0. " +
				"This is a configuration hygiene issue (GCM is preferred), not an exploitable vulnerability. " +
				"Downgraded to Informational.",
		}
	}

	// Rule S-4: Expired certificate — valid low severity finding.
	if strings.Contains(combined, "expired") || strings.Contains(title, "expired ssl") {
		return PreValidResult{Outcome: PreValidKeep}
	}

	// Rule S-5: Wildcard certificate analysis — not a vulnerability.
	if strings.Contains(combined, "wildcard") && !strings.Contains(combined, "expired") {
		return PreValidResult{
			Outcome: PreValidReject,
			Reason: "Wildcard SSL certificates are a standard, accepted practice. " +
				"Using *.domain.com is not a vulnerability unless the certificate is expired " +
				"or the private key is compromised. This is not a bug bounty finding.",
		}
	}

	return PreValidResult{Outcome: PreValidKeep}
}

func findingText(f scanner.Finding) string {
	return strings.ToLower(strings.Join([]string{
		f.Title,
		f.Description,
		f.Type,
		f.Target,
		f.URL,
		f.Evidence,
		f.Request,
		f.Response,
		strings.Join(f.Tags, " "),
	}, " "))
}

func isHTTPStatus(f scanner.Finding, statuses ...int) bool {
	combined := findingText(f)
	for _, status := range statuses {
		code := strconv.Itoa(status)
		if strings.Contains(combined, "http/1.1 "+code) ||
			strings.Contains(combined, "http/2 "+code) ||
			strings.Contains(combined, "http "+code) ||
			strings.Contains(combined, "| "+code) ||
			strings.Contains(combined, code+" |") ||
			strings.Contains(combined, "status: "+code) ||
			strings.Contains(combined, "status_code:"+code) ||
			strings.Contains(combined, "status-code: "+code) {
			return true
		}
	}
	return false
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
