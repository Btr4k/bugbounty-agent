package analyzer

import (
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/scanner"
)

func TestPreValidatorUsesCapturedStatusNotUntrustedProse(t *testing.T) {
	tests := []struct {
		name    string
		finding scanner.Finding
		want    PreValidOutcome
	}{
		{
			name: "captured protected diagnostic is rejected",
			finding: scanner.Finding{
				Type:     "http",
				URL:      "https://example.com/trace.axd",
				Response: "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nblocked",
			},
			want: PreValidReject,
		},
		{
			name: "title cannot invent a status",
			finding: scanner.Finding{
				Type:  "directory-bruteforce",
				URL:   "https://example.com/admin",
				Title: "Protected endpoint HTTP 403",
			},
			want: PreValidKeep,
		},
		{
			name: "body text cannot override response status line",
			finding: scanner.Finding{
				Type:     "http",
				URL:      "https://example.com/trace.axd",
				Response: "HTTP/1.1 200 OK\r\n\r\nattacker text HTTP/1.1 403 Forbidden",
			},
			want: PreValidKeep,
		},
		{
			name: "structured directory evidence is accepted",
			finding: scanner.Finding{
				Type:     "directory-bruteforce",
				URL:      "https://example.com/server-status",
				Evidence: "server-status | 403 | 120 bytes",
			},
			want: PreValidReject,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := PreValidateFinding(test.finding).Outcome; got != test.want {
				t.Fatalf("outcome = %v, want %v", got, test.want)
			}
		})
	}
}

func TestSensitiveDebugExposureRequiresCapturedResponseProof(t *testing.T) {
	proven := scanner.Finding{
		Type:     "http",
		URL:      "https://example.com/phpinfo.php",
		Request:  "GET /phpinfo.php HTTP/1.1\r\nHost: example.com",
		Response: "HTTP/1.1 200 OK\r\n\r\nPHP Version 8.4\n_SERVER DOCUMENT_ROOT=/srv/app",
		Metadata: map[string]string{"tool": "nuclei", "matcher": "php-version"},
	}
	if got := PreValidateFinding(proven); got.Outcome != PreValidKeep || !isTrustedSensitiveDebugExposure(proven) {
		t.Fatalf("trusted debug exposure should remain unchanged while its proof is recognized: %#v", got)
	}

	proseOnly := scanner.Finding{
		Type:        "http",
		URL:         "https://example.com/phpinfo.php",
		Description: "HTTP 200 with PHP Version and environment variables",
	}
	if got := PreValidateFinding(proseOnly).Outcome; got != PreValidKeep {
		t.Fatalf("untrusted prose drove deterministic validation: %v", got)
	}
	if isTrustedSensitiveDebugExposure(proseOnly) {
		t.Fatal("untrusted prose was treated as a trusted scanner exchange")
	}

	sqliWithStackTrace := scanner.Finding{
		ID:       "time-based-sqli",
		Title:    "SQL injection",
		Type:     "sqli",
		URL:      "https://example.com/search?id=",
		Evidence: "DBMS: PostgreSQL; time-based proof; stack trace mentions SELECT",
		Response: "HTTP/1.1 200 OK\r\n\r\nSQL exception stack trace",
	}
	if got := PreValidateFinding(sqliWithStackTrace); got.Outcome != PreValidKeep {
		t.Fatalf("unrelated SQLi was reclassified as debug exposure: %#v", got)
	}
}
