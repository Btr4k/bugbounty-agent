package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// runCORSCheck tests live hosts for CORS misconfigurations
func (e *Engine) runCORSCheck(ctx context.Context, liveHosts []string) ([]Finding, error) {
	var findings []Finding

	if len(liveHosts) == 0 {
		return findings, nil
	}

	// Limit targets
	maxTargets := 30
	if len(liveHosts) > maxTargets {
		liveHosts = liveHosts[:maxTargets]
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	mu := &sync.Mutex{}
	sem := make(chan struct{}, 10) // Concurrency limit
	var wg sync.WaitGroup

	for _, host := range liveHosts {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Ensure protocol
		if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
			host = "https://" + host
		}

		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			hostFindings := e.testCORS(ctx, client, target)
			if len(hostFindings) > 0 {
				mu.Lock()
				findings = append(findings, hostFindings...)
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	return findings, nil
}

func (e *Engine) testCORS(ctx context.Context, client *http.Client, target string) []Finding {
	var findings []Finding
	foundTypes := make(map[string]bool) // Deduplicate findings per host per type

	// Test cases for CORS misconfiguration (ordered by severity)
	tests := []struct {
		origin   string
		testName string
	}{
		// Test 1: Arbitrary origin reflection (most critical)
		{"https://evil-attacker.com", "arbitrary_origin"},
		// Test 2: Null origin (can be triggered via sandboxed iframe)
		{"null", "null_origin"},
		// Test 3: Subdomain of attacker domain that looks like target
		{"https://" + extractBaseDomain(target) + ".evil.com", "subdomain_spoof"},
	}

	// Test 4: HTTP downgrade — only meaningful for HTTPS targets
	if strings.HasPrefix(target, "https://") {
		tests = append(tests, struct {
			origin   string
			testName string
		}{strings.Replace(target, "https://", "http://", 1), "http_downgrade"})
	}

	for _, test := range tests {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Origin", test.origin)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		resp.Body.Close()

		if acao == "" {
			continue // No CORS header, not vulnerable
		}

		// Determine finding type and severity — only report ONCE per type per host
		var findingID, title, description, severity string

		switch {
		// Critical: Wildcard with credentials
		case acao == "*" && strings.EqualFold(acac, "true"):
			findingID = "cors-wildcard-credentials"
			title = "CORS: Wildcard Origin with Credentials"
			description = "Server returns Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. This allows any website to make authenticated requests and steal user data."
			severity = "critical"

		// Critical: Arbitrary origin reflected with credentials
		case acao == test.origin && strings.EqualFold(acac, "true") && test.testName == "arbitrary_origin":
			findingID = "cors-origin-reflection-creds"
			title = "CORS: Origin Reflection with Credentials"
			description = "Server reflects any attacker-controlled Origin header and allows credentials. An attacker can steal authenticated user data from any origin."
			severity = "critical"

		// High: Null origin accepted with credentials
		case (acao == "null" || acao == test.origin) && strings.EqualFold(acac, "true") && test.testName == "null_origin":
			findingID = "cors-null-origin-creds"
			title = "CORS: Null Origin Accepted with Credentials"
			description = "Server accepts null Origin with credentials. Attackers can exploit this via sandboxed iframes to steal user data."
			severity = "high"

		// High: Arbitrary origin reflected without credentials
		case acao == test.origin && test.testName == "arbitrary_origin":
			findingID = "cors-origin-reflection"
			title = "CORS: Arbitrary Origin Reflected"
			description = "Server reflects attacker-controlled Origin in ACAO header. While credentials aren't included, public data can still be exfiltrated cross-origin."
			severity = "high"

		// High: Subdomain spoof reflected with credentials (e.g. target.evil.com accepted)
		case acao == test.origin && strings.EqualFold(acac, "true") && test.testName == "subdomain_spoof":
			findingID = "cors-subdomain-spoof-creds"
			title = "CORS: Subdomain Spoofing with Credentials"
			description = "Server accepts an attacker-controlled subdomain (e.g. target.evil.com) as a trusted origin with credentials. An attacker can register a matching domain to steal authenticated data."
			severity = "high"

		// Medium: Subdomain spoof reflected without credentials
		case acao == test.origin && test.testName == "subdomain_spoof":
			findingID = "cors-subdomain-spoof"
			title = "CORS: Subdomain Spoofing Accepted"
			description = "Server accepts an attacker-controlled subdomain (e.g. target.evil.com) as a trusted origin. This indicates weak origin validation using suffix matching."
			severity = "medium"

		// High: HTTP downgrade reflected with credentials (HTTPS→HTTP origin accepted)
		case acao == test.origin && strings.EqualFold(acac, "true") && test.testName == "http_downgrade":
			findingID = "cors-http-downgrade-creds"
			title = "CORS: HTTP Origin Accepted with Credentials on HTTPS Site"
			description = "HTTPS site accepts HTTP origin with credentials. A MITM attacker on the network can intercept the HTTP origin and steal authenticated data from the HTTPS endpoint."
			severity = "high"

		// Medium: HTTP downgrade reflected without credentials
		case acao == test.origin && test.testName == "http_downgrade":
			findingID = "cors-http-downgrade"
			title = "CORS: HTTP Origin Accepted on HTTPS Site"
			description = "HTTPS site accepts HTTP origin without credentials. This weakens the security model by allowing insecure origins to read cross-origin responses."
			severity = "medium"

		// Medium: Wildcard CORS (no credentials)
		case acao == "*":
			findingID = "cors-wildcard"
			title = "CORS: Wildcard Access-Control-Allow-Origin"
			description = "Server uses Access-Control-Allow-Origin: * which allows any website to read responses. Acceptable for public APIs but risky for sensitive endpoints."
			severity = "medium"
		}

		// Skip if no finding or already reported this type for this host
		if findingID == "" || foundTypes[findingID] {
			continue
		}
		foundTypes[findingID] = true

		// Once we find wildcard (*), skip remaining tests — they'll all match wildcard too
		isWildcard := acao == "*"

		findings = append(findings, Finding{
			ID:          findingID,
			Title:       title,
			Description: description,
			Severity:    severity,
			Type:        "cors-misconfiguration",
			URL:         target,
			Evidence:    fmt.Sprintf("Origin: %s → ACAO: %s, ACAC: %s", test.origin, acao, acac),
			CWE:         "CWE-942",
			Tags:        []string{"cors", "misconfiguration"},
			Metadata: map[string]string{
				"tool":      "cors-checker",
				"test_type": test.testName,
				"acao":      acao,
				"acac":      acac,
			},
			Timestamp: time.Now().Format(time.RFC3339),
		})

		// Wildcard always matches all origins — no need to test more
		if isWildcard {
			break
		}
	}

	return findings
}

// extractBaseDomain extracts the base domain from a URL for subdomain spoofing test
func extractBaseDomain(target string) string {
	// Remove protocol
	domain := target
	if idx := strings.Index(domain, "://"); idx != -1 {
		domain = domain[idx+3:]
	}
	// Remove path and port
	if idx := strings.IndexAny(domain, "/:?#"); idx != -1 {
		domain = domain[:idx]
	}
	return domain
}
