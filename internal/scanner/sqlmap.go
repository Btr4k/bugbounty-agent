package scanner

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"
)

// runSQLMap performs SQL injection testing on parameterized URLs
func (e *Engine) runSQLMap(ctx context.Context, urls []string) ([]Finding, error) {
	var findings []Finding

	if len(urls) == 0 {
		return findings, nil
	}

	// Check if sqlmap is installed
	if _, err := exec.LookPath("sqlmap"); err != nil {
		e.log.Warnf("sqlmap not installed - skipping SQLi testing (install: apt install sqlmap)")
		return findings, nil
	}

	// Limit to prevent extremely long scans
	maxURLs := 20
	if len(urls) > maxURLs {
		urls = urls[:maxURLs]
	}

	e.log.Debugf("SQLMap testing %d parameterized URLs", len(urls))

	for _, url := range urls {
		// Skip if context cancelled
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		// Quick SQLi detection (non-intrusive)
		args := []string{
			"-u", url,
			"--batch",              // Non-interactive
			"--random-agent",       // Random user agent
			"--level=1",            // Quick scan
			"--risk=1",             // Safe (low risk)
			"--technique=BEUST",    // All techniques
			"--threads=3",          // Parallel threads
			"--timeout=10",         // Per-request timeout
			"--retries=1",          // Retry once
			"--skip-waf",           // Skip WAF detection (faster)
			"--parse-errors",       // Parse error messages
			"--flush-session",      // Fresh session
			"--output-dir=/tmp/sqlmap-hawkeye",
		}

		cmd := exec.CommandContext(ctx, "sqlmap", args...)
		
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		// Run with timeout
		if err := cmd.Run(); err != nil {
			// sqlmap returns non-zero even on success sometimes
			e.log.Debugf("SQLMap on %s: %v", url, err)
		}

		// Parse output for SQL injection findings
		output := stdout.String()
		
		if strings.Contains(output, "is vulnerable") || 
		   strings.Contains(output, "SQL injection") ||
		   strings.Contains(output, "injectable") {
			
			// Extract vulnerability type
			vulnType := "SQL Injection"
			if strings.Contains(output, "time-based blind") {
				vulnType = "Time-Based Blind SQL Injection"
			} else if strings.Contains(output, "boolean-based blind") {
				vulnType = "Boolean-Based Blind SQL Injection"
			} else if strings.Contains(output, "error-based") {
				vulnType = "Error-Based SQL Injection"
			} else if strings.Contains(output, "UNION query") {
				vulnType = "UNION-Based SQL Injection"
			}

			finding := Finding{
				ID:          "sqlmap-sqli",
				Title:       vulnType,
				Description: "SQL injection vulnerability detected by SQLMap automated testing",
				Severity:    "critical",  // SQLi is always critical
				Type:        "sqli",
				URL:         url,
				Evidence:    extractSQLMapEvidence(output),
				Tags:        []string{"sqli", "sqlmap", "injection", "database"},
				Metadata: map[string]string{
					"tool":      "sqlmap",
					"technique": extractTechnique(output),
				},
				Timestamp: time.Now().Format(time.RFC3339),
			}

			findings = append(findings, finding)
			e.log.Debugf("SQLMap found SQLi in %s", url)
		}
	}

	return findings, nil
}

func extractSQLMapEvidence(output string) string {
	// Extract the important parts of sqlmap output
	lines := strings.Split(output, "\n")
	evidence := []string{}
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Parameter:") ||
		   strings.Contains(line, "Type:") ||
		   strings.Contains(line, "Title:") ||
		   strings.Contains(line, "Payload:") ||
		   strings.Contains(line, "vector:") {
			evidence = append(evidence, line)
			if len(evidence) >= 5 {
				break
			}
		}
	}
	
	if len(evidence) > 0 {
		return strings.Join(evidence, "\n")
	}
	return "SQL injection detected - check SQLMap logs for details"
}

func extractTechnique(output string) string {
	if strings.Contains(output, "time-based blind") {
		return "time-based-blind"
	} else if strings.Contains(output, "boolean-based blind") {
		return "boolean-based-blind"
	} else if strings.Contains(output, "error-based") {
		return "error-based"
	} else if strings.Contains(output, "UNION query") {
		return "union-based"
	} else if strings.Contains(output, "stacked queries") {
		return "stacked-queries"
	}
	return "unknown"
}
