package scanner

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	scopepolicy "github.com/Btr4k/bugbounty-agent/internal/scope"
)

func TestResolveHttpxBinaryAllowsSlowProjectDiscoveryVersionCheck(t *testing.T) {
	goPath := t.TempDir()
	binDir := filepath.Join(goPath, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	httpxPath := filepath.Join(binDir, "httpx")
	script := "#!/bin/sh\nsleep 4\necho projectdiscovery.io\n"
	if err := os.WriteFile(httpxPath, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPATH", goPath)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+"/bin")

	got, ok := ResolveHttpxBinary()
	if !ok || got != httpxPath {
		t.Fatalf("ResolveHttpxBinary() = %q, %v; want %q, true", got, ok, httpxPath)
	}
}

func TestBoundedToolLimitsRespectGlobalConfig(t *testing.T) {
	engine := &Engine{cfg: &config.Config{Scanning: config.ScanningConfig{RateLimit: 12, Threads: 7}}}
	if got := engine.boundedRateLimit(80); got != 12 {
		t.Fatalf("boundedRateLimit = %d, want 12", got)
	}
	if got := engine.boundedThreads(15); got != 7 {
		t.Fatalf("boundedThreads = %d, want 7", got)
	}
}

func TestRunNucleiDirectReturnsErrorWhenCommandWritesNonJSONBeforeTimeout(t *testing.T) {
	engine := testEngineWithFakeNuclei(t, "#!/bin/sh\necho '[WRN] still running'\nexec sleep 5\n")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	findings, err := engine.runNucleiDirect(ctx, []string{"https://example.com"})
	if err == nil {
		t.Fatal("runNucleiDirect accepted a timed-out nuclei process as successful")
	}
	if len(findings) != 0 {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestRunSQLiScanPreservesPartialFindingsOnFailure(t *testing.T) {
	output := `{"template-id":"partial-sqli","info":{"name":"Partial SQLi","severity":"high"},"type":"http","host":"example.com","matched-at":"https://example.com/search?id=1"}` + "\n"
	engine := testEngineWithFakeNuclei(t, "#!/bin/sh\nprintf '%s' '"+output+"'\nexit 1\n")

	findings, err := engine.runSQLiScan(context.Background(), []string{"https://example.com"}, nil)
	if err == nil {
		t.Fatal("runSQLiScan accepted a failed nuclei process as successful")
	}
	if len(findings) != 1 || findings[0].Title != "Partial SQLi" {
		t.Fatalf("partial SQLi findings were lost: %#v", findings)
	}
}

func TestRunNucleiDirectPreservesPartialFindingsOnFailure(t *testing.T) {
	output := `{"template-id":"partial-test","info":{"name":"Partial Finding","severity":"high"},"type":"http","host":"example.com","matched-at":"https://example.com/test"}` + "\n"
	engine := testEngineWithFakeNuclei(t, "#!/bin/sh\nprintf '%s' '"+output+"'\nexit 1\n")

	findings, err := engine.runNucleiDirect(context.Background(), []string{"https://example.com"})
	if err == nil {
		t.Fatal("runNucleiDirect accepted a failed nuclei process as successful")
	}
	if len(findings) != 1 || findings[0].Title != "Partial Finding" {
		t.Fatalf("partial findings were lost: %#v", findings)
	}
}

func TestRunNucleiDirectUsesHighSignalDefaultProfile(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "args.txt")
	t.Setenv("NUCLEI_ARGS_CAPTURE", capture)
	engine := testEngineWithFakeNuclei(t, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$NUCLEI_ARGS_CAPTURE\"\n")

	if _, err := engine.runNucleiDirect(context.Background(), []string{"https://example.com"}); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	got := string(args)
	for _, expected := range []string{
		"exposure,misconfig,takeover,default-login",
		"http,ssl,dns",
		"critical,high,medium,low",
	} {
		if !strings.Contains(got, expected) {
			t.Errorf("nuclei args missing %q:\n%s", expected, got)
		}
	}
}

func testEngineWithFakeNuclei(t *testing.T, script string) *Engine {
	t.Helper()
	binDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(binDir, "nuclei"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+"/bin")
	log := logger.New(false)
	t.Cleanup(log.Close)
	return &Engine{
		cfg: &config.Config{Scanning: config.ScanningConfig{Threads: 1, RateLimit: 1}},
		log: log,
	}
}

func TestAppendHeaderArgsIncludesConfiguredAuthentication(t *testing.T) {
	engine := &Engine{cfg: &config.Config{
		Authentication: config.AuthenticationConfig{
			AllowedHosts: []string{"app.example.com"},
			Headers:      map[string]string{"Authorization": "Bearer test-token"},
			Cookies:      map[string]string{"session": "test-session"},
		},
	}}
	args := engine.appendHeaderArgs([]string{"-silent"}, "-H", "https://app.example.com")
	if !slices.Contains(args, "Authorization: Bearer test-token") ||
		!slices.Contains(args, "Cookie: session=test-session") {
		t.Fatalf("authentication headers missing from tool args: %#v", args)
	}
	redactionArgs := engine.appendNucleiRedactionArgs(nil)
	if !slices.Contains(redactionArgs, "Authorization") || !slices.Contains(redactionArgs, "Cookie") {
		t.Fatalf("nuclei redaction keys missing from tool args: %#v", redactionArgs)
	}
	blocked := engine.appendHeaderArgs([]string{"-silent"}, "-H", "https://evil.example.com")
	if slices.Contains(blocked, "Authorization: Bearer test-token") {
		t.Fatalf("authentication header leaked to disallowed host: %#v", blocked)
	}
}

func TestFindingInScope(t *testing.T) {
	policy := scopepolicy.New(config.TargetConfig{Domains: []string{"example.com"}})
	if !findingInScope(policy, Finding{URL: "https://api.example.com/path"}) {
		t.Fatal("expected in-scope URL to be accepted")
	}
	if findingInScope(policy, Finding{URL: "https://example.com.evil.test/path"}) {
		t.Fatal("expected out-of-scope URL to be rejected")
	}
}

func TestDeduplicateFindingsKeepsDistinctIssuesOnSameURL(t *testing.T) {
	policy := scopepolicy.New(config.TargetConfig{Domains: []string{"example.com"}})
	findings := []Finding{
		{Title: "SQL Injection", URL: "https://example.com/search?q=1"},
		{Title: "Reflected XSS", URL: "https://example.com/search?q=1"},
		{Title: "SQL Injection", URL: "https://example.com/search?q=1"},
		{Title: "Out of scope", URL: "https://evil.test/"},
	}
	got := deduplicateFindings(policy, findings)
	if len(got) != 2 {
		t.Fatalf("deduplicateFindings returned %d findings, want 2: %#v", len(got), got)
	}
}

func TestClassifyFfufSeverityRejectsWeakDiscoveries(t *testing.T) {
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"admin", 200},
		{".env", 302},
		{"server-status", 403},
		{"api/v1", 200},
		{"anything", 500},
	} {
		if got := classifyFfufSeverity(tc.path, tc.status); got != "" {
			t.Errorf("classifyFfufSeverity(%q, %d) = %q, want empty", tc.path, tc.status, got)
		}
	}
	if got := classifyFfufSeverity(".env", 200); got != "critical" {
		t.Errorf("expected accessible .env candidate to remain critical, got %q", got)
	}
}
