package recon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
)

func TestRunAlwaysIncludesRootTarget(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	cfg := &config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com"}},
		Recon:  config.ReconConfig{Timeout: 5},
	}
	results, err := NewEngine(cfg, log).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results.Subdomains) != 1 || results.Subdomains[0] != "example.com" {
		t.Fatalf("root target missing from recon results: %v", results.Subdomains)
	}
	if !results.Complete {
		t.Fatalf("empty enabled-tool set should complete: %#v", results.FailedTools)
	}
}

func TestRunFailsClosedWithoutTarget(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	engine := NewEngine(&config.Config{Recon: config.ReconConfig{Timeout: 5}}, log)

	results, err := engine.Run(context.Background())
	if err == nil || results != nil {
		t.Fatalf("empty target must fail closed without results, got results=%#v err=%v", results, err)
	}
	if !strings.Contains(err.Error(), "at least one authorized target") {
		t.Fatalf("unexpected empty-target error: %v", err)
	}
}

func TestRunExactScopeSkipsSubdomainEnumerators(t *testing.T) {
	binDir := t.TempDir()
	subfinderMarker := filepath.Join(t.TempDir(), "subfinder-ran")
	assetfinderMarker := filepath.Join(t.TempDir(), "assetfinder-ran")
	writeExecutable(t, filepath.Join(binDir, "subfinder"), "#!/bin/sh\ntouch '"+subfinderMarker+"'\n")
	writeExecutable(t, filepath.Join(binDir, "assetfinder"), "#!/bin/sh\ntouch '"+assetfinderMarker+"'\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	log := logger.New(false)
	defer log.Close()
	cfg := &config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com"}},
		Recon: config.ReconConfig{
			Timeout: 5,
			Tools: config.ReconToolsConfig{
				Subfinder:   true,
				Assetfinder: true,
			},
		},
	}

	engine := NewEngine(cfg, log)
	engine.activeTargetURLValidate = func(context.Context, string) error { return nil }
	results, err := engine.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !results.Complete || len(results.Subdomains) != 1 || results.Subdomains[0] != "example.com" {
		t.Fatalf("exact-only recon must remain complete and contain only its configured root: %#v", results)
	}
	for name, marker := range map[string]string{
		"subfinder":   subfinderMarker,
		"assetfinder": assetfinderMarker,
	} {
		if _, err := os.Stat(marker); !os.IsNotExist(err) {
			t.Fatalf("%s ran for exact-only scope (stat error: %v)", name, err)
		}
	}
}

func TestConfiguredSubdomainReconRootsExcludeExactOnlyRoots(t *testing.T) {
	domains := []string{
		"exact-a.example.com",
		"*.wild-b.example.com",
		"*.WILD-B.example.com",
		"exact-c.example.com",
	}
	if got := configuredSubdomainReconRoots(domains); !slices.Equal(got, []string{"wild-b.example.com"}) {
		t.Fatalf("subdomain enumeration roots = %v, want only explicitly wildcard-authorized root", got)
	}
	if got := configuredReconRoots(domains); !slices.Equal(got, []string{"exact-a.example.com", "exact-c.example.com", "wild-b.example.com"}) {
		t.Fatalf("general recon roots unexpectedly changed: %v", got)
	}
}

func TestReconTrafficBoundsUseGlobalScannerLimits(t *testing.T) {
	engine := &Engine{cfg: &config.Config{Scanning: config.ScanningConfig{Threads: 40, RateLimit: 3}}}
	if got := engine.reconConcurrency(10); got != 3 {
		t.Fatalf("recon concurrency = %d, want rate-limited value 3", got)
	}
	if got := engine.reconConcurrency(2); got != 2 {
		t.Fatalf("recon concurrency = %d, want tool cap 2", got)
	}
	if got := engine.reconRateLimit(); got != 3 {
		t.Fatalf("recon rate limit = %d, want 3", got)
	}

	engine.cfg.Scanning.Threads = 0
	engine.cfg.Scanning.RateLimit = 0
	if got := engine.reconConcurrency(10); got != 1 {
		t.Fatalf("invalid config did not fail closed to one worker: %d", got)
	}
}

func TestRunContinuesAfterOptionalSourceFailureAndPassiveTimeout(t *testing.T) {
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "katana-ran")
	writeExecutable(t, filepath.Join(binDir, "subfinder"), "#!/bin/sh\nsleep 2\nexit 1\n")
	writeExecutable(t, filepath.Join(binDir, "katana"), "#!/bin/sh\ntouch '"+marker+"'\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	log := logger.New(false)
	defer log.Close()
	cfg := &config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com", "*.example.com"}},
		Recon: config.ReconConfig{
			Timeout: 1,
			Tools: config.ReconToolsConfig{
				Subfinder: true,
				Katana:    true,
			},
		},
	}

	engine := NewEngine(cfg, log)
	engine.activeTargetURLValidate = func(context.Context, string) error { return nil }
	results, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("optional recon failure must not stop the pipeline: %v", err)
	}
	if results.Complete || len(results.FailedTools) != 1 || results.FailedTools[0] != "subfinder" {
		t.Fatalf("expected partial recon with subfinder failure: %#v", results)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("katana did not run after the passive recon timeout")
	}
}

func TestParseCertSpotterNames(t *testing.T) {
	body := []byte(`[
		{"dns_names":["*.seu.edu.sa","lms.seu.edu.sa"]},
		{"dns_names":["seu.edu.sa"," itsm.seu.edu.sa ",""]}
	]`)

	names, err := parseCertSpotterNames(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]bool{
		"seu.edu.sa":      true, // wildcard prefix stripped
		"lms.seu.edu.sa":  true,
		"itsm.seu.edu.sa": true, // surrounding whitespace trimmed
	}
	if len(names) != 4 { // "*.seu.edu.sa" -> "seu.edu.sa" and the standalone "seu.edu.sa" both kept (dedup happens later)
		t.Fatalf("expected 4 names, got %d: %v", len(names), names)
	}
	for _, n := range names {
		if n == "" {
			t.Fatalf("empty name should be filtered out: %v", names)
		}
		if !want[n] {
			t.Fatalf("unexpected name %q in %v", n, names)
		}
	}
}

func TestParseCertSpotterNamesInvalidJSON(t *testing.T) {
	if _, err := parseCertSpotterNames([]byte("not json")); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func TestRunKatanaReturnsCrawlURLsAndJSSubset(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "katana"), `#!/bin/sh
echo "https://example.com/search?id=1"
echo "https://example.com/app.js?v=2"
echo "https://cdn.example.net/vendor.js"
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	log := logger.New(false)
	defer log.Close()
	engine := NewEngine(&config.Config{Target: config.TargetConfig{Domains: []string{"example.com"}}}, log)
	engine.activeTargetURLValidate = func(context.Context, string) error { return nil }
	urls, jsURLs, err := engine.runKatana(context.Background(), []string{"example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(urls, "https://example.com/search?id=1") {
		t.Fatalf("crawl URL missing: %v", urls)
	}
	if !slices.Contains(jsURLs, "https://example.com/app.js?v=2") {
		t.Fatalf("JS URL missing: %v", jsURLs)
	}
}

func TestPassiveToolPreservesPartialScopedResultsWithoutResolving(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "subfinder"), `#!/bin/sh
printf 'api.example.com\n'
printf 'outside.example.net\n'
printf 'https://example.com/path?token=DO_NOT_LOG\n'
printf 'stderr?secret=DO_NOT_LOG\n' >&2
exit 9
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	log := logger.New(false)
	defer log.Close()
	engine := NewEngine(&config.Config{
		Target: config.TargetConfig{Domains: []string{"*.example.com"}},
	}, log)
	validatorCalls := 0
	engine.activeTargetURLValidate = func(context.Context, string) error {
		validatorCalls++
		return errors.New("passive source unexpectedly resolved a target")
	}

	results, err := engine.runSubfinder(context.Background())
	if !slices.Equal(results, []string{"api.example.com"}) {
		t.Fatalf("valid scoped partial output was not preserved: %v", results)
	}
	if err == nil || !strings.Contains(err.Error(), "malformed output") || !strings.Contains(err.Error(), "status 9") {
		t.Fatalf("malformed/process failures were not surfaced: %v", err)
	}
	if strings.Contains(err.Error(), "DO_NOT_LOG") || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("diagnostic leaked untrusted output: %q", err)
	}
	if validatorCalls != 0 {
		t.Fatalf("passive enumeration performed %d active validation call(s)", validatorCalls)
	}
}

func TestWaybackAggregateByteCapPreservesOnlyCompletePartialRecords(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "waybackurls"), `#!/bin/sh
printf 'https://example.com/a\nhttps://example.com/b\nhttps://example.com/c\n'
printf 'stderr?token=DO_NOT_LOG\n' >&2
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	log := logger.New(false)
	defer log.Close()
	engine := NewEngine(&config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com"}},
		Recon:  config.ReconConfig{MaxWaybackURLs: 100},
	}, log)

	urls, err := engine.runWaybackURLsBounded(context.Background(), 30, 128)
	if !slices.Equal(urls, []string{"https://example.com/a"}) {
		t.Fatalf("byte-capped wayback output retained an incomplete record: %v", urls)
	}
	if err == nil || !strings.Contains(err.Error(), "30-byte limit") {
		t.Fatalf("wayback byte truncation was not surfaced: %v", err)
	}
	if strings.Contains(err.Error(), "DO_NOT_LOG") {
		t.Fatalf("wayback stderr leaked into coverage diagnostic: %v", err)
	}
}

func TestRunRetainsPassiveResultsWhenToolCoverageIsPartial(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "subfinder"), `#!/bin/sh
printf 'api.example.com\n'
exit 4
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	log := logger.New(false)
	defer log.Close()
	engine := NewEngine(&config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com", "*.example.com"}},
		Recon: config.ReconConfig{
			Timeout: 5,
			Tools:   config.ReconToolsConfig{Subfinder: true},
		},
	}, log)

	results, err := engine.Run(context.Background())
	if err != nil {
		t.Fatalf("optional source failure should not stop recon: %v", err)
	}
	if !slices.Contains(results.Subdomains, "api.example.com") {
		t.Fatalf("valid partial result was discarded by Run: %v", results.Subdomains)
	}
	if results.Complete || !slices.Equal(results.FailedTools, []string{"subfinder"}) {
		t.Fatalf("partial coverage was not recorded: %#v", results)
	}
}

func TestKatanaPublicAddressGateFailsClosedWithoutLeakingValidatorError(t *testing.T) {
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "katana-ran")
	writeExecutable(t, filepath.Join(binDir, "katana"), "#!/bin/sh\ntouch '"+marker+"'\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	log := logger.New(false)
	defer log.Close()
	engine := NewEngine(&config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com"}},
	}, log)
	engine.activeTargetURLValidate = func(context.Context, string) error {
		return errors.New("https://example.com/?token=DO_NOT_LOG\nforged")
	}

	urls, jsURLs, err := engine.runKatana(context.Background(), []string{"https://example.com/start?token=DO_NOT_LOG"})
	if len(urls) != 0 || len(jsURLs) != 0 || err == nil {
		t.Fatalf("rejected target must produce no crawl results: urls=%v js=%v err=%v", urls, jsURLs, err)
	}
	if !strings.Contains(err.Error(), "public-address validation rejected 1") || strings.Contains(err.Error(), "DO_NOT_LOG") || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("unsafe validation diagnostic: %q", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("Katana executed despite a failed public-address gate (stat error: %v)", statErr)
	}
}

func TestKatanaPreservesValidPartialOutputAndSanitizesTargetOrigin(t *testing.T) {
	binDir := t.TempDir()
	writeExecutable(t, filepath.Join(binDir, "katana"), `#!/bin/sh
printf 'https://example.com/app.js?v=2\n'
printf 'not a URL with token=DO_NOT_LOG\n'
printf 'stderr?secret=DO_NOT_LOG\n' >&2
exit 7
`)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	log := logger.New(false)
	defer log.Close()
	engine := NewEngine(&config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com"}},
	}, log)
	var validated string
	engine.activeTargetURLValidate = func(_ context.Context, target string) error {
		validated = target
		return nil
	}

	urls, jsURLs, err := engine.runKatana(context.Background(), []string{"https://example.com/start?token=DO_NOT_LOG#fragment"})
	if validated != "https://example.com" {
		t.Fatalf("Katana validation target retained path/query/fragment: %q", validated)
	}
	if !slices.Equal(urls, []string{"https://example.com/app.js?v=2"}) || !slices.Equal(jsURLs, urls) {
		t.Fatalf("valid output preceding failure was not preserved: urls=%v js=%v", urls, jsURLs)
	}
	if err == nil || !strings.Contains(err.Error(), "malformed output") || !strings.Contains(err.Error(), "status 7") {
		t.Fatalf("partial Katana coverage was not surfaced: %v", err)
	}
	if strings.Contains(err.Error(), "DO_NOT_LOG") || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("Katana diagnostic leaked query/stderr/control data: %q", err)
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
}
