package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/recon"
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
	if got := engine.conservativeConcurrency(80); got != 7 {
		t.Fatalf("conservativeConcurrency = %d, want 7", got)
	}

	engine.cfg.Scanning.Threads = 50
	engine.cfg.Scanning.RateLimit = 3
	if got := engine.conservativeConcurrency(80); got != 3 {
		t.Fatalf("rate-limited conservativeConcurrency = %d, want 3", got)
	}
	if got := dalfoxDelayMillis(3, 7); got != 429 {
		t.Fatalf("dalfoxDelayMillis = %d, want 429", got)
	}

	engine.cfg.Scanning.Threads = 0
	engine.cfg.Scanning.RateLimit = -1
	if got := engine.boundedThreads(10); got != 1 {
		t.Fatalf("zero boundedThreads = %d, want safe minimum 1", got)
	}
	if got := engine.boundedRateLimit(10); got != 1 {
		t.Fatalf("negative boundedRateLimit = %d, want safe minimum 1", got)
	}
	if got := engine.conservativeConcurrency(10); got != 1 {
		t.Fatalf("zero conservativeConcurrency = %d, want safe minimum 1", got)
	}
	if got := dalfoxDelayMillis(0, 0); got != 1000 {
		t.Fatalf("zero dalfoxDelayMillis = %d, want safe one-request/second delay", got)
	}
}

func TestBoundedCaptureRetainsPrefixAndReportsTruncation(t *testing.T) {
	capture := newBoundedCapture(5)
	if written, err := capture.Write([]byte("abc")); err != nil || written != 3 {
		t.Fatalf("first Write() = %d, %v; want 3, nil", written, err)
	}
	if written, err := capture.Write([]byte("defg")); err != nil || written != 4 {
		t.Fatalf("second Write() = %d, %v; want 4, nil", written, err)
	}
	if got := capture.String(); got != "abcde" {
		t.Fatalf("bounded capture retained %q, want %q", got, "abcde")
	}
	if !capture.Truncated() {
		t.Fatal("bounded capture did not surface truncation")
	}
}

type targetFileFixture struct {
	content  strings.Builder
	writeErr error
	closeErr error
	short    bool
}

func (fixture *targetFileFixture) Write(input []byte) (int, error) {
	if fixture.writeErr != nil {
		return 0, fixture.writeErr
	}
	if fixture.short && len(input) > 0 {
		written, _ := fixture.content.Write(input[:len(input)-1])
		return written, nil
	}
	return fixture.content.Write(input)
}

func (fixture *targetFileFixture) Close() error { return fixture.closeErr }

func TestWriteTargetLinesFailsClosedOnFlushShortWriteAndClose(t *testing.T) {
	success := &targetFileFixture{}
	if err := writeTargetLines(success, []string{"https://a.example.com", "https://b.example.com"}); err != nil {
		t.Fatal(err)
	}
	if got := success.content.String(); got != "https://a.example.com\nhttps://b.example.com\n" {
		t.Fatalf("unexpected target file content: %q", got)
	}

	for name, fixture := range map[string]*targetFileFixture{
		"flush error": {writeErr: errors.New("synthetic disk failure")},
		"short write": {short: true},
		"close error": {closeErr: errors.New("synthetic close failure")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := writeTargetLines(fixture, []string{"https://example.com"}); err == nil {
				t.Fatal("target-file failure was accepted as complete")
			}
		})
	}
}

func TestRunExternalCommandKillsDescendantsAfterLeaderExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tree-tool")
	marker := filepath.Join(t.TempDir(), "descendant-survived")
	if err := os.WriteFile(path, []byte(`#!/bin/sh
(sleep 0.25; printf escaped > "$1") &
exit 0
`), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := runExternalCommand(exec.Command(path, marker)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(350 * time.Millisecond)
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("descendant survived the scanner process group: %v", statErr)
	}
}

func TestSafeToolDiagnosticMasksSecretsAndControls(t *testing.T) {
	engine := &Engine{cfg: &config.Config{AI: config.AIConfig{APIKey: "configured-opaque-secret"}}}
	got := engine.safeToolDiagnostic("first\napi_key=detected-opaque-secret\x1b[31m configured-opaque-secret https://example.com/path?sig=query-opaque-secret")
	for _, leaked := range []string{"\n", "\x1b", "detected-opaque-secret", "configured-opaque-secret", "query-opaque-secret"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("unsafe diagnostic %q still contains %q", got, leaked)
		}
	}
	for _, preserved := range []string{"[REDACTED", "https://example.com/path?sig="} {
		if !strings.Contains(got, preserved) {
			t.Fatalf("safe diagnostic did not preserve %q: %q", preserved, got)
		}
	}
}

func TestSafeFindingBlockMasksOpaqueCookieHeaders(t *testing.T) {
	engine := &Engine{cfg: &config.Config{}}
	input := "GET /account HTTP/1.1\r\nCookie: sessionid=opaque-session-value; theme=dark\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nSet-Cookie: refresh=opaque-refresh-value; Path=/; Secure; HttpOnly; SameSite=Lax\r\n"
	got := engine.safeFindingBlock(input, 32<<10)
	for _, leaked := range []string{"opaque-session-value", "opaque-refresh-value", "theme=dark"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("sanitized scanner evidence leaked %q: %q", leaked, got)
		}
	}
	for _, preserved := range []string{"Cookie: sessionid=[REDACTED", "theme=[REDACTED", "Set-Cookie: refresh=[REDACTED", "Path=/", "Secure", "HttpOnly", "SameSite=Lax"} {
		if !strings.Contains(got, preserved) {
			t.Fatalf("sanitized scanner evidence lost %q: %q", preserved, got)
		}
	}
}

type scannerResolver struct {
	addresses []net.IPAddr
}

func (resolver scannerResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), resolver.addresses...), nil
}

func TestBlindCallbackExecutionRequiresAllPublicDNSAnswers(t *testing.T) {
	raw := "https://callback.example.com/oast"
	mixed := scopepolicy.PublicOriginOptions{Resolver: scannerResolver{addresses: []net.IPAddr{
		{IP: net.ParseIP("8.8.8.8")},
		{IP: net.ParseIP("10.0.0.7")},
	}}}
	if err := validateBlindCallbackForExecution(context.Background(), raw, mixed); err == nil || strings.Contains(err.Error(), raw) {
		t.Fatalf("mixed public/private callback was accepted or reflected: %v", err)
	}
	public := scopepolicy.PublicOriginOptions{Resolver: scannerResolver{addresses: []net.IPAddr{
		{IP: net.ParseIP("8.8.8.8")},
		{IP: net.ParseIP("1.1.1.1")},
	}}}
	if err := validateBlindCallbackForExecution(context.Background(), raw, public); err != nil {
		t.Fatalf("public callback was rejected: %v", err)
	}
}

func TestPartitionExternalTargetsPreservesSafeTargetsWithoutLeakingRawURL(t *testing.T) {
	engine := newScannerTestEngine(t, config.ScanningConfig{})
	const secret = "opaque-query-secret"
	engine.externalTargetValidator = func(_ context.Context, target string) error {
		if strings.Contains(target, "private.example.com") {
			// Even a validator error that contains the raw target must not cross the
			// scanner's sanitized error boundary.
			return fmt.Errorf("unsafe resolver answer for %s", target)
		}
		return nil
	}

	safe, rejected, err := engine.partitionExternalTargets(context.Background(), []string{
		"https://safe.example.com/search?q=public",
		"https://private.example.com/admin?token=" + secret,
	})
	if !slices.Equal(safe, []string{"https://safe.example.com/search?q=public"}) || rejected != 1 {
		t.Fatalf("partition = safe:%#v rejected:%d, want one safe and one rejected", safe, rejected)
	}
	if !errors.Is(err, errExternalTargetRejected) {
		t.Fatalf("partition error = %v, want errExternalTargetRejected", err)
	}
	for _, leaked := range []string{secret, "/admin", "token="} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("validation error leaked %q: %v", leaked, err)
		}
	}
	if !strings.Contains(err.Error(), "private.example.com") {
		t.Fatalf("validation error omitted safe hostname label: %v", err)
	}
}

func TestDefaultExternalTargetGuardFailsClosedOnLoopbackLiteral(t *testing.T) {
	engine := NewEngine(&config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com"}},
	}, nil)
	safe, rejected, err := engine.partitionExternalTargets(context.Background(), []string{
		"https://127.0.0.1/admin?token=opaque-secret",
	})
	if len(safe) != 0 || rejected != 1 || !errors.Is(err, errExternalTargetRejected) {
		t.Fatalf("loopback partition = safe:%#v rejected:%d err:%v", safe, rejected, err)
	}
	if strings.Contains(err.Error(), "opaque-secret") || strings.Contains(err.Error(), "/admin") {
		t.Fatalf("loopback rejection leaked raw URL data: %v", err)
	}
}

func TestBulkExternalToolsFailClosedBeforeExecWithoutLeakingQuery(t *testing.T) {
	const target = "https://example.com/search?token=opaque-query-secret"
	tests := []struct {
		name string
		run  func(*testing.T, *Engine, string) error
	}{
		{
			name: "httpx",
			run: func(t *testing.T, engine *Engine, sentinel string) error {
				installFakeHttpx(t, "#!/bin/sh\nif [ \"$1\" = \"-version\" ]; then echo projectdiscovery.io; exit 0; fi\nprintf ran > "+shellQuote(sentinel)+"\n")
				_, _, err := engine.runHttpx(context.Background(), []string{"example.com"})
				return err
			},
		},
		{
			name: "nuclei",
			run: func(t *testing.T, engine *Engine, sentinel string) error {
				installFakeTool(t, "nuclei", "#!/bin/sh\nprintf ran > "+shellQuote(sentinel)+"\n")
				_, err := engine.runNucleiDirect(context.Background(), []string{target})
				return err
			},
		},
		{
			name: "dalfox",
			run: func(t *testing.T, engine *Engine, sentinel string) error {
				installFakeTool(t, "dalfox", "#!/bin/sh\nprintf ran > "+shellQuote(sentinel)+"\n")
				_, err := engine.runDalfox(context.Background(), []string{target})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sentinel := filepath.Join(t.TempDir(), "tool-ran")
			engine := newScannerTestEngine(t, config.ScanningConfig{Threads: 1, RateLimit: 1})
			engine.externalTargetValidator = func(context.Context, string) error {
				return errors.New("private address for " + target)
			}
			err := test.run(t, engine, sentinel)
			if !errors.Is(err, errExternalTargetRejected) {
				t.Fatalf("tool error = %v, want errExternalTargetRejected", err)
			}
			if strings.Contains(err.Error(), "opaque-query-secret") || strings.Contains(err.Error(), "token=") {
				t.Fatalf("tool validation error leaked query data: %v", err)
			}
			if _, statErr := os.Stat(sentinel); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("tool ran after target rejection: %v", statErr)
			}
		})
	}
}

func TestRunHttpxContinuesSafeTargetsAndCountsRejectedValidation(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "httpx-targets.txt")
	installFakeHttpx(t, fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-version" ]; then
  echo "projectdiscovery.io"
  exit 0
fi
while [ $# -gt 0 ]; do
  if [ "$1" = "-l" ]; then cp "$2" %s; fi
  shift
done
echo '{"url":"https://safe.example.com"}'
`, shellQuote(capture)))

	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads: 1, RateLimit: 1, Timeout: 5,
		Tools: config.ScanningToolsConfig{Httpx: config.HttpxConfig{Enabled: true}},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}
	engine.externalTargetValidator = func(_ context.Context, target string) error {
		if externalTargetHost(target) == "private.example.com" {
			return errors.New("private address")
		}
		return nil
	}

	results, err := engine.Run(context.Background(), &recon.Results{
		Subdomains: []string{"safe.example.com", "private.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if results.Complete || !slices.Equal(results.FailedTools, []string{"httpx"}) {
		t.Fatalf("validation rejection was not surfaced once: %#v", results)
	}
	if results.Stats.TotalAttempted != 2 || results.Stats.TotalScanned != 1 ||
		results.Stats.TotalFailed != 1 || results.Stats.TotalSkipped != 0 {
		t.Fatalf("unexpected validation coverage: %#v", results.Stats)
	}
	if got := readArgumentLines(t, capture); !slices.Equal(got, []string{"safe.example.com"}) {
		t.Fatalf("httpx received rejected target: %v", got)
	}
}

func TestRunDalfoxContinuesSafeURLsAndCountsRejectedAsSubstantiveFailure(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "dalfox-targets.txt")
	installFakeTool(t, "dalfox", fmt.Sprintf(`#!/bin/sh
cp "$2" %s
echo '{"type":"v","severity":"high","data":"https://safe.example.com/search?q=poc","param":"q","inject_type":"attribute"}'
`, shellQuote(capture)))

	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads: 1, RateLimit: 1, Timeout: 5,
		Tools: config.ScanningToolsConfig{Dalfox: config.DalfoxConfig{Enabled: true}},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}
	engine.externalTargetValidator = func(_ context.Context, target string) error {
		if externalTargetHost(target) == "private.example.com" {
			return errors.New("private address")
		}
		return nil
	}

	results, err := engine.Run(context.Background(), &recon.Results{URLs: []string{
		"https://safe.example.com/search?q=1",
		"https://private.example.com/search?q=opaque-secret",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if results.Complete || !slices.Equal(results.FailedTools, []string{"dalfox"}) {
		t.Fatalf("Dalfox validation rejection was not surfaced once: %#v", results)
	}
	if results.Stats.TotalAttempted != 2 || results.Stats.TotalScanned != 1 || results.Stats.TotalFailed != 1 ||
		results.Stats.SubstantiveAttempted != 2 || results.Stats.SubstantiveScanned != 1 || results.Stats.SubstantiveFailed != 1 {
		t.Fatalf("unexpected substantive validation coverage: %#v", results.Stats)
	}
	if len(results.Findings) != 1 || results.Findings[0].Type != "xss" {
		t.Fatalf("safe partial finding was lost: %#v", results.Findings)
	}
	if got := readArgumentLines(t, capture); !slices.Equal(got, []string{"https://safe.example.com/search?q=1"}) {
		t.Fatalf("Dalfox received rejected URL: %v", got)
	}
}

func TestNucleiRevalidatesImmediatelyBeforeExecAndDoesNotRetryRejection(t *testing.T) {
	sentinel := filepath.Join(t.TempDir(), "nuclei-ran")
	installFakeTool(t, "nuclei", "#!/bin/sh\nprintf ran > "+shellQuote(sentinel)+"\n")

	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads: 1, RateLimit: 1, Timeout: 5,
		Tools: config.ScanningToolsConfig{Nuclei: config.NucleiConfig{Enabled: true}},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com"}}
	validationCalls := 0
	engine.externalTargetValidator = func(context.Context, string) error {
		validationCalls++
		if validationCalls >= 2 {
			return errors.New("DNS answer changed")
		}
		return nil
	}

	results, err := engine.Run(context.Background(), &recon.Results{Subdomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if validationCalls != 2 {
		t.Fatalf("validator called %d times, want orchestration and immediate pre-exec checks only", validationCalls)
	}
	if _, statErr := os.Stat(sentinel); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Nuclei ran after pre-exec DNS rejection: %v", statErr)
	}
	if results.Complete || !slices.Equal(results.FailedTools, []string{"nuclei"}) ||
		results.Stats.TotalAttempted != 1 || results.Stats.TotalScanned != 0 || results.Stats.TotalFailed != 1 ||
		results.Stats.SubstantiveAttempted != 1 || results.Stats.SubstantiveFailed != 1 {
		t.Fatalf("unexpected pre-exec rejection coverage: %#v", results)
	}
}

func TestNmapRevalidatesPerTargetAndContinuesOtherSafeTargets(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "nmap-targets.txt")
	installFakeTool(t, "nmap", fmt.Sprintf("#!/bin/sh\nfor arg in \"$@\"; do last=\"$arg\"; done\nprintf '%%s\\n' \"$last\" >> %s\n", shellQuote(capture)))

	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads: 1, RateLimit: 1, Timeout: 5,
		Tools: config.ScanningToolsConfig{Nmap: config.NmapConfig{Enabled: true}},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}
	calls := make(map[string]int)
	engine.externalTargetValidator = func(_ context.Context, target string) error {
		host := externalTargetHost(target)
		calls[host]++
		if host == "changed.example.com" && calls[host] >= 2 {
			return errors.New("DNS answer changed")
		}
		return nil
	}

	results, err := engine.Run(context.Background(), &recon.Results{Subdomains: []string{
		"safe.example.com",
		"changed.example.com",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if results.Complete || !slices.Equal(results.FailedTools, []string{"nmap"}) ||
		results.Stats.TotalAttempted != 2 || results.Stats.TotalScanned != 1 || results.Stats.TotalFailed != 1 {
		t.Fatalf("unexpected per-target revalidation coverage: %#v", results)
	}
	if got := readArgumentLines(t, capture); !slices.Equal(got, []string{"safe.example.com"}) {
		t.Fatalf("Nmap did not preserve only the still-safe target: %v", got)
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

func TestRunNucleiDirectPreservesPartialFindingsOnFailure(t *testing.T) {
	output := `{"template-id":"partial-test","info":{"name":"Partial Finding","severity":"high"},"type":"http","host":"example.com","matched-at":"https://example.com/test"}` + "\n"
	script := "#!/bin/sh\nprintf '%s' '" + output + "'\nexit 1\n"
	engine := testEngineWithFakeNuclei(t, script)

	findings, err := engine.runNucleiDirect(context.Background(), []string{"https://example.com"})
	if err == nil {
		t.Fatal("runNucleiDirect accepted a failed nuclei process as successful")
	}
	if len(findings) != 1 || findings[0].Title != "Partial Finding" {
		t.Fatalf("partial findings were lost: %#v", findings)
	}
}

func TestRunNucleiDirectPreservesFindingsAndRejectsMalformedJSONL(t *testing.T) {
	valid := `{"template-id":"valid-test","info":{"name":"Valid Finding","severity":"high"},"type":"http","host":"example.com","matched-at":"https://example.com/test"}` + "\n"
	script := "#!/bin/sh\nprintf '%s' '" + valid + "not-json\n'\n"
	engine := testEngineWithFakeNuclei(t, script)

	findings, err := engine.runNucleiDirect(context.Background(), []string{"https://example.com"})
	if err == nil || !strings.Contains(err.Error(), "malformed JSON") {
		t.Fatalf("malformed nuclei JSONL was not surfaced: %v", err)
	}
	if len(findings) != 1 || findings[0].Title != "Valid Finding" {
		t.Fatalf("valid finding beside malformed output was lost: %#v", findings)
	}
}

func TestRunNucleiDirectUsesHighSignalDefaultProfile(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "args.txt")
	engine := testEngineWithFakeNuclei(t, "#!/bin/sh\nprintf '%s\\n' \"$@\" > "+shellQuote(capture)+"\n")
	engine.cfg.Scanning.Threads = 50
	engine.cfg.Scanning.RateLimit = 4
	engine.cfg.Authentication = testAuthenticationConfig()

	if _, err := engine.runNucleiDirect(context.Background(), []string{"https://example.com"}); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	got := string(args)
	for _, expected := range []string{
		"exposure,takeover,default-login",
		"http,ssl,dns",
		"critical,high,medium,low",
	} {
		if !strings.Contains(got, expected) {
			t.Errorf("nuclei args missing %q:\n%s", expected, got)
		}
	}
	argsList := strings.Fields(got)
	for flag, want := range map[string]string{
		"-c":         "4",
		"-rl":        "4",
		"-bulk-size": "4",
	} {
		if value := argumentValue(argsList, flag); value != want {
			t.Errorf("nuclei %s = %q, want %q; args: %v", flag, value, want, argsList)
		}
	}
	assertNoExternalAuthentication(t, argsList)
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
		cfg:                     &config.Config{Scanning: config.ScanningConfig{Threads: 1, RateLimit: 1}},
		log:                     log,
		externalTargetValidator: allowExternalTargetForTest,
	}
}

func allowExternalTargetForTest(context.Context, string) error { return nil }

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func TestExternalToolArgsNeverIncludeAuthenticationSecrets(t *testing.T) {
	engine := &Engine{cfg: &config.Config{
		Authentication: testAuthenticationConfig(),
	}}
	base := []string{"-silent"}
	allowed := engine.withoutExternalToolAuth(append([]string(nil), base...))
	blocked := engine.withoutExternalToolAuth(append([]string(nil), base...))
	assertNoExternalAuthentication(t, allowed)
	assertNoExternalAuthentication(t, blocked)
	if !slices.Equal(allowed, base) || !slices.Equal(blocked, base) {
		t.Fatalf("external tool arguments changed: allowed=%#v blocked=%#v", allowed, blocked)
	}
	redactionArgs := engine.appendNucleiRedactionArgs(nil)
	if !slices.Contains(redactionArgs, "Authorization") || !slices.Contains(redactionArgs, "Cookie") {
		t.Fatalf("nuclei redaction keys missing from tool args: %#v", redactionArgs)
	}
}

func TestFindingInScope(t *testing.T) {
	policy := scopepolicy.New(config.TargetConfig{Domains: []string{"example.com", "*.example.com"}})
	if !findingInScope(policy, Finding{URL: "https://api.example.com/path"}) {
		t.Fatal("expected in-scope URL to be accepted")
	}
	if findingInScope(policy, Finding{URL: "https://example.com.evil.test/path"}) {
		t.Fatal("expected out-of-scope URL to be rejected")
	}
}

func TestRunFailsClosedOnInvalidScope(t *testing.T) {
	engine := newScannerTestEngine(t, config.ScanningConfig{})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"com"}}

	results, err := engine.Run(context.Background(), &recon.Results{
		Subdomains: []string{"example.com"},
	})
	if err == nil {
		t.Fatal("Run accepted a public suffix as scan authorization")
	}
	if results == nil || results.Complete || !slices.Contains(results.FailedTools, "scope") {
		t.Fatalf("invalid scope did not fail closed: %#v", results)
	}
	if results.Stats != (ScanStats{}) {
		t.Fatalf("invalid scope recorded work that must not run: %#v", results.Stats)
	}
}

func TestRunFailsClosedOnNilReconResults(t *testing.T) {
	engine := newScannerTestEngine(t, config.ScanningConfig{
		Tools: config.ScanningToolsConfig{Httpx: config.HttpxConfig{Enabled: true}},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com"}}

	results, err := engine.Run(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "non-nil reconnaissance results") {
		t.Fatalf("nil reconnaissance error = %v", err)
	}
	if results == nil || results.Complete || !slices.Equal(results.FailedTools, []string{"recon-input"}) {
		t.Fatalf("nil reconnaissance input did not fail closed: %#v", results)
	}
	if results.Stats != (ScanStats{}) || len(results.Findings) != 0 {
		t.Fatalf("nil reconnaissance input recorded work: %#v", results)
	}
}

func TestRunFiltersOutOfScopeTargetsBeforeExternalTools(t *testing.T) {
	httpxTargets := filepath.Join(t.TempDir(), "httpx-targets.txt")
	dalfoxTargets := filepath.Join(t.TempDir(), "dalfox-targets.txt")
	installFakeHttpx(t, fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-version" ]; then
  echo "projectdiscovery.io"
  exit 0
fi
while [ $# -gt 0 ]; do
  if [ "$1" = "-l" ]; then cp "$2" %s; fi
  shift
done
`, shellQuote(httpxTargets)))
	installFakeTool(t, "dalfox", fmt.Sprintf("#!/bin/sh\ncp \"$2\" %s\n", shellQuote(dalfoxTargets)))

	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads:   2,
		RateLimit: 2,
		Timeout:   5,
		Tools: config.ScanningToolsConfig{
			Httpx:  config.HttpxConfig{Enabled: true},
			Dalfox: config.DalfoxConfig{Enabled: true},
		},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}

	results, err := engine.Run(context.Background(), &recon.Results{
		Subdomains: []string{"app.example.com", "example.com.evil.test", "evil.test"},
		URLs: []string{
			"https://app.example.com/search?q=1",
			"https://example.com.evil.test/search?q=1",
			"https://evil.test/search?q=1",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !results.Complete || results.Stats.TotalAttempted != 2 || results.Stats.TotalScanned != 2 ||
		results.Stats.TotalSkipped != 0 || results.Stats.TotalFailed != 0 {
		t.Fatalf("unexpected scoped coverage: %#v", results)
	}
	if got := readArgumentLines(t, httpxTargets); !slices.Equal(got, []string{"app.example.com"}) {
		t.Fatalf("httpx received targets outside scope: %v", got)
	}
	if got := readArgumentLines(t, dalfoxTargets); !slices.Equal(got, []string{"https://app.example.com/search?q=1"}) {
		t.Fatalf("dalfox received URLs outside scope: %v", got)
	}
}

func TestDeduplicateFindingsKeepsDistinctIssuesOnSameURL(t *testing.T) {
	policy := scopepolicy.New(config.TargetConfig{Domains: []string{"example.com", "*.example.com"}})
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

func TestDeduplicateFindingsKeepsDistinctNmapPorts(t *testing.T) {
	policy := scopepolicy.New(config.TargetConfig{Domains: []string{"example.com", "*.example.com"}})
	findings := []Finding{
		{ID: "nmap-open-port", Type: "port-scan", Title: "Open Port Detected", Target: "app.example.com", Evidence: "80/tcp open http"},
		{ID: "nmap-open-port", Type: "port-scan", Title: "Open Port Detected", Target: "app.example.com", Evidence: "80/tcp open http nginx 1.25"},
		{ID: "nmap-open-port", Type: "port-scan", Title: "Open Port Detected", Target: "app.example.com", Evidence: "443/tcp open https"},
		{ID: "nmap-open-port", Type: "port-scan", Title: "Open Port Detected", Target: "api.example.com", Evidence: "80/tcp open http"},
	}

	got := deduplicateFindings(policy, findings)
	if len(got) != 3 {
		t.Fatalf("deduplicateFindings did not use host+port identity: %#v", got)
	}
}

func TestHttpxArgumentsRespectRateLimit(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "httpx-args.txt")
	goPath := t.TempDir()
	binDir := filepath.Join(goPath, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "httpx"), []byte(fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-version" ]; then
  echo "projectdiscovery.io"
  exit 0
fi
printf '%%s\n' "$@" > %s
`, shellQuote(capture))), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPATH", goPath)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+"/bin")

	engine := newScannerTestEngine(t, config.ScanningConfig{Threads: 20, RateLimit: 3})
	engine.cfg.Authentication = testAuthenticationConfig()
	if _, _, err := engine.runHttpx(context.Background(), []string{"app.example.com"}); err != nil {
		t.Fatal(err)
	}

	args := readArgumentLines(t, capture)
	if got := argumentValue(args, "-t"); got != "3" {
		t.Fatalf("httpx -t = %q, want 3; args: %v", got, args)
	}
	if got := argumentValue(args, "-rl"); got != "3" {
		t.Fatalf("httpx -rl = %q, want 3; args: %v", got, args)
	}
	assertNoExternalAuthentication(t, args)
}

func TestRunHttpxPreservesHostsAndRejectsMalformedJSONL(t *testing.T) {
	installFakeHttpx(t, `#!/bin/sh
if [ "$1" = "-version" ]; then
  echo "projectdiscovery.io"
  exit 0
fi
echo '{"url":"https://app.example.com"}'
echo 'not-json'
`)
	engine := newScannerTestEngine(t, config.ScanningConfig{Threads: 1, RateLimit: 1})

	_, hosts, err := engine.runHttpx(context.Background(), []string{"app.example.com"})
	if err == nil || !strings.Contains(err.Error(), "malformed JSON") {
		t.Fatalf("malformed httpx JSONL was not surfaced: %v", err)
	}
	if !slices.Equal(hosts, []string{"https://app.example.com"}) {
		t.Fatalf("valid host beside malformed output was lost: %#v", hosts)
	}
}

func TestRunDoesNotRetrySuccessfulHttpxWithNoLiveHosts(t *testing.T) {
	runs := filepath.Join(t.TempDir(), "httpx-runs.txt")
	installFakeHttpx(t, fmt.Sprintf(`#!/bin/sh
if [ "$1" = "-version" ]; then
  echo "projectdiscovery.io"
  exit 0
fi
echo run >> %s
`, shellQuote(runs)))

	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads: 2, RateLimit: 2, Timeout: 5,
		Tools: config.ScanningToolsConfig{Httpx: config.HttpxConfig{Enabled: true}},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}
	results, err := engine.Run(context.Background(), &recon.Results{
		Subdomains: []string{"app.example.com", "admin.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(runs)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "run\n"); got != 1 {
		t.Fatalf("successful empty httpx result ran %d times, want 1", got)
	}
	if !results.Complete || results.Stats.TotalAttempted != 2 || results.Stats.TotalScanned != 2 ||
		results.Stats.TotalFailed != 0 {
		t.Fatalf("unexpected zero-live-host coverage: %#v", results)
	}
}

func TestRunCountsOnlyRequestedHostsFromPartialHttpxOutput(t *testing.T) {
	installFakeHttpx(t, `#!/bin/sh
if [ "$1" = "-version" ]; then
  echo "projectdiscovery.io"
  exit 0
fi
echo '{"url":"https://app.example.com"}'
echo '{"url":"https://api.example.com"}'
exec sleep 5
`)
	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads: 2, RateLimit: 2, Timeout: 1,
		Tools: config.ScanningToolsConfig{Httpx: config.HttpxConfig{Enabled: true}},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}

	results, err := engine.Run(context.Background(), &recon.Results{
		Subdomains: []string{"app.example.com", "admin.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if results.Complete || !slices.Contains(results.FailedTools, "httpx") {
		t.Fatalf("partial httpx failure was not surfaced: %#v", results)
	}
	if results.Stats.TotalAttempted != 2 || results.Stats.TotalScanned != 1 ||
		results.Stats.TotalSkipped != 0 || results.Stats.TotalFailed != 1 {
		t.Fatalf("unrequested httpx output inflated coverage: %#v", results.Stats)
	}
}

func TestDalfoxArgumentsRespectRateLimit(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "dalfox-args.txt")
	installFakeTool(t, "dalfox", "#!/bin/sh\nprintf '%s\\n' \"$@\" > "+shellQuote(capture)+"\n")

	engine := newScannerTestEngine(t, config.ScanningConfig{Threads: 20, RateLimit: 5})
	engine.cfg.Authentication = testAuthenticationConfig()
	if _, err := engine.runDalfox(context.Background(), []string{"https://example.com/search?q=1"}); err != nil {
		t.Fatal(err)
	}

	args := readArgumentLines(t, capture)
	if got := argumentValue(args, "--worker"); got != "5" {
		t.Fatalf("dalfox --worker = %q, want 5; args: %v", got, args)
	}
	if got := argumentValue(args, "--delay"); got != "1000" {
		t.Fatalf("dalfox --delay = %q, want 1000; args: %v", got, args)
	}
	assertNoExternalAuthentication(t, args)
}

func TestRunDalfoxPreservesFindingsAndRejectsMalformedJSONL(t *testing.T) {
	installFakeTool(t, "dalfox", `#!/bin/sh
echo '{"type":"v","severity":"high","data":"https://example.com/search?q=poc","param":"q","inject_type":"attribute"}'
echo 'not-json'
`)
	engine := newScannerTestEngine(t, config.ScanningConfig{Threads: 1, RateLimit: 1})

	findings, err := engine.runDalfox(context.Background(), []string{"https://example.com/search?q=1"})
	if err == nil || !strings.Contains(err.Error(), "malformed JSON") {
		t.Fatalf("malformed dalfox JSONL was not surfaced: %v", err)
	}
	if len(findings) != 1 || findings[0].Type != "xss" {
		t.Fatalf("valid finding beside malformed output was lost: %#v", findings)
	}
}

func TestNmapArgumentsRespectRateLimitAndPreservePorts(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "nmap-args.txt")
	installFakeTool(t, "nmap", fmt.Sprintf(`#!/bin/sh
printf '%%s\n' "$@" > %s
echo "80/tcp open http"
echo "443/tcp open https"
`, shellQuote(capture)))

	engine := newScannerTestEngine(t, config.ScanningConfig{Threads: 20, RateLimit: 4})
	findings, scanned, failed, err := engine.runNmapWithStats(context.Background(), []string{"app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if scanned != 1 || failed != 0 {
		t.Fatalf("nmap coverage = scanned:%d failed:%d, want 1/0", scanned, failed)
	}
	if len(findings) != 2 {
		t.Fatalf("nmap returned %d ports, want 2: %#v", len(findings), findings)
	}

	args := readArgumentLines(t, capture)
	if got := argumentValue(args, "--max-rate"); got != "4" {
		t.Fatalf("nmap --max-rate = %q, want 4; args: %v", got, args)
	}
	if got := argumentValue(args, "--max-parallelism"); got != "4" {
		t.Fatalf("nmap --max-parallelism = %q, want 4; args: %v", got, args)
	}
	if !slices.Contains(args, "-T3") || slices.Contains(args, "-T4") {
		t.Fatalf("nmap timing profile is not conservative: %v", args)
	}
}

func TestRunMarksNmapTargetCapAsPartial(t *testing.T) {
	installFakeTool(t, "nmap", "#!/bin/sh\nexit 0\n")
	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads:   2,
		RateLimit: 2,
		Timeout:   5,
		Tools: config.ScanningToolsConfig{
			Nmap: config.NmapConfig{Enabled: true},
		},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}

	subdomains := []string{"example.com"}
	for i := 0; i < 25; i++ {
		subdomains = append(subdomains, fmt.Sprintf("host-%02d.example.com", i))
	}
	results, err := engine.Run(context.Background(), &recon.Results{Subdomains: subdomains})
	if err != nil {
		t.Fatal(err)
	}
	if results.Complete {
		t.Fatal("target cap was reported as complete")
	}
	if results.Stats.TotalAttempted != 25 || results.Stats.TotalScanned != 25 ||
		results.Stats.TotalSkipped != 1 || results.Stats.TotalFailed != 0 {
		t.Fatalf("unexpected capped coverage: %#v", results.Stats)
	}
}

func TestRunMarksNucleiTargetCapAsPartial(t *testing.T) {
	installFakeTool(t, "nuclei", "#!/bin/sh\nexit 0\n")
	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads:   2,
		RateLimit: 2,
		Timeout:   5,
		Tools: config.ScanningToolsConfig{
			Nuclei: config.NucleiConfig{Enabled: true},
		},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}

	subdomains := []string{"example.com"}
	for i := 0; i < 25; i++ {
		subdomains = append(subdomains, fmt.Sprintf("host-%02d.example.com", i))
	}
	results, err := engine.Run(context.Background(), &recon.Results{Subdomains: subdomains})
	if err != nil {
		t.Fatal(err)
	}
	if results.Complete {
		t.Fatal("nuclei target cap was reported as complete")
	}
	if results.Stats.TotalAttempted != 25 || results.Stats.TotalScanned != 25 ||
		results.Stats.TotalSkipped != 1 || results.Stats.TotalFailed != 0 {
		t.Fatalf("unexpected nuclei capped coverage: %#v", results.Stats)
	}
}

func TestRunTracksNmapToolFailures(t *testing.T) {
	installFakeTool(t, "nmap", "#!/bin/sh\nexit 1\n")
	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads:   2,
		RateLimit: 2,
		Timeout:   5,
		Tools: config.ScanningToolsConfig{
			Nmap: config.NmapConfig{Enabled: true},
		},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}

	results, err := engine.Run(context.Background(), &recon.Results{
		Subdomains: []string{"example.com", "app.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if results.Complete || !slices.Contains(results.FailedTools, "nmap") {
		t.Fatalf("nmap failure was not surfaced: %#v", results)
	}
	if results.Stats.TotalAttempted != 2 || results.Stats.TotalScanned != 0 ||
		results.Stats.TotalSkipped != 0 || results.Stats.TotalFailed != 2 {
		t.Fatalf("unexpected failed coverage: %#v", results.Stats)
	}
}

func TestRunMarksDalfoxURLCapAsPartial(t *testing.T) {
	installFakeTool(t, "dalfox", "#!/bin/sh\nexit 0\n")
	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads:   2,
		RateLimit: 2,
		Timeout:   5,
		Tools: config.ScanningToolsConfig{
			Dalfox: config.DalfoxConfig{Enabled: true, MaxURLs: 2},
		},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}

	results, err := engine.Run(context.Background(), &recon.Results{
		Subdomains: []string{"example.com"},
		URLs: []string{
			"https://example.com/search?q=1",
			"https://example.com/view?id=1",
			"https://example.com/redirect?next=/home",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if results.Complete {
		t.Fatal("dalfox URL cap was reported as complete")
	}
	if results.Stats.TotalAttempted != 2 || results.Stats.TotalScanned != 2 ||
		results.Stats.TotalSkipped != 1 || results.Stats.TotalFailed != 0 {
		t.Fatalf("unexpected dalfox coverage: %#v", results.Stats)
	}
}

func TestRunPreservesDalfoxFindingsAndMarksFailedCoverage(t *testing.T) {
	installFakeTool(t, "dalfox", `#!/bin/sh
echo '{"type":"v","severity":"high","data":"https://example.com/search?q=poc","param":"q","inject_type":"attribute"}'
echo 'simulated partial failure' >&2
exit 1
`)
	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads:   1,
		RateLimit: 1,
		Timeout:   5,
		Tools: config.ScanningToolsConfig{
			Dalfox: config.DalfoxConfig{Enabled: true},
		},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}

	results, err := engine.Run(context.Background(), &recon.Results{
		URLs: []string{"https://example.com/search?q=1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if results.Complete || !slices.Contains(results.FailedTools, "dalfox") {
		t.Fatalf("partial dalfox failure was not surfaced: %#v", results)
	}
	if len(results.Findings) != 1 || results.Findings[0].Type != "xss" {
		t.Fatalf("partial dalfox finding was lost: %#v", results.Findings)
	}
	if results.Stats.TotalAttempted != 1 || results.Stats.TotalScanned != 0 ||
		results.Stats.TotalSkipped != 0 || results.Stats.TotalFailed != 1 {
		t.Fatalf("unexpected dalfox failed coverage: %#v", results.Stats)
	}
}

func TestRunMarksNucleiTimeoutAsFailedCoverage(t *testing.T) {
	installFakeTool(t, "nuclei", "#!/bin/sh\nexec sleep 5\n")
	engine := newScannerTestEngine(t, config.ScanningConfig{
		Threads:   1,
		RateLimit: 1,
		Timeout:   1,
		Tools: config.ScanningToolsConfig{
			Nuclei: config.NucleiConfig{Enabled: true},
		},
	})
	engine.cfg.Target = config.TargetConfig{Domains: []string{"example.com", "*.example.com"}}

	results, err := engine.Run(context.Background(), &recon.Results{Subdomains: []string{"example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if results.Complete {
		t.Fatal("nuclei timeout was reported as complete")
	}
	if results.Stats.TotalAttempted != 1 || results.Stats.TotalScanned != 0 ||
		results.Stats.TotalSkipped != 0 || results.Stats.TotalFailed != 1 {
		t.Fatalf("unexpected timeout coverage: %#v", results.Stats)
	}
}

func argumentValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func readArgumentLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(data))
}

func installFakeTool(t *testing.T, name, script string) string {
	t.Helper()
	binDir := t.TempDir()
	path := filepath.Join(binDir, name)
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+"/bin")
	return binDir
}

func installFakeHttpx(t *testing.T, script string) string {
	t.Helper()
	goPath := t.TempDir()
	binDir := filepath.Join(goPath, "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(binDir, "httpx")
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPATH", goPath)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+"/bin")
	return path
}

func testAuthenticationConfig() config.AuthenticationConfig {
	return config.AuthenticationConfig{
		AllowedHosts: []string{"https://app.example.com"},
		Headers: map[string]string{
			"Authorization": "Bearer test-token; $(touch must-not-run)",
		},
		Cookies: map[string]string{"session": "test-session"},
	}
}

func assertNoExternalAuthentication(t *testing.T, args []string) {
	t.Helper()
	joined := strings.Join(args, "\x00")
	for _, secret := range []string{"test-token", "test-session", "must-not-run"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("authentication secret %q leaked to external process args: %#v", secret, args)
		}
	}
	if slices.Contains(args, "-H") || slices.Contains(args, "--header") {
		t.Fatalf("authentication flag leaked to external process args: %#v", args)
	}
}

func newScannerTestEngine(t *testing.T, scanning config.ScanningConfig) *Engine {
	t.Helper()
	log := logger.New(false)
	t.Cleanup(log.Close)
	return &Engine{
		cfg:                     &config.Config{Scanning: scanning},
		log:                     log,
		externalTargetValidator: allowExternalTargetForTest,
	}
}
