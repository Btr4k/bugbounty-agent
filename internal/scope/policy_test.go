package scope

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/config"
)

func TestPolicyAllowsOnlyTargetDomain(t *testing.T) {
	policy := New(config.TargetConfig{
		Domains:            []string{"example.com"},
		ExcludedSubdomains: []string{"admin.example.com", "*.legacy.example.com"},
	})

	tests := map[string]bool{
		"example.com":                    true,
		"api.example.com":                false,
		"https://api.example.com/path":   false,
		"admin.example.com":              false,
		"x.admin.example.com":            false,
		"legacy.example.com":             false,
		"x.legacy.example.com":           false,
		"example.com.evil.test":          false,
		"notexample.com":                 false,
		"https://example.com.evil.test/": false,
		"127.0.0.1":                      false,
	}

	for input, want := range tests {
		got := policy.AllowsHost(input)
		if got != want {
			t.Errorf("AllowsHost(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestPolicyFiltersURLs(t *testing.T) {
	policy := New(config.TargetConfig{Domains: []string{"*.example.com"}})
	got := policy.FilterURLs([]string{
		"https://example.com/a",
		"https://api.example.com/b",
		"https://evil.test/c",
		"https://example.com/a",
	})
	if len(got) != 1 || got[0] != "https://api.example.com/b" {
		t.Fatalf("wildcard-only scope must retain children but not the apex: %v", got)
	}
}

func TestPolicyRejectsUnsafeAuthorizationRoots(t *testing.T) {
	unsafe := []string{
		"com",
		"co.uk",
		"github.io",
		"localhost",
		"127.0.0.1",
		"127.1",
		"2130706433",
		"017700000001",
		"0x7f000001",
		"0x7f.0.0.1",
		"foo.local",
		"foo.example",
		"foo.test",
		"bad_label.example.com",
	}
	for _, target := range unsafe {
		t.Run(target, func(t *testing.T) {
			_, err := NewWithOptions(config.TargetConfig{Domains: []string{target}}, Options{})
			if !errors.Is(err, ErrInvalidTarget) {
				t.Fatalf("NewWithOptions(%q) error = %v, want ErrInvalidTarget", target, err)
			}

			legacy := New(config.TargetConfig{Domains: []string{target}})
			if legacy.ValidationError() == nil || legacy.AllowsHost("anything.example.com") {
				t.Fatalf("legacy constructor must fail closed for %q", target)
			}
		})
	}
}

func TestPolicyExplicitMatchModes(t *testing.T) {
	target := config.TargetConfig{Domains: []string{"example.com"}}
	exact, err := NewWithMode(target, ModeExact)
	if err != nil {
		t.Fatal(err)
	}
	withChildren, err := NewWithMode(target, ModeSubdomains)
	if err != nil {
		t.Fatal(err)
	}

	if !exact.AllowsHost("example.com") || exact.AllowsHost("api.example.com") {
		t.Fatal("exact mode must allow the configured root only")
	}
	if !withChildren.AllowsHost("example.com") || !withChildren.AllowsHost("api.example.com") {
		t.Fatal("subdomains mode must allow the root and its children")
	}
	if New(target).Mode() != ModeExact {
		t.Fatal("a bare rule must default to exact mode")
	}
	wildcard := New(config.TargetConfig{Domains: []string{"*.example.com"}})
	if wildcard.Mode() != ModeRules || wildcard.AllowsHost("example.com") || !wildcard.AllowsHost("api.example.com") {
		t.Fatal("a wildcard rule must authorize children only and report rule-derived mode")
	}
	combined := New(config.TargetConfig{Domains: []string{"example.com", "*.example.com"}})
	if combined.Mode() != ModeRules || !combined.AllowsHost("example.com") || !combined.AllowsHost("api.example.com") {
		t.Fatal("combined exact and wildcard rules must authorize both the apex and its children")
	}
	mixed := New(config.TargetConfig{Domains: []string{"example.com", "*.example.net"}})
	if mixed.Mode() != ModeRules || mixed.AllowsHost("api.example.com") || !mixed.AllowsHost("api.example.net") {
		t.Fatal("mixed exact and wildcard rules were not enforced independently")
	}
}

func TestAllowsURLRequiresHTTPWithoutUserinfo(t *testing.T) {
	policy := New(config.TargetConfig{Domains: []string{"example.com"}})
	for _, allowed := range []string{
		"https://example.com/path",
	} {
		if !policy.AllowsURL(allowed) {
			t.Errorf("AllowsURL(%q) = false, want true", allowed)
		}
	}
	for _, blocked := range []string{
		"http://api.example.com:8080/path",
		"ftp://example.com/file",
		"https://user:pass@example.com/",
		"https://127.0.0.1/",
		"https://example.com:99999/",
		"https://evil.test/",
	} {
		if policy.AllowsURL(blocked) {
			t.Errorf("AllowsURL(%q) = true, want false", blocked)
		}
	}
}

func TestResolveAndValidateHostBlocksEveryNonPublicClass(t *testing.T) {
	tests := map[string]string{
		"loopback":      "127.0.0.1",
		"private-v4":    "10.1.2.3",
		"carrier-nat":   "100.64.0.1",
		"link-local-v4": "169.254.1.2",
		"unspecified":   "0.0.0.0",
		"multicast":     "224.0.0.1",
		"documentation": "198.51.100.4",
		"benchmark":     "198.18.0.1",
		"reserved":      "240.0.0.1",
		"loopback-v6":   "::1",
		"private-v6":    "fd00::1",
		"link-local-v6": "fe80::1",
		"multicast-v6":  "ff02::1",
		"docs-v6":       "2001:db8::1",
	}
	for name, rawIP := range tests {
		t.Run(name, func(t *testing.T) {
			resolver := &sequenceResolver{answers: map[string][][]net.IPAddr{
				"example.com": {{{IP: net.ParseIP(rawIP)}}},
			}}
			policy := mustPolicy(t, resolver, nil)
			_, err := policy.ResolveAndValidateHost(context.Background(), "example.com")
			if !errors.Is(err, ErrUnsafeAddress) {
				t.Fatalf("address %s error = %v, want ErrUnsafeAddress", rawIP, err)
			}
		})
	}
}

func TestResolveRejectsMixedPublicAndPrivateAnswers(t *testing.T) {
	resolver := &sequenceResolver{answers: map[string][][]net.IPAddr{
		"example.com": {{
			{IP: net.ParseIP("8.8.8.8")},
			{IP: net.ParseIP("10.0.0.8")},
		}},
	}}
	policy := mustPolicy(t, resolver, nil)
	if _, err := policy.ResolveAndValidateHost(context.Background(), "example.com"); !errors.Is(err, ErrUnsafeAddress) {
		t.Fatalf("mixed answer error = %v, want ErrUnsafeAddress", err)
	}
}

func TestValidateURLChecksScopeAndDNS(t *testing.T) {
	resolver := &sequenceResolver{answers: map[string][][]net.IPAddr{
		"example.com":     {{{IP: net.ParseIP("8.8.8.8")}}},
		"api.example.com": {{{IP: net.ParseIP("1.1.1.1")}}},
	}}
	policy := mustPolicy(t, resolver, nil)
	if err := policy.ValidateURL(context.Background(), "https://api.example.com/path"); err != nil {
		t.Fatalf("safe in-scope URL rejected: %v", err)
	}
	if err := policy.ValidateURL(context.Background(), "https://evil.test/path"); !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("out-of-scope URL error = %v, want ErrOutOfScope", err)
	}
	if err := policy.ValidateURL(context.Background(), "file://example.com/tmp"); err == nil {
		t.Fatal("non-HTTP URL must be rejected")
	}
}

func TestCheckRedirectRevalidatesAndStripsSensitiveHeaders(t *testing.T) {
	resolver := &sequenceResolver{answers: map[string][][]net.IPAddr{
		"api.example.com": {{{IP: net.ParseIP("1.1.1.1")}}},
	}}
	policy := mustPolicy(t, resolver, nil)
	previousURL, _ := url.Parse("https://example.com/start")
	nextURL, _ := url.Parse("https://api.example.com/next")
	previous := &http.Request{URL: previousURL}
	next := &http.Request{
		URL: nextURL,
		Header: http.Header{
			"Authorization":       []string{"Bearer secret"},
			"Cookie":              []string{"session=secret"},
			"Proxy-Authorization": []string{"Basic secret"},
		},
	}
	if err := policy.CheckRedirect(next, []*http.Request{previous}); err != nil {
		t.Fatalf("safe redirect rejected: %v", err)
	}
	for _, header := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		if next.Header.Get(header) != "" {
			t.Errorf("%s was retained across a host-changing redirect", header)
		}
	}
	if resolver.callCount("api.example.com") != 1 {
		t.Fatal("redirect target must be resolved exactly once during redirect validation")
	}
}

func TestCheckRedirectTreatsSchemeAndPortAsOriginBoundaries(t *testing.T) {
	resolver := &sequenceResolver{answers: map[string][][]net.IPAddr{
		"example.com": {{{IP: net.ParseIP("8.8.8.8")}}},
	}}
	policy := mustPolicy(t, resolver, nil)
	tests := []struct {
		name       string
		from       string
		to         string
		wantSecret bool
	}{
		{name: "implicit and explicit HTTPS default port", from: "https://example.com/start", to: "https://example.com:443/next", wantSecret: true},
		{name: "HTTPS port change", from: "https://example.com/start", to: "https://example.com:8443/next", wantSecret: false},
		{name: "HTTPS downgrade", from: "https://example.com/start", to: "http://example.com/next", wantSecret: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			previousURL, _ := url.Parse(test.from)
			nextURL, _ := url.Parse(test.to)
			next := &http.Request{URL: nextURL, Header: http.Header{
				"Authorization": []string{"Bearer secret"},
				"Cookie":        []string{"session=secret"},
			}}
			if err := policy.CheckRedirect(next, []*http.Request{{URL: previousURL}}); err != nil {
				t.Fatal(err)
			}
			gotSecret := next.Header.Get("Authorization") != "" || next.Header.Get("Cookie") != ""
			if gotSecret != test.wantSecret {
				t.Fatalf("credentials retained = %v, want %v", gotSecret, test.wantSecret)
			}
		})
	}
}

func TestDialContextPinsResolvedIPAndResolvesEveryConnection(t *testing.T) {
	dialFailure := errors.New("synthetic dial stop")
	resolver := &sequenceResolver{answers: map[string][][]net.IPAddr{
		"example.com": {
			{{IP: net.ParseIP("8.8.8.8")}},
			{{IP: net.ParseIP("1.1.1.1")}},
		},
	}}
	dialer := &recordingDialer{err: dialFailure}
	policy := mustPolicy(t, resolver, dialer)

	for attempt := 0; attempt < 2; attempt++ {
		if _, err := policy.DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, dialFailure) {
			t.Fatalf("DialContext error = %v, want synthetic dial error", err)
		}
	}
	if resolver.callCount("example.com") != 2 {
		t.Fatalf("resolver calls = %d, want one per connection", resolver.callCount("example.com"))
	}
	got := dialer.addressesSnapshot()
	want := []string{"8.8.8.8:443", "1.1.1.1:443"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("dialed addresses = %v, want pinned numeric addresses %v", got, want)
	}
}

func TestRedirectThenDialClosesDNSRebindingWindow(t *testing.T) {
	resolver := &sequenceResolver{answers: map[string][][]net.IPAddr{
		"example.com": {
			{{IP: net.ParseIP("8.8.8.8")}},   // redirect validation
			{{IP: net.ParseIP("127.0.0.1")}}, // connection-time re-resolution
		},
	}}
	dialer := &recordingDialer{err: errors.New("must not be called")}
	policy := mustPolicy(t, resolver, dialer)

	redirectURL, _ := url.Parse("https://example.com/rebound")
	request := &http.Request{URL: redirectURL, Header: make(http.Header)}
	if err := policy.CheckRedirect(request, nil); err != nil {
		t.Fatalf("first public DNS answer should pass redirect validation: %v", err)
	}
	if _, err := policy.DialContext(context.Background(), "tcp", "example.com:443"); !errors.Is(err, ErrUnsafeAddress) {
		t.Fatalf("rebound dial error = %v, want ErrUnsafeAddress", err)
	}
	if len(dialer.addressesSnapshot()) != 0 {
		t.Fatal("numeric dialer was reached after a private rebound answer")
	}
}

func TestSafeHTTPClientDisablesProxyAndInstallsGuards(t *testing.T) {
	policy := mustPolicy(t, &sequenceResolver{}, &recordingDialer{})
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.Proxy = http.ProxyFromEnvironment
	baseTransport.DialTLS = func(string, string) (net.Conn, error) {
		return nil, errors.New("legacy TLS bypass reached")
	}
	baseTransport.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("TLS context bypass reached")
	}
	base := &http.Client{Transport: baseTransport}
	client := policy.SafeHTTPClient(base)

	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.DialContext == nil || transport.Proxy != nil ||
		transport.DialTLS != nil || transport.DialTLSContext != nil || client.CheckRedirect == nil {
		t.Fatal("safe client did not install direct guarded dial and redirect hooks")
	}
	if baseTransport.Proxy == nil || baseTransport.DialTLS == nil || baseTransport.DialTLSContext == nil {
		t.Fatal("SafeHTTPClient mutated the caller's transport")
	}
}

func TestPublicSuffixDatabaseCoversRegistriesAndHostedServices(t *testing.T) {
	for _, suffix := range []string{"com", "co.uk", "github.io", "appspot.com"} {
		if !isPublicSuffix(suffix) {
			t.Errorf("expected %q to be recognized as a public suffix", suffix)
		}
	}
	for _, registrable := range []string{"example.com", "example.co.uk", "tenant.github.io"} {
		if isPublicSuffix(registrable) {
			t.Errorf("registrable domain %q was treated as a public suffix", registrable)
		}
	}
}

func mustPolicy(t *testing.T, resolver Resolver, dialer ContextDialer) *Policy {
	t.Helper()
	policy, err := NewWithOptions(config.TargetConfig{Domains: []string{"example.com"}}, Options{
		Mode:     ModeSubdomains,
		Resolver: resolver,
		Dialer:   dialer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

type sequenceResolver struct {
	mu      sync.Mutex
	answers map[string][][]net.IPAddr
	calls   map[string]int
}

func (r *sequenceResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.calls == nil {
		r.calls = make(map[string]int)
	}
	index := r.calls[host]
	r.calls[host]++
	answers := r.answers[host]
	if len(answers) == 0 {
		return nil, fmt.Errorf("no fake DNS answer for %s", host)
	}
	if index >= len(answers) {
		index = len(answers) - 1
	}
	return append([]net.IPAddr(nil), answers[index]...), nil
}

func (r *sequenceResolver) callCount(host string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[host]
}

type recordingDialer struct {
	mu        sync.Mutex
	addresses []string
	err       error
}

func (d *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addresses = append(d.addresses, address)
	d.mu.Unlock()
	return nil, d.err
}

func (d *recordingDialer) addressesSnapshot() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addresses...)
}
