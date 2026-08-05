package scope

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestPublicOriginRejectsUnsafeLexicalEndpoints(t *testing.T) {
	unsafe := []string{
		"http://ai.example.com/v1",
		"https://user:pass@ai.example.com/v1",
		"https://ai.example.com/v1?token=secret",
		"https://ai.example.com/v1#fragment",
		"https://localhost/v1",
		"https://metadata/v1",
		"https://127.0.0.1/v1",
		"https://127.1/v1",
		"https://2130706433/v1",
		"https://100.64.0.1/v1",
		"https://model.dev.internal/v1",
	}
	for _, raw := range unsafe {
		t.Run(raw, func(t *testing.T) {
			if _, err := NewPublicOriginPolicy(raw, PublicOriginOptions{}); !errors.Is(err, ErrInvalidPublicOrigin) {
				t.Fatalf("unsafe public origin error = %v, want ErrInvalidPublicOrigin", err)
			}
		})
	}
	if _, err := NewPublicOriginPolicy("https://8.8.8.8/v1", PublicOriginOptions{}); err != nil {
		t.Fatalf("public IP origin was rejected: %v", err)
	}
}

func TestPublicOriginRejectsMixedDNSBeforeDial(t *testing.T) {
	resolver := &sequenceResolver{answers: map[string][][]net.IPAddr{
		"ai.example.com": {{
			{IP: net.ParseIP("8.8.8.8")},
			{IP: net.ParseIP("10.0.0.8")},
		}},
	}}
	dialer := &recordingDialer{err: errors.New("must not be reached")}
	policy, err := NewPublicOriginPolicy("https://ai.example.com/v1", PublicOriginOptions{Resolver: resolver, Dialer: dialer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.DialContext(context.Background(), "tcp", "ai.example.com:443"); !errors.Is(err, ErrUnsafeAddress) {
		t.Fatalf("mixed DNS dial error = %v, want ErrUnsafeAddress", err)
	}
	if len(dialer.addressesSnapshot()) != 0 {
		t.Fatal("numeric dialer was reached after a mixed public/private DNS answer")
	}
}

func TestPublicOriginPinsNumericIPAndRechecksEveryConnection(t *testing.T) {
	resolver := &sequenceResolver{answers: map[string][][]net.IPAddr{
		"ai.example.com": {
			{{IP: net.ParseIP("8.8.8.8")}},
			{{IP: net.ParseIP("1.1.1.1")}},
		},
	}}
	dialer := &recordingDialer{err: errors.New("synthetic stop")}
	policy, err := NewPublicOriginPolicy("https://ai.example.com:8443/v1", PublicOriginOptions{Resolver: resolver, Dialer: dialer})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := policy.DialContext(context.Background(), "tcp", "ai.example.com:8443"); err == nil {
			t.Fatal("synthetic dial failure was hidden")
		}
	}
	if got := dialer.addressesSnapshot(); len(got) != 2 || got[0] != "8.8.8.8:8443" || got[1] != "1.1.1.1:8443" {
		t.Fatalf("public origin did not pin fresh numeric answers: %v", got)
	}
	if policy.Origin() != "https://ai.example.com:8443" {
		t.Fatalf("unexpected canonical origin: %q", policy.Origin())
	}
}

func TestPublicOriginClientClosesProxyTLSAndRedirectBypasses(t *testing.T) {
	policy, err := NewPublicOriginPolicy("https://ai.example.com/v1", PublicOriginOptions{
		Resolver: &sequenceResolver{answers: map[string][][]net.IPAddr{
			"ai.example.com": {{{IP: net.ParseIP("8.8.8.8")}}},
		}},
		Dialer: &recordingDialer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = http.ProxyFromEnvironment
	base.DialTLS = func(string, string) (net.Conn, error) { return nil, errors.New("legacy bypass") }
	base.DialTLSContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("context bypass") }
	base.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, ServerName: "attacker.example"} //nolint:gosec -- adversarial fixture

	transport := policy.SafeTransport(base)
	if transport.Proxy != nil || transport.DialContext == nil || transport.DialTLS != nil || transport.DialTLSContext != nil {
		t.Fatal("public-origin transport retained an alternate network path")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify ||
		transport.TLSClientConfig.ServerName != "" || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("unsafe TLS configuration survived: %#v", transport.TLSClientConfig)
	}
	if base.Proxy == nil || base.DialTLS == nil || base.DialTLSContext == nil || !base.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("SafeTransport mutated the caller's transport")
	}

	client := policy.SafeHTTPClient(&http.Client{Transport: base})
	redirect, _ := http.NewRequest(http.MethodPost, "https://redirect.example/steal?token=DO_NOT_LOG", nil)
	if err := client.CheckRedirect(redirect, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect was not stopped without reflecting its URL: %v", err)
	}
	if _, ok := client.Transport.(exactPublicOriginTransport); !ok {
		t.Fatalf("client omitted exact-origin request wrapper: %T", client.Transport)
	}
}

type originRoundTripFunc func(*http.Request) (*http.Response, error)

func (function originRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestExactPublicOriginTransportRejectsCrossOriginWithoutDispatch(t *testing.T) {
	policy, err := NewPublicOriginPolicy("https://ai.example.com/v1", PublicOriginOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dispatched := 0
	transport := exactPublicOriginTransport{policy: policy, base: originRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		dispatched++
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: request}, nil
	})}

	allowed, _ := http.NewRequest(http.MethodPost, "https://ai.example.com/chat/completions", nil)
	if _, err := transport.RoundTrip(allowed); err != nil {
		t.Fatalf("exact-origin request rejected: %v", err)
	}
	blocked, _ := http.NewRequest(http.MethodPost, "https://other.example.com/steal?token=DO_NOT_LOG", nil)
	_, err = transport.RoundTrip(blocked)
	if !errors.Is(err, ErrOriginMismatch) || strings.Contains(err.Error(), "DO_NOT_LOG") {
		t.Fatalf("unsafe cross-origin diagnostic: %v", err)
	}
	if dispatched != 1 {
		t.Fatalf("cross-origin request reached base transport: dispatches=%d", dispatched)
	}
}
