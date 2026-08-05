package recon

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/config"
)

type allowAllURLScope struct{}

func (allowAllURLScope) AllowsURL(string) bool { return true }

// staticOnlyURLScope preserves the static authorization decision while hiding
// guarded DNS methods. Redirect unit tests use a scripted transport and should
// not depend on public DNS for example.com test names; DNS enforcement has
// dedicated resolver-injected tests in the scope package.
type staticOnlyURLScope struct{ inner urlScope }

func (s staticOnlyURLScope) AllowsURL(raw string) bool { return s.inner.AllowsURL(raw) }

func withoutDNSValidation(policy jsRequestPolicy) jsRequestPolicy {
	policy.scope = staticOnlyURLScope{inner: policy.scope}
	return policy
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func redirectResponse(req *http.Request, location string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusFound,
		Status:     "302 Found",
		Header:     http.Header{"Location": []string{location}},
		Body:       io.NopCloser(strings.NewReader("")),
		Request:    req,
	}
}

func okResponse(req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}
}

func testAuthentication() config.AuthenticationConfig {
	return config.AuthenticationConfig{
		AllowedHosts: []string{"app.example.com"},
		Headers: map[string]string{
			"Authorization":  "Bearer test-token",
			"X-Test-Session": "test-session",
		},
		Cookies: map[string]string{"session": "test-cookie"},
	}
}

func TestJSRequestPolicyOnlyAttachesCredentialsToAllowedHTTPSURL(t *testing.T) {
	policy := newJSRequestPolicy(&config.Config{
		Target:         config.TargetConfig{Domains: []string{"*.example.com"}},
		Authentication: testAuthentication(),
	})
	policy = withoutDNSValidation(policy)

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "allowed https origin", url: "https://app.example.com/app.js", want: true},
		{name: "allowed https custom port", url: "https://app.example.com:8443/app.js", want: true},
		{name: "plaintext http", url: "http://app.example.com/app.js", want: false},
		{name: "bare host", url: "app.example.com/app.js", want: false},
		{name: "unlisted subdomain", url: "https://child.app.example.com/app.js", want: false},
		{name: "out of scope", url: "https://evil.test/app.js", want: false},
		{name: "url userinfo", url: "https://user:password@app.example.com/app.js", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := policy.headersForURL(tt.url)
			got := headers["Authorization"] != "" || headers["Cookie"] != ""
			if got != tt.want {
				t.Fatalf("credentials present = %v, want %v (headers: %#v)", got, tt.want, headers)
			}
		})
	}
}

func TestSecureOriginNormalizesDefaultHTTPSPort(t *testing.T) {
	_, implicit, ok := secureOrigin("https://app.example.com/a")
	if !ok {
		t.Fatal("implicit HTTPS origin was rejected")
	}
	_, explicit, ok := secureOrigin("https://APP.example.com:443/b")
	if !ok {
		t.Fatal("explicit HTTPS origin was rejected")
	}
	_, otherPort, ok := secureOrigin("https://app.example.com:8443/c")
	if !ok {
		t.Fatal("custom HTTPS origin was rejected")
	}
	if implicit != explicit {
		t.Fatalf("default HTTPS origins differ: %q != %q", implicit, explicit)
	}
	if implicit == otherPort {
		t.Fatalf("different ports collapsed to the same origin: %q", implicit)
	}
}

func TestJSRedirectCredentialPolicy(t *testing.T) {
	policy := newJSRequestPolicy(&config.Config{
		Target:         config.TargetConfig{Domains: []string{"*.example.com"}},
		Authentication: testAuthentication(),
	})
	policy = withoutDNSValidation(policy)

	tests := []struct {
		name              string
		destination       string
		wantSecondRequest bool
		wantCredentials   bool
	}{
		{
			name:              "same origin preserves credentials",
			destination:       "https://app.example.com/next.js",
			wantSecondRequest: true,
			wantCredentials:   true,
		},
		{
			name:              "explicit default port is same origin",
			destination:       "https://app.example.com:443/next.js",
			wantSecondRequest: true,
			wantCredentials:   true,
		},
		{
			name:              "subdomain redirect strips credentials",
			destination:       "https://child.app.example.com/next.js",
			wantSecondRequest: true,
			wantCredentials:   false,
		},
		{
			name:              "port change strips credentials",
			destination:       "https://app.example.com:8443/next.js",
			wantSecondRequest: true,
			wantCredentials:   false,
		},
		{
			name:              "downgrade is not followed",
			destination:       "http://app.example.com/next.js",
			wantSecondRequest: false,
			wantCredentials:   false,
		},
		{
			name:              "out of scope redirect is not followed",
			destination:       "https://evil.test/next.js",
			wantSecondRequest: false,
			wantCredentials:   false,
		},
		{
			name:              "userinfo redirect is not followed",
			destination:       "https://user:password@app.example.com/next.js",
			wantSecondRequest: false,
			wantCredentials:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			var redirectedHeaders http.Header
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return redirectResponse(req, tt.destination), nil
				}
				redirectedHeaders = req.Header.Clone()
				return okResponse(req), nil
			})
			client := newJSHTTPClient(policy, transport)

			req, err := http.NewRequest(http.MethodGet, "https://app.example.com/start.js", nil)
			if err != nil {
				t.Fatal(err)
			}
			for name, value := range policy.headersForURL(req.URL.String()) {
				req.Header.Set(name, value)
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("redirect request failed: %v", err)
			}
			resp.Body.Close()

			gotSecondRequest := calls == 2
			if gotSecondRequest != tt.wantSecondRequest {
				t.Fatalf("second request = %v, want %v (calls: %d)", gotSecondRequest, tt.wantSecondRequest, calls)
			}
			if !tt.wantSecondRequest {
				return
			}

			gotCredentials := redirectedHeaders.Get("Authorization") != "" ||
				redirectedHeaders.Get("Cookie") != "" ||
				redirectedHeaders.Get("X-Test-Session") != ""
			if gotCredentials != tt.wantCredentials {
				t.Fatalf("redirected credentials present = %v, want %v (headers: %#v)", gotCredentials, tt.wantCredentials, redirectedHeaders)
			}
		})
	}
}

func TestJSRedirectLoopStopsAfterTenRequests(t *testing.T) {
	policy := newJSRequestPolicy(&config.Config{
		Target:         config.TargetConfig{Domains: []string{"*.example.com"}},
		Authentication: testAuthentication(),
	})
	policy = withoutDNSValidation(policy)
	calls := 0
	client := newJSHTTPClient(policy, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return redirectResponse(req, "https://app.example.com/loop.js"), nil
	}))

	req, err := http.NewRequest(http.MethodGet, "https://app.example.com/loop.js", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range policy.headersForURL(req.URL.String()) {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "stopped after 10 redirects") {
		t.Fatalf("expected redirect-limit error, got %v", err)
	}
	if calls != 10 {
		t.Fatalf("redirect loop made %d requests, want 10", calls)
	}
}

func TestJSHTTPClientRejectsUntrustedTLSCertificate(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	client := newJSHTTPClient(jsRequestPolicy{scope: allowAllURLScope{}}, nil)
	resp, err := client.Get(server.URL)
	if resp != nil {
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("self-signed TLS certificate was unexpectedly accepted")
	}
}

func TestJSHTTPClientTrustedTestCAAllowsHTTPSAuthentication(t *testing.T) {
	received := make(chan http.Header, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		received <- req.Header.Clone()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("trusted"))
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy := jsRequestPolicy{
		scope: allowAllURLScope{},
		authentication: config.AuthenticationConfig{
			AllowedHosts: []string{parsed.Hostname()},
			Headers:      map[string]string{"Authorization": "Bearer trusted-test-token"},
			Cookies:      map[string]string{"session": "trusted-test-cookie"},
		},
	}

	trustedTransport, ok := server.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatalf("unexpected test transport type %T", server.Client().Transport)
	}
	if trustedTransport.TLSClientConfig != nil && trustedTransport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("test transport unexpectedly skips TLS verification")
	}
	client := newJSHTTPClient(policy, trustedTransport.Clone())
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range policy.headersForURL(req.URL.String()) {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("trusted TLS request failed: %v", err)
	}
	resp.Body.Close()

	headers := <-received
	if headers.Get("Authorization") != "Bearer trusted-test-token" || headers.Get("Cookie") != "session=trusted-test-cookie" {
		t.Fatalf("trusted HTTPS request did not receive credentials: %#v", headers)
	}
}

func TestNormalizeJSURLRejectsNonHTTPAndUserinfo(t *testing.T) {
	for _, raw := range []string{
		"file://app.example.com/app.js",
		"http://app.example.com/app.js",
		"https://user:password@app.example.com/app.js",
		"javascript://app.example.com/app.js",
	} {
		if parsed, ok := normalizeJSURL(raw); ok {
			t.Errorf("normalizeJSURL(%q) unexpectedly accepted %v", raw, parsed)
		}
	}
	parsed, ok := normalizeJSURL("app.example.com/app.js")
	if !ok || parsed.String() != "https://app.example.com/app.js" {
		t.Fatalf("bare host did not normalize to HTTPS: %v, %v", parsed, ok)
	}
}

func TestCheckRedirectRejectsMissingOrigin(t *testing.T) {
	policy := jsRequestPolicy{scope: allowAllURLScope{}}
	req, err := http.NewRequest(http.MethodGet, "https://app.example.com/next", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer must-be-removed")
	err = policy.checkRedirect(req, nil)
	if err == nil || req.Header.Get("Authorization") != "" {
		t.Fatalf("missing-origin redirect was not rejected safely: err=%v headers=%#v", err, req.Header)
	}
}

func TestRedirectStopUsesErrUseLastResponse(t *testing.T) {
	policy := newJSRequestPolicy(&config.Config{
		Target:         config.TargetConfig{Domains: []string{"example.com"}},
		Authentication: testAuthentication(),
	})
	initial, _ := http.NewRequest(http.MethodGet, "https://app.example.com/start", nil)
	destination, _ := http.NewRequest(http.MethodGet, "http://app.example.com/end", nil)
	destination.Header.Set("Authorization", "Bearer test-token")
	err := policy.checkRedirect(destination, []*http.Request{initial})
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("downgrade returned %v, want ErrUseLastResponse", err)
	}
	if destination.Header.Get("Authorization") != "" {
		t.Fatal("downgrade retained Authorization header")
	}
}
