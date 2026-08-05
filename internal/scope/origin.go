package scope

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var (
	ErrInvalidPublicOrigin = errors.New("invalid public HTTPS origin")
	ErrOriginMismatch      = errors.New("request is outside the configured HTTPS origin")
)

// PublicOriginOptions provides deterministic resolver/dialer injection for a
// public service endpoint such as an AI API. Production callers normally leave
// both fields nil.
type PublicOriginOptions struct {
	Resolver Resolver
	Dialer   ContextDialer
}

// PublicOriginPolicy protects an exact HTTPS origin that is intentionally
// outside target scope. It rejects mixed/non-public DNS answers and connects to
// a validated numeric address, while TLS still authenticates the request URL's
// original hostname.
type PublicOriginPolicy struct {
	host     string
	port     string
	resolver Resolver
	dialer   ContextDialer
}

// NewPublicOriginPolicy validates the lexical origin. DNS is intentionally
// checked again at every connection boundary instead of being trusted here.
// Paths are permitted for versioned API bases; userinfo, queries, fragments,
// local names, public suffixes, and alternative IP spellings are not.
func NewPublicOriginPolicy(raw string, opts PublicOriginOptions) (*PublicOriginPolicy, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Opaque != "" || !strings.EqualFold(parsed.Scheme, "https") || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil, ErrInvalidPublicOrigin
	}

	host, err := canonicalPublicOriginHost(parsed.Hostname())
	if err != nil {
		return nil, ErrInvalidPublicOrigin
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	} else if value, convErr := strconv.Atoi(port); convErr != nil || value < 1 || value > 65535 {
		return nil, ErrInvalidPublicOrigin
	}

	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := opts.Dialer
	if dialer == nil {
		dialer = defaultDialer()
	}
	return &PublicOriginPolicy{host: host, port: port, resolver: resolver, dialer: dialer}, nil
}

func canonicalPublicOriginHost(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if host == "" {
		return "", ErrInvalidPublicOrigin
	}
	if ip := net.ParseIP(host); ip != nil {
		if !isPublicIP(ip) {
			return "", ErrUnsafeAddress
		}
		return ip.String(), nil
	}
	if looksLikeAlternativeIP(host) || validateTargetRoot(host) != nil {
		return "", ErrInvalidPublicOrigin
	}
	return host, nil
}

// AllowsURL is a DNS-free exact-origin check suitable for request dispatch.
func (p *PublicOriginPolicy) AllowsURL(raw string) bool {
	if p == nil {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Opaque != "" || parsed.User != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	host, err := canonicalPublicOriginHost(parsed.Hostname())
	if err != nil || host != p.host {
		return false
	}
	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return port == p.port
}

// ResolveAndValidate resolves the configured origin and rejects the entire
// answer set if even one address is private or special-use.
func (p *PublicOriginPolicy) ResolveAndValidate(ctx context.Context) ([]net.IPAddr, error) {
	if p == nil {
		return nil, ErrInvalidPublicOrigin
	}
	if literal := net.ParseIP(p.host); literal != nil {
		if !isPublicIP(literal) {
			return nil, ErrUnsafeAddress
		}
		return []net.IPAddr{{IP: append(net.IP(nil), literal...)}}, nil
	}

	addresses, err := p.resolver.LookupIPAddr(ctx, p.host)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
		return nil, errors.New("public origin DNS resolution failed")
	}
	if len(addresses) == 0 {
		return nil, errors.New("public origin DNS returned no addresses")
	}

	seen := make(map[string]bool, len(addresses))
	safe := make([]net.IPAddr, 0, len(addresses))
	for _, address := range addresses {
		if address.Zone != "" || !isPublicIP(address.IP) {
			return nil, ErrUnsafeAddress
		}
		key := address.IP.String()
		if key == "" {
			return nil, ErrUnsafeAddress
		}
		if !seen[key] {
			seen[key] = true
			safe = append(safe, net.IPAddr{IP: append(net.IP(nil), address.IP...)})
		}
	}
	return safe, nil
}

// ValidateURL verifies both exact origin and current public DNS without ever
// reflecting the caller-controlled URL in its error.
func (p *PublicOriginPolicy) ValidateURL(ctx context.Context, raw string) error {
	if !p.AllowsURL(raw) {
		return ErrOriginMismatch
	}
	_, err := p.ResolveAndValidate(ctx)
	return err
}

// DialContext pins each new connection to a freshly validated numeric address.
func (p *PublicOriginPolicy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if p == nil {
		return nil, ErrInvalidPublicOrigin
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("unsupported public-origin network")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid public-origin dial address")
	}
	canonicalHost, err := canonicalPublicOriginHost(host)
	if err != nil || canonicalHost != p.host || port != p.port {
		return nil, ErrOriginMismatch
	}

	addresses, err := p.ResolveAndValidate(ctx)
	if err != nil {
		return nil, err
	}
	for _, resolved := range addresses {
		ip := resolved.IP
		if network == "tcp4" && ip.To4() == nil {
			continue
		}
		if network == "tcp6" && ip.To4() != nil {
			continue
		}
		connection, dialErr := p.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return nil, contextErr
		}
	}
	return nil, errors.New("public origin connection failed")
}

// SafeTransport installs the public-address dialer and removes every alternate
// direct-TLS/proxy path that could bypass it.
func (p *PublicOriginPolicy) SafeTransport(base *http.Transport) *http.Transport {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	transport := base.Clone()
	transport.Proxy = nil
	transport.DialContext = p.DialContext
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.InsecureSkipVerify = false
		transport.TLSClientConfig.ServerName = ""
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	return transport
}

type exactPublicOriginTransport struct {
	policy *PublicOriginPolicy
	base   http.RoundTripper
}

func (transport exactPublicOriginTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request == nil || request.URL == nil || transport.policy == nil || !transport.policy.AllowsURL(request.URL.String()) {
		return nil, ErrOriginMismatch
	}
	return transport.base.RoundTrip(request)
}

// SafeHTTPClient returns a clone that refuses cross-origin requests and every
// redirect. http.ErrUseLastResponse prevents net/http from wrapping an untrusted
// Location URL into a diagnostic while still returning the bounded response to
// the caller for status handling.
func (p *PublicOriginPolicy) SafeHTTPClient(base *http.Client) *http.Client {
	client := &http.Client{}
	if base != nil {
		*client = *base
	}
	var transport *http.Transport
	if configured, ok := client.Transport.(*http.Transport); ok {
		transport = configured
	}
	client.Transport = exactPublicOriginTransport{policy: p, base: p.SafeTransport(transport)}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

// Origin returns the canonical scheme/host/effective-port tuple and never
// includes a path, userinfo, query, or fragment.
func (p *PublicOriginPolicy) Origin() string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("https://%s", net.JoinHostPort(p.host, p.port))
}
