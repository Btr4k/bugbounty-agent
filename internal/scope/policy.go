package scope

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/config"
)

// MatchMode controls whether an authorized root also authorizes its children.
type MatchMode string

const (
	// ModeRules derives authorization from each configured rule: a bare hostname
	// is exact, while a leading "*." explicitly includes its DNS children.
	ModeRules MatchMode = "rules"
	// ModeSubdomains forces every configured root to authorize both the root
	// itself and all of its DNS subdomains.
	ModeSubdomains MatchMode = "subdomains"
	// ModeExact authorizes configured hostnames only.
	ModeExact MatchMode = "exact"
)

var (
	ErrInvalidTarget = errors.New("invalid scope target")
	ErrOutOfScope    = errors.New("host is outside the authorized scope")
	ErrUnsafeAddress = errors.New("host resolves to a non-public address")
)

// Resolver is deliberately compatible with net.Resolver and injectable so
// callers can make DNS decisions deterministic in tests.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ContextDialer is the subset of net.Dialer used by the guarded transport.
// Supplying one is primarily useful for tests and controlled runtimes.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Options configures a Policy. A zero Mode uses the explicit rule syntax: bare
// hostnames are exact and "*." rules include children.
type Options struct {
	Mode     MatchMode
	Resolver Resolver
	Dialer   ContextDialer
}

// Policy is the single source of truth for deciding whether a host or URL is
// authorized for active scanning. Static Allows* methods never perform DNS.
// ResolveAndValidateHost, DialContext, and CheckRedirect add network safety.
type Policy struct {
	domains       []authorizationRule
	excluded      []authorizationRule
	mode          MatchMode
	resolver      Resolver
	dialer        ContextDialer
	validationErr error
}

type authorizationRule struct {
	host       string
	subdomains bool
	apex       bool
}

// New derives scope from the configured rules. Bare domains are exact; only a
// leading "*." authorizes children. Invalid rules create a fail-closed policy;
// ValidationError exposes the reason.
func New(target config.TargetConfig) *Policy {
	p, err := NewWithOptions(target, Options{Mode: ModeRules})
	if err == nil {
		return p
	}
	return &Policy{
		mode:          ModeRules,
		resolver:      net.DefaultResolver,
		dialer:        defaultDialer(),
		validationErr: err,
	}
}

// NewWithMode creates a policy using an explicit matching mode.
func NewWithMode(target config.TargetConfig, mode MatchMode) (*Policy, error) {
	return NewWithOptions(target, Options{Mode: mode})
}

// NewWithOptions validates every configured rule and returns a fail-closed
// policy on error. Public suffixes, single-label names, IP literals, alternative
// IP spellings, and malformed DNS names are never valid authorization roots.
func NewWithOptions(target config.TargetConfig, opts Options) (*Policy, error) {
	requestedMode := opts.Mode
	if requestedMode == "" {
		requestedMode = ModeRules
	}
	if requestedMode != ModeRules && requestedMode != ModeSubdomains && requestedMode != ModeExact {
		return nil, fmt.Errorf("%w: unsupported match mode %q", ErrInvalidTarget, requestedMode)
	}

	domains, err := normalizeAndValidateRules(target.Domains, requestedMode)
	if err != nil {
		return nil, err
	}
	if len(domains) == 0 {
		return nil, fmt.Errorf("%w: at least one domain is required", ErrInvalidTarget)
	}
	excludedRules, err := normalizeAndValidateRules(target.ExcludedSubdomains, ModeSubdomains)
	if err != nil {
		return nil, fmt.Errorf("invalid excluded domain: %w", err)
	}

	mode := requestedMode
	if requestedMode == ModeRules {
		hasExact, hasSubdomains := false, false
		for _, rule := range domains {
			if rule.subdomains {
				hasSubdomains = true
			} else {
				hasExact = true
			}
		}
		if hasExact && !hasSubdomains {
			mode = ModeExact
		} else {
			// Explicit wildcard rules exclude their apex, whereas legacy
			// ModeSubdomains includes it; keep ModeRules so Mode() is unambiguous.
			mode = ModeRules
		}
	}

	resolver := opts.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := opts.Dialer
	if dialer == nil {
		dialer = defaultDialer()
	}

	return &Policy{
		domains:  domains,
		excluded: excludedRules,
		mode:     mode,
		resolver: resolver,
		dialer:   dialer,
	}, nil
}

func defaultDialer() *net.Dialer {
	return &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
}

// ValidationError is non-nil when the backward-compatible New constructor had
// to create a deny-all policy because one of its rules was unsafe.
func (p *Policy) ValidationError() error {
	if p == nil {
		return fmt.Errorf("%w: nil policy", ErrInvalidTarget)
	}
	return p.validationErr
}

// Mode returns the policy's configured matching behavior.
func (p *Policy) Mode() MatchMode {
	if p == nil {
		return ""
	}
	return p.mode
}

func (p *Policy) AllowsHost(raw string) bool {
	if p == nil || p.validationErr != nil {
		return false
	}
	host := normalizeHost(raw)
	if validateHostname(host) != nil {
		return false
	}

	for _, excluded := range p.excluded {
		// Exclusions stay subtree-wide in both modes. This is fail-closed and
		// preserves the previous wildcard/exclusion semantics.
		if matchesDomainAndChildren(host, excluded.host) {
			return false
		}
	}
	for _, domain := range p.domains {
		if (domain.apex && host == domain.host) ||
			(domain.subdomains && strings.HasSuffix(host, "."+domain.host)) {
			return true
		}
	}
	return false
}

func (p *Policy) AllowsURL(raw string) bool {
	parsed, err := parseHTTPURL(raw)
	if err != nil {
		return false
	}
	return p.AllowsHost(parsed.Hostname())
}

func (p *Policy) FilterHosts(hosts []string) []string {
	return filterUnique(hosts, p.AllowsHost)
}

func (p *Policy) FilterURLs(urls []string) []string {
	return filterUnique(urls, p.AllowsURL)
}

// ResolveAndValidateHost resolves an authorized hostname and rejects the entire
// answer set when any address is non-public. No DNS result is cached: each call
// represents a fresh connection/redirect boundary.
func (p *Policy) ResolveAndValidateHost(ctx context.Context, raw string) ([]net.IPAddr, error) {
	if p == nil || p.validationErr != nil {
		if p != nil && p.validationErr != nil {
			return nil, p.validationErr
		}
		return nil, fmt.Errorf("%w: nil policy", ErrInvalidTarget)
	}
	host := normalizeHost(raw)
	if !p.AllowsHost(host) {
		return nil, fmt.Errorf("%w: %q", ErrOutOfScope, host)
	}

	addresses, err := p.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve %q: no addresses returned", host)
	}

	seen := make(map[string]bool, len(addresses))
	safe := make([]net.IPAddr, 0, len(addresses))
	for _, address := range addresses {
		if address.Zone != "" || !isPublicIP(address.IP) {
			return nil, fmt.Errorf("%w: %q resolved to %q", ErrUnsafeAddress, host, address.String())
		}
		key := address.IP.String()
		if key == "" {
			return nil, fmt.Errorf("%w: %q returned an invalid IP", ErrUnsafeAddress, host)
		}
		if !seen[key] {
			seen[key] = true
			safe = append(safe, net.IPAddr{IP: append(net.IP(nil), address.IP...)})
		}
	}
	return safe, nil
}

// ValidateURL performs the network-aware URL check used at redirect boundaries.
func (p *Policy) ValidateURL(ctx context.Context, raw string) error {
	parsed, err := parseHTTPURL(raw)
	if err != nil {
		return err
	}
	if !p.AllowsHost(parsed.Hostname()) {
		return fmt.Errorf("%w: %q", ErrOutOfScope, parsed.Hostname())
	}
	_, err = p.ResolveAndValidateHost(ctx, parsed.Hostname())
	return err
}

// CheckRedirect is suitable for http.Client.CheckRedirect. It validates scope
// and DNS on every hop. Sensitive headers are removed on host changes before the
// request can be sent, even when both hosts are otherwise in scope.
func (p *Policy) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	if req == nil || req.URL == nil {
		return fmt.Errorf("invalid redirect request")
	}
	if len(via) > 0 && !sameHTTPOrigin(via[len(via)-1].URL, req.URL) {
		for _, header := range []string{"Authorization", "Cookie", "Cookie2", "Proxy-Authorization"} {
			req.Header.Del(header)
		}
	}
	return p.ValidateURL(req.Context(), req.URL.String())
}

func sameHTTPOrigin(left, right *url.URL) bool {
	if left == nil || right == nil ||
		!strings.EqualFold(left.Scheme, right.Scheme) ||
		!strings.EqualFold(left.Hostname(), right.Hostname()) {
		return false
	}
	return effectiveHTTPPort(left) == effectiveHTTPPort(right)
}

func effectiveHTTPPort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(parsed.Scheme, "http") {
		return "80"
	}
	return ""
}

// DialContext is suitable for http.Transport.DialContext. It resolves on every
// new connection, validates every returned address, then dials the already
// resolved numeric IP. This removes the DNS-check-to-connect TOCTOU window.
func (p *Policy) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("unsupported guarded network %q", network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid dial address %q: %w", address, err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, fmt.Errorf("invalid dial port %q", port)
	}

	addresses, err := p.ResolveAndValidateHost(ctx, host)
	if err != nil {
		return nil, err
	}
	var dialErrors []error
	for _, resolved := range addresses {
		ip := resolved.IP
		if network == "tcp4" && ip.To4() == nil {
			continue
		}
		if network == "tcp6" && ip.To4() != nil {
			continue
		}
		conn, dialErr := p.dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, dialErr)
	}
	if len(dialErrors) == 0 {
		return nil, fmt.Errorf("no %s address available for %q", network, host)
	}
	return nil, errors.Join(dialErrors...)
}

// SafeTransport clones base (or http.DefaultTransport) and installs the guarded
// dialer. Proxies are disabled because a proxy would resolve the hostname again,
// defeating address validation and IP pinning.
func (p *Policy) SafeTransport(base *http.Transport) *http.Transport {
	if base == nil {
		base = http.DefaultTransport.(*http.Transport)
	}
	transport := base.Clone()
	transport.Proxy = nil
	transport.DialContext = p.DialContext
	// A caller-supplied TLS dialer takes precedence over DialContext for direct
	// HTTPS requests. Retaining either hook would silently bypass scope checks,
	// public-address validation, and numeric-IP pinning.
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	return transport
}

// SafeHTTPClient returns a shallow clone of base (or a default client) wired for
// guarded direct connections and redirect validation.
func (p *Policy) SafeHTTPClient(base *http.Client) *http.Client {
	client := &http.Client{}
	if base != nil {
		*client = *base
	}
	var transport *http.Transport
	if configured, ok := client.Transport.(*http.Transport); ok {
		transport = configured
	}
	client.Transport = p.SafeTransport(transport)
	client.CheckRedirect = p.CheckRedirect
	return client
}

func normalizeAndValidateRules(rules []string, mode MatchMode) ([]authorizationRule, error) {
	seen := make(map[string]bool)
	var normalized []authorizationRule
	for _, raw := range rules {
		host, wildcard, err := parseAuthorizationRule(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: %q: %v", ErrInvalidTarget, raw, err)
		}
		includeSubdomains := wildcard
		includeApex := !wildcard
		switch mode {
		case ModeExact:
			includeSubdomains = false
			includeApex = true
		case ModeSubdomains:
			includeSubdomains = true
			includeApex = true
		}
		key := fmt.Sprintf("%t:%t:%s", includeApex, includeSubdomains, host)
		if !seen[key] {
			seen[key] = true
			normalized = append(normalized, authorizationRule{host: host, subdomains: includeSubdomains, apex: includeApex})
		}
	}
	return normalized, nil
}

func parseAuthorizationRule(raw string) (string, bool, error) {
	rule := strings.ToLower(strings.TrimSpace(raw))
	if rule == "" || strings.ContainsAny(rule, "\r\n") {
		return "", false, errors.New("authorization root is empty or multiline")
	}
	wildcard := strings.HasPrefix(rule, "*.")
	if wildcard {
		rule = strings.TrimPrefix(rule, "*.")
	}
	// Authorization roots are DNS names, not URLs. Rejecting URL syntax avoids
	// silently broadening malformed input while normalizing it.
	if strings.ContainsAny(rule, "/\\:@?#[]*") || strings.HasPrefix(rule, ".") {
		return "", false, errors.New("authorization root must be a DNS hostname")
	}
	rule = strings.TrimSuffix(rule, ".")
	if err := validateTargetRoot(rule); err != nil {
		return "", false, err
	}
	return rule, wildcard, nil
}

func normalizeHost(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		raw = parsed.Hostname()
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, ".")
	return raw
}

func validateTargetRoot(host string) error {
	if err := validateHostname(host); err != nil {
		return err
	}
	if isPublicSuffix(host) {
		return fmt.Errorf("public suffixes cannot be authorization roots")
	}
	if !hasRecognizedICANNTLD(host) {
		return fmt.Errorf("authorization root must use a recognized public DNS suffix")
	}
	return nil
}

func validateHostname(host string) error {
	if host == "" {
		return errors.New("hostname is empty")
	}
	if net.ParseIP(host) != nil || looksLikeAlternativeIP(host) {
		return errors.New("IP literals and IP-like hostnames are not allowed")
	}
	if len(host) > 253 {
		return errors.New("hostname exceeds 253 bytes")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return errors.New("single-label hostnames are not allowed")
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("hostname contains an invalid DNS label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return errors.New("hostname contains non-DNS characters")
			}
		}
	}
	return nil
}

func looksLikeAlternativeIP(host string) bool {
	parts := strings.Split(strings.ToLower(host), ".")
	if len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		base := 10
		digits := part
		if strings.HasPrefix(part, "0x") {
			base = 16
			digits = part[2:]
		} else if len(part) > 1 && part[0] == '0' {
			base = 8
			digits = part[1:]
		}
		if digits == "" {
			return false
		}
		if _, err := strconv.ParseUint(digits, base, 32); err != nil {
			return false
		}
	}
	return true
}

func parseHTTPURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
		return nil, fmt.Errorf("invalid URL %q", raw)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("URL scheme %q is not allowed", parsed.Scheme)
	}
	if parsed.User != nil {
		return nil, errors.New("URL userinfo is not allowed")
	}
	if port := parsed.Port(); port != "" {
		value, convErr := strconv.Atoi(port)
		if convErr != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("invalid URL port %q", port)
		}
	}
	return parsed, nil
}

func matchesDomainAndChildren(host, domain string) bool {
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func filterUnique(items []string, allowed func(string) bool) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(items))
	for _, item := range items {
		key := strings.ToLower(strings.TrimSpace(item))
		if key == "" || seen[key] || !allowed(item) {
			continue
		}
		seen[key] = true
		result = append(result, item)
	}
	return result
}
