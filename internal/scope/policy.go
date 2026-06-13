package scope

import (
	"net"
	"net/url"
	"strings"

	"github.com/Btr4k/bugbounty-agent/internal/config"
)

// Policy is the single source of truth for deciding whether a host or URL is
// authorized for active scanning.
type Policy struct {
	domains  []string
	excluded []string
}

func New(target config.TargetConfig) *Policy {
	return &Policy{
		domains:  normalizeRules(target.Domains),
		excluded: normalizeRules(target.ExcludedSubdomains),
	}
}

func (p *Policy) AllowsHost(raw string) bool {
	host := normalizeHost(raw)
	if host == "" || net.ParseIP(host) != nil {
		return false
	}

	for _, excluded := range p.excluded {
		if matchesDomain(host, excluded) {
			return false
		}
	}
	for _, domain := range p.domains {
		if matchesDomain(host, domain) {
			return true
		}
	}
	return false
}

func (p *Policy) AllowsURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" {
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

func normalizeRules(rules []string) []string {
	seen := make(map[string]bool)
	var normalized []string
	for _, rule := range rules {
		rule = normalizeHost(rule)
		if rule != "" && !seen[rule] {
			seen[rule] = true
			normalized = append(normalized, rule)
		}
	}
	return normalized
}

func normalizeHost(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	raw = strings.TrimPrefix(raw, "*.")
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		raw = parsed.Hostname()
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, ".")
	return raw
}

func matchesDomain(host, domain string) bool {
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
