package scope

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// isPublicSuffix uses the maintained Mozilla Public Suffix List bundled with
// x/net. This covers both ICANN registries and private hosted-service suffixes
// consistently across minimal containers and developer machines.
func isPublicSuffix(host string) bool {
	host = strings.ToLower(strings.Trim(host, "."))
	if host == "" {
		return false
	}
	suffix, _ := publicsuffix.PublicSuffix(host)
	return suffix == host
}

// hasRecognizedICANNTLD rejects reserved and local-only suffixes such as
// .local, .internal, .test, and .example while still allowing registrable
// hosts beneath private PSL entries (for example, tenant.appspot.com).
func hasRecognizedICANNTLD(host string) bool {
	host = strings.ToLower(strings.Trim(host, "."))
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	tld := labels[len(labels)-1]
	suffix, icann := publicsuffix.PublicSuffix(tld)
	return icann && suffix == tld
}
