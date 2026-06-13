package main

import "testing"

func TestValidateDomain(t *testing.T) {
	for _, domain := range []string{"example.com", "api.example.com", "xn--bcher-kva.example"} {
		if err := validateDomain(domain); err != nil {
			t.Errorf("validateDomain(%q) unexpected error: %v", domain, err)
		}
	}
	for _, domain := range []string{"example..com", "-api.example.com", "api-.example.com", "localhost", "example.com/path"} {
		if err := validateDomain(domain); err == nil {
			t.Errorf("validateDomain(%q) expected error", domain)
		}
	}
}
