package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression: ProjectDiscovery httpx prints its banner to STDERR. The detector
// must read stderr, not just stdout. Uses fake scripts so it needs no real httpx.
func TestIsProjectDiscoveryHttpxReadsStderr(t *testing.T) {
	dir := t.TempDir()

	// Marker on STDERR only (how real httpx -version behaves) -> must detect.
	pd := filepath.Join(dir, "httpx-pd")
	if err := os.WriteFile(pd, []byte("#!/bin/sh\necho 'projectdiscovery.io' 1>&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !isProjectDiscoveryHttpx(pd) {
		t.Error("expected true: projectdiscovery marker on stderr must be detected")
	}

	// Marker on STDOUT (also acceptable) -> must detect.
	pdOut := filepath.Join(dir, "httpx-pd-stdout")
	if err := os.WriteFile(pdOut, []byte("#!/bin/sh\necho 'projectdiscovery.io'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !isProjectDiscoveryHttpx(pdOut) {
		t.Error("expected true: projectdiscovery marker on stdout must be detected")
	}

	// No marker (e.g. the unrelated Python httpx) -> must be rejected.
	other := filepath.Join(dir, "httpx-other")
	if err := os.WriteFile(other, []byte("#!/bin/sh\necho 'HTTPie/httpx python client'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if isProjectDiscoveryHttpx(other) {
		t.Error("expected false: no projectdiscovery marker present")
	}
}
