package recon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
)

func TestRunAlwaysIncludesRootTarget(t *testing.T) {
	log := logger.New(false)
	defer log.Close()
	cfg := &config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com"}},
		Recon:  config.ReconConfig{Timeout: 5},
	}
	results, err := NewEngine(cfg, log).Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(results.Subdomains) != 1 || results.Subdomains[0] != "example.com" {
		t.Fatalf("root target missing from recon results: %v", results.Subdomains)
	}
	if !results.Complete {
		t.Fatalf("empty enabled-tool set should complete: %#v", results.FailedTools)
	}
}

func TestRunContinuesAfterOptionalSourceFailureAndPassiveTimeout(t *testing.T) {
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "katana-ran")
	writeExecutable(t, filepath.Join(binDir, "subfinder"), "#!/bin/sh\nsleep 2\nexit 1\n")
	writeExecutable(t, filepath.Join(binDir, "katana"), "#!/bin/sh\ntouch '"+marker+"'\n")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	log := logger.New(false)
	defer log.Close()
	cfg := &config.Config{
		Target: config.TargetConfig{Domains: []string{"example.com"}},
		Recon: config.ReconConfig{
			Timeout: 1,
			Tools: config.ReconToolsConfig{
				Subfinder: true,
				Katana:    true,
			},
		},
	}

	results, err := NewEngine(cfg, log).Run(context.Background())
	if err != nil {
		t.Fatalf("optional recon failure must not stop the pipeline: %v", err)
	}
	if results.Complete || len(results.FailedTools) != 1 || results.FailedTools[0] != "subfinder" {
		t.Fatalf("expected partial recon with subfinder failure: %#v", results)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("katana did not run after the passive recon timeout")
	}
}

func TestParseCertSpotterNames(t *testing.T) {
	body := []byte(`[
		{"dns_names":["*.seu.edu.sa","lms.seu.edu.sa"]},
		{"dns_names":["seu.edu.sa"," itsm.seu.edu.sa ",""]}
	]`)

	names, err := parseCertSpotterNames(body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := map[string]bool{
		"seu.edu.sa":      true, // wildcard prefix stripped
		"lms.seu.edu.sa":  true,
		"itsm.seu.edu.sa": true, // surrounding whitespace trimmed
	}
	if len(names) != 4 { // "*.seu.edu.sa" -> "seu.edu.sa" and the standalone "seu.edu.sa" both kept (dedup happens later)
		t.Fatalf("expected 4 names, got %d: %v", len(names), names)
	}
	for _, n := range names {
		if n == "" {
			t.Fatalf("empty name should be filtered out: %v", names)
		}
		if !want[n] {
			t.Fatalf("unexpected name %q in %v", n, names)
		}
	}
}

func TestParseCertSpotterNamesInvalidJSON(t *testing.T) {
	if _, err := parseCertSpotterNames([]byte("not json")); err == nil {
		t.Fatal("expected error on invalid JSON")
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
}
