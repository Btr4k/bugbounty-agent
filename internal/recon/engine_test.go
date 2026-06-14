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

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
}
