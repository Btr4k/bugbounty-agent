package recon

import (
	"context"
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
}
