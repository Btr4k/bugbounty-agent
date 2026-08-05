package analyzer

import (
	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
)

// NewProvider builds the configured AI provider (claude/deepseek/openai/...).
// Exported so other engines — e.g. the Phase-1 hunter — can reuse the exact
// same provider wiring, retries, and timeouts as the validation analyzer.
func NewProvider(cfg *config.Config, log *logger.Logger) AIProvider {
	return createAIProvider(cfg, log)
}
