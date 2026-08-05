package analyzer

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/scope"
)

var errUnsafeAIEndpoint = errors.New("AI endpoint failed safety validation")

// reviewedProviderBaseURL is a second, constructor-level trust boundary. Config
// validation pins hosted providers too, but exported constructors must remain
// safe when callers bypass config.Load/Validate.
func reviewedProviderBaseURL(provider, configured string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "openai":
		return "https://api.openai.com/v1", nil
	case "deepseek":
		return "https://api.deepseek.com/v1", nil
	case "openrouter":
		return "https://openrouter.ai/api/v1", nil
	case "custom":
		configured = strings.TrimRight(strings.TrimSpace(configured), "/")
		if configured == "" {
			return "", errUnsafeAIEndpoint
		}
		return configured, nil
	default:
		return "", errUnsafeAIEndpoint
	}
}

func newGuardedAIHTTPClient(baseURL string, timeoutSeconds int) (*http.Client, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300
	}
	if timeoutSeconds > 3600 {
		return nil, errUnsafeAIEndpoint
	}
	policy, err := scope.NewPublicOriginPolicy(baseURL, scope.PublicOriginOptions{})
	if err != nil {
		return nil, errUnsafeAIEndpoint
	}
	return policy.SafeHTTPClient(&http.Client{
		Timeout: time.Duration(timeoutSeconds) * time.Second,
	}), nil
}

// safeAIRequestFailure never wraps net/http's URL-bearing diagnostics. Custom
// endpoint paths and redirect locations are untrusted and may themselves
// contain secrets or forged log content.
func safeAIRequestFailure(ctx context.Context, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return contextErr
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return errors.New("AI provider request timed out")
	}
	return errors.New("AI provider request failed")
}
