package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxAIResponseBytes = 4 << 20

// AIProvider is the interface all AI providers must implement
type AIProvider interface {
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
	CompleteWithRetry(ctx context.Context, systemPrompt, userPrompt string, maxRetries int) (string, error)
	ProviderName() string
}

// unavailableAIProvider is a fail-closed implementation used when a caller
// bypasses config.Load/Validate and asks the exported analyzer constructors for
// an unknown provider. Falling back to a real vendor here could send another
// vendor's API key and prompt data to the wrong endpoint.
type unavailableAIProvider struct{}

func (unavailableAIProvider) Complete(context.Context, string, string) (string, error) {
	return "", fmt.Errorf("AI provider is unavailable because its configuration was not validated")
}

func (unavailableAIProvider) CompleteWithRetry(context.Context, string, string, int) (string, error) {
	return "", fmt.Errorf("AI provider is unavailable because its configuration was not validated")
}

func (unavailableAIProvider) ProviderName() string { return "unavailable" }

// ═══════════════════════════════════════════════════════════
// OpenAI-Compatible Provider (covers DeepSeek, OpenAI, OpenRouter, Groq, etc.)
// ═══════════════════════════════════════════════════════════

type OpenAIProvider struct {
	apiKey     string
	model      string
	maxTokens  int
	baseURL    string
	provider   string
	httpClient *http.Client
	initErr    error
}

type openAIRequest struct {
	Model          string                `json:"model"`
	Messages       []openAIMessage       `json:"messages"`
	MaxTokens      int                   `json:"max_tokens"`
	Temperature    float64               `json:"temperature"`
	ResponseFormat *openAIResponseFormat `json:"response_format,omitempty"`
}

type openAIResponseFormat struct {
	Type string `json:"type"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

func NewOpenAIProvider(apiKey, model string, maxTokens int, baseURL, provider string, timeoutSeconds int) *OpenAIProvider {
	// Large prompts (JS batches up to ~60KB) on slower providers like DeepSeek
	// can take well over 2 minutes to generate + stream a full response. A short
	// timeout trips mid-body; default to 300s when unset.
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	resolvedBaseURL, endpointErr := reviewedProviderBaseURL(provider, baseURL)
	client, clientErr := newGuardedAIHTTPClient(resolvedBaseURL, timeoutSeconds)
	if endpointErr != nil {
		clientErr = endpointErr
	}
	return &OpenAIProvider{
		apiKey:     apiKey,
		model:      model,
		maxTokens:  maxTokens,
		baseURL:    resolvedBaseURL,
		provider:   provider,
		httpClient: client,
		initErr:    clientErr,
	}
}

func (p *OpenAIProvider) ProviderName() string {
	return p.provider
}

func (p *OpenAIProvider) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if p == nil || p.initErr != nil || p.httpClient == nil {
		return "", errUnsafeAIEndpoint
	}
	messages := []openAIMessage{
		{Role: "user", Content: userPrompt},
	}
	if systemPrompt != "" {
		messages = append([]openAIMessage{{Role: "system", Content: systemPrompt}}, messages...)
	}

	reqBody := openAIRequest{
		Model:       p.model,
		Messages:    messages,
		MaxTokens:   p.maxTokens,
		Temperature: 0.1,
	}
	// Known hosted providers support the OpenAI JSON-object response contract.
	// Keep it disabled for arbitrary custom endpoints so existing compatible-but-
	// minimal servers are not broken by an unsupported optional request field.
	if supportsJSONResponseFormat(p.provider) {
		reqBody.ResponseFormat = &openAIResponseFormat{Type: "json_object"}
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	endpoint := strings.TrimRight(p.baseURL, "/") + "/chat/completions"
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.apiKey)

	// OpenRouter requires extra headers
	if p.provider == "openrouter" {
		req.Header.Set("HTTP-Referer", "https://github.com/hawkeye-bugbounty")
		req.Header.Set("X-Title", "HawkEye Bug Bounty Agent")
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", safeAIRequestFailure(ctx, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAIResponseBytes+1))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if len(body) > maxAIResponseBytes {
		return "", fmt.Errorf("AI response exceeded %d bytes", maxAIResponseBytes)
	}

	if resp.StatusCode != http.StatusOK {
		// The response body is remote-controlled and may echo prompt content or
		// credentials. Status is sufficient for retry classification and support.
		return "", fmt.Errorf("API error (status %d)", resp.StatusCode)
	}

	var result openAIResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("empty response from %s", p.provider)
	}
	finishReason := result.Choices[0].FinishReason
	if finishReason != "stop" {
		return "", fmt.Errorf("incomplete response from %s (unexpected finish reason)", p.provider)
	}

	return result.Choices[0].Message.Content, nil
}

func supportsJSONResponseFormat(provider string) bool {
	switch provider {
	case "openai", "deepseek", "openrouter":
		return true
	default:
		return false
	}
}

func (p *OpenAIProvider) CompleteWithRetry(ctx context.Context, systemPrompt, userPrompt string, maxRetries int) (string, error) {
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			backoff := time.Duration(i*i) * time.Second
			if lastErr != nil && isRateLimitError(lastErr) {
				backoff = 60 * time.Second
			}
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(backoff):
			}
		}

		response, err := p.Complete(ctx, systemPrompt, userPrompt)
		if err == nil {
			return response, nil
		}

		lastErr = err
		if isNonRetryableError(err) {
			return "", err
		}
	}

	return "", fmt.Errorf("max retries exceeded: %w", lastErr)
}
