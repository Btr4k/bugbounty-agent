package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	claudeAPIURL = "https://api.anthropic.com/v1/messages"
	apiVersion   = "2023-06-01"
)

// ClaudeProvider implements AIProvider for Anthropic Claude API
type ClaudeProvider struct {
	apiKey     string
	model      string
	maxTokens  int
	httpClient *http.Client
	initErr    error
}

type claudeRequest struct {
	Model       string    `json:"model"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature *float64  `json:"temperature,omitempty"`
	System      string    `json:"system,omitempty"`
	Messages    []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeResponse struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Role    string `json:"role"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Model        string `json:"model"`
	StopReason   string `json:"stop_reason"`
	StopSequence string `json:"stop_sequence"`
	Usage        struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

func NewClaudeProvider(apiKey, model string, maxTokens, timeoutSeconds int) *ClaudeProvider {
	// Matches the OpenAI-compatible provider: large JS-analysis batches can take
	// minutes to generate. A short timeout trips mid-body; default to 300s.
	if timeoutSeconds <= 0 {
		timeoutSeconds = 300
	}
	client, clientErr := newGuardedAIHTTPClient(claudeAPIURL, timeoutSeconds)
	return &ClaudeProvider{
		apiKey:     apiKey,
		model:      model,
		maxTokens:  maxTokens,
		httpClient: client,
		initErr:    clientErr,
	}
}

func (c *ClaudeProvider) ProviderName() string {
	return "claude"
}

// Complete sends a completion request to Claude API
func (c *ClaudeProvider) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if c == nil || c.initErr != nil || c.httpClient == nil {
		return "", errUnsafeAIEndpoint
	}
	reqBody := claudeRequest{
		Model:     c.model,
		MaxTokens: c.maxTokens,
		System:    systemPrompt,
		Messages: []message{
			{
				Role:    "user",
				Content: userPrompt,
			},
		},
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", claudeAPIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Anthropic-Version", apiVersion)

	resp, err := c.httpClient.Do(req)
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
		// Never reflect a remote error body: providers may echo prompt content or
		// credentials in diagnostic messages.
		return "", fmt.Errorf("API error (status %d)", resp.StatusCode)
	}

	var claudeResp claudeResponse
	if err := json.Unmarshal(body, &claudeResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(claudeResp.Content) == 0 {
		return "", fmt.Errorf("empty response from Claude")
	}
	if claudeResp.StopReason != "end_turn" {
		return "", fmt.Errorf("incomplete response from Claude (unexpected stop reason)")
	}

	var fullText string
	for _, content := range claudeResp.Content {
		if content.Type == "text" {
			fullText += content.Text
		}
	}
	if fullText == "" {
		return "", fmt.Errorf("empty text response from Claude")
	}

	return fullText, nil
}

// CompleteWithRetry implements retry logic for API calls
func (c *ClaudeProvider) CompleteWithRetry(ctx context.Context, systemPrompt, userPrompt string, maxRetries int) (string, error) {
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

		response, err := c.Complete(ctx, systemPrompt, userPrompt)
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

func isNonRetryableError(err error) bool {
	errStr := err.Error()
	return bytes.Contains([]byte(errStr), []byte("authentication")) ||
		bytes.Contains([]byte(errStr), []byte("invalid_request")) ||
		bytes.Contains([]byte(errStr), []byte("status 400")) ||
		bytes.Contains([]byte(errStr), []byte("status 401")) ||
		bytes.Contains([]byte(errStr), []byte("status 403")) ||
		bytes.Contains([]byte(errStr), []byte("status 404")) ||
		bytes.Contains([]byte(errStr), []byte("status 422"))
}

func isRateLimitError(err error) bool {
	errStr := err.Error()
	return bytes.Contains([]byte(errStr), []byte("rate_limit")) ||
		bytes.Contains([]byte(errStr), []byte("rate limit")) ||
		bytes.Contains([]byte(errStr), []byte("429"))
}
