package analyzer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestOpenAICompatibleProviderRequestsJSONObjectMode(t *testing.T) {
	tests := []struct {
		provider       string
		wantJSONFormat bool
	}{
		{provider: "deepseek", wantJSONFormat: true},
		{provider: "openai", wantJSONFormat: true},
		{provider: "openrouter", wantJSONFormat: true},
		{provider: "custom", wantJSONFormat: false},
	}

	for _, test := range tests {
		t.Run(test.provider, func(t *testing.T) {
			var request openAIRequest
			provider := NewOpenAIProvider("test-key", "test-model", 128, "https://custom-provider.example.com/v1", test.provider, 5)
			provider.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "" || !strings.HasSuffix(r.URL.Path, "/chat/completions") {
					t.Errorf("unexpected request path %q", r.URL.Path)
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Errorf("decode request: %v", err)
				}
				return jsonHTTPResponse(r, http.StatusOK, `{"choices":[{"message":{"role":"assistant","content":"{}"},"finish_reason":"stop"}]}`), nil
			})}
			if _, err := provider.Complete(context.Background(), securitySystemPrompt, "Return JSON"); err != nil {
				t.Fatal(err)
			}

			if test.wantJSONFormat {
				if request.ResponseFormat == nil || request.ResponseFormat.Type != "json_object" {
					t.Fatalf("%s request did not enable JSON-object mode: %#v", test.provider, request.ResponseFormat)
				}
			} else if request.ResponseFormat != nil {
				t.Fatalf("custom provider received an unsupported response_format: %#v", request.ResponseFormat)
			}
		})
	}
}

func TestAnalyzerProviderFactoryFailsClosedForUnknownProvider(t *testing.T) {
	log := logger.New(false)
	defer log.Close()

	provider := NewProvider(&config.Config{AI: config.AIConfig{
		Provider: "openai-typo",
		APIKey:   "key-that-must-not-go-to-anthropic",
		Model:    "model",
	}}, log)
	if provider.ProviderName() != "unavailable" {
		t.Fatalf("unknown provider was routed to %q", provider.ProviderName())
	}
	if _, err := provider.Complete(context.Background(), "system", "prompt"); err == nil {
		t.Fatal("unknown provider did not fail closed")
	}
}

func TestOpenAICompatibleProviderDoesNotReflectRemoteErrorBody(t *testing.T) {
	const remoteSecret = "remote-body-secret-must-not-leak"
	provider := NewOpenAIProvider("test-key", "test-model", 128, "https://custom-provider.example.com/v1", "custom", 5)
	provider.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(request, http.StatusUnauthorized, `{"error":{"message":"`+remoteSecret+`\nforged log"}}`), nil
	})}
	_, err := provider.Complete(context.Background(), securitySystemPrompt, "Return JSON")
	if err == nil {
		t.Fatal("expected provider error")
	}
	if strings.Contains(err.Error(), remoteSecret) || strings.Contains(err.Error(), "forged log") {
		t.Fatalf("remote error body was reflected: %q", err)
	}
	if !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("safe status diagnostic missing: %q", err)
	}
}

func TestOpenAICompatibleProviderRejectsOversizedResponse(t *testing.T) {
	provider := NewOpenAIProvider("test-key", "test-model", 128, "https://custom-provider.example.com/v1", "custom", 5)
	provider.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return jsonHTTPResponse(request, http.StatusOK, strings.Repeat("x", maxAIResponseBytes+1)), nil
	})}
	_, err := provider.Complete(context.Background(), securitySystemPrompt, "Return JSON")
	if err == nil || !strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("oversized provider response was not rejected: %v", err)
	}
}

func TestOpenAICompatibleProviderRequiresExplicitStopReason(t *testing.T) {
	for _, name := range []string{"openai", "deepseek", "openrouter", "custom"} {
		provider := NewOpenAIProvider("test-key", "test-model", 128, "https://custom-provider.example.com/v1", name, 5)
		provider.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return jsonHTTPResponse(request, http.StatusOK, `{"choices":[{"message":{"role":"assistant","content":"{}"}}]}`), nil
		})}
		if _, err := provider.Complete(context.Background(), securitySystemPrompt, "Return JSON"); err == nil {
			t.Fatalf("%s accepted a response without a finish reason", name)
		}
	}
}

func TestHostedProviderConstructorsPinReviewedEndpoints(t *testing.T) {
	tests := map[string]string{
		"openai":     "https://api.openai.com/v1/chat/completions",
		"deepseek":   "https://api.deepseek.com/v1/chat/completions",
		"openrouter": "https://openrouter.ai/api/v1/chat/completions",
	}
	for name, expected := range tests {
		t.Run(name, func(t *testing.T) {
			provider := NewOpenAIProvider("vendor-key", "model", 128, "https://attacker.example/steal", name, 5)
			var destination string
			provider.httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
				destination = request.URL.String()
				return jsonHTTPResponse(request, http.StatusOK, `{"choices":[{"message":{"content":"{}"},"finish_reason":"stop"}]}`), nil
			})}
			if _, err := provider.Complete(context.Background(), "system", "prompt"); err != nil {
				t.Fatal(err)
			}
			if destination != expected {
				t.Fatalf("%s constructor dispatched to %q, want %q", name, destination, expected)
			}
		})
	}
}

func TestAIProviderConstructorsInstallFailClosedEndpointGuards(t *testing.T) {
	unsafe := NewOpenAIProvider("key", "model", 128, "http://127.0.0.1:8080/v1", "custom", 5)
	if _, err := unsafe.Complete(context.Background(), "system", "prompt"); err == nil || !strings.Contains(err.Error(), "safety validation") {
		t.Fatalf("unsafe custom endpoint did not fail closed: %v", err)
	}
	unsafeTimeout := NewOpenAIProvider("key", "model", 128, "https://custom-provider.example.com/v1", "custom", 3601)
	if _, err := unsafeTimeout.Complete(context.Background(), "system", "prompt"); err == nil {
		t.Fatal("out-of-policy AI timeout did not fail closed")
	}

	custom := NewOpenAIProvider("key", "model", 128, "https://custom-provider.example.com/v1", "custom", 5)
	if custom.initErr != nil || custom.httpClient == nil || custom.httpClient.CheckRedirect == nil {
		t.Fatalf("custom provider omitted guarded client: init=%v client=%#v", custom.initErr, custom.httpClient)
	}
	redirect, _ := http.NewRequest(http.MethodPost, "https://attacker.example/steal?token=DO_NOT_REFLECT", nil)
	if err := custom.httpClient.CheckRedirect(redirect, nil); err == nil || strings.Contains(err.Error(), "DO_NOT_REFLECT") {
		t.Fatalf("redirect guard failed or reflected an unsafe URL: %v", err)
	}

	claude := NewClaudeProvider("key", "model", 128, 5)
	if claude.initErr != nil || claude.httpClient == nil || claude.httpClient.CheckRedirect == nil {
		t.Fatalf("Claude provider omitted guarded client: init=%v client=%#v", claude.initErr, claude.httpClient)
	}
}

func TestAIProviderDoesNotReflectTransportURLs(t *testing.T) {
	const secret = "DO_NOT_REFLECT_PATH_SECRET"
	provider := NewOpenAIProvider("key", "model", 128, "https://custom-provider.example.com/v1", "custom", 5)
	provider.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("synthetic redirect https://attacker.example/" + secret)
	})}
	_, err := provider.Complete(context.Background(), "system", "prompt")
	if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("unsafe transport diagnostic escaped: %v", err)
	}
}

func jsonHTTPResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

func TestClaudeRequiresEndTurnAndOmitsUnsupportedSamplingParameters(t *testing.T) {
	var request claudeRequest
	provider := NewClaudeProvider("test-key", "test-model", 128, 5)
	provider.httpClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"content":[{"type":"text","text":"{}"}]}`,
			)),
			Request: req,
		}, nil
	})}

	if _, err := provider.Complete(context.Background(), securitySystemPrompt, "Return JSON"); err == nil {
		t.Fatal("Claude response without end_turn must fail closed")
	}
	if request.Temperature != nil {
		t.Fatalf("Claude request sent an unsupported temperature override: %v", *request.Temperature)
	}
}
