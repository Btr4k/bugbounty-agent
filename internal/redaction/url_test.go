package redaction

import (
	"strings"
	"testing"
)

func TestSanitizeURLBlanksValuesAndRemovesCredentialsAndFragment(t *testing.T) {
	t.Parallel()

	input := "https://alice:p%40ss@example.com/path?sig=first&sig=second&flag&empty=#private-fragment"
	got := SanitizeURL(input)
	want := "https://example.com/path?sig=&sig=&flag&empty="
	if got != want {
		t.Fatalf("SanitizeURL() = %q, want %q", got, want)
	}
	for _, secret := range []string{"alice", "p%40ss", "first", "second", "private-fragment"} {
		if strings.Contains(got, secret) {
			t.Fatalf("URL-borne secret %q leaked in %q", secret, got)
		}
	}
}

func TestSanitizeURLSupportsRelativeAndSchemeRelativeURLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "relative request target",
			input: "/download?X-Amz-Credential=opaque&X-Amz-Signature=secret#fragment",
			want:  "/download?X-Amz-Credential=&X-Amz-Signature=",
		},
		{
			name:  "scheme relative user info",
			input: "//user:password@example.com/a?token=opaque",
			want:  "//example.com/a?token=",
		},
		{
			name:  "semicolon query separator",
			input: "https://example.com/a?first=one;second=two&third=three",
			want:  "https://example.com/a?first=;second=&third=",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := SanitizeURL(test.input); got != test.want {
				t.Fatalf("SanitizeURL(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestSanitizeURLFailsClosedForMalformedInput(t *testing.T) {
	t.Parallel()

	input := "https://example.com/%zz?token=opaque"
	if got := SanitizeURL(input); got != invalidURLMarker {
		t.Fatalf("malformed URL was not replaced: got %q", got)
	}
	if strings.Contains(SanitizeURL(input), "opaque") {
		t.Fatal("malformed URL leaked its opaque query value")
	}
}

func TestSanitizeURLsInTextPreservesPunctuationAndRepeatedKeys(t *testing.T) {
	t.Parallel()

	input := "See (https://user:pass@example.com/a?sig=one&sig=two&next=/home#private), then continue."
	got := SanitizeURLsInText(input)
	want := "See (https://example.com/a?sig=&sig=&next=), then continue."
	if got != want {
		t.Fatalf("SanitizeURLsInText() = %q, want %q", got, want)
	}
	for _, secret := range []string{"user", "pass", "one", "two", "/home", "private"} {
		if strings.Contains(got, secret) {
			t.Fatalf("URL-borne secret %q leaked in %q", secret, got)
		}
	}
}

func TestSanitizeURLsInTextSanitizesHTTPOriginFormRequestTargets(t *testing.T) {
	t.Parallel()

	input := strings.Join([]string{
		"request follows:",
		"GET /path?sig=first&sig=second&plain=value HTTP/1.1",
		"Host: example.com",
		"Authorization: Bearer still-needs-Mask",
	}, "\n")
	got := SanitizeURLsInText(input)
	want := strings.Join([]string{
		"request follows:",
		"GET /path?sig=&sig=&plain= HTTP/1.1",
		"Host: example.com",
		"Authorization: Bearer still-needs-Mask",
	}, "\n")
	if got != want {
		t.Fatalf("SanitizeURLsInText() =\n%q\nwant\n%q", got, want)
	}
	for _, secret := range []string{"first", "second", "value"} {
		if strings.Contains(got, secret) {
			t.Fatalf("request-target secret %q leaked in %q", secret, got)
		}
	}
}

func TestSanitizeURLsInTextSanitizesRelativeURLTokens(t *testing.T) {
	t.Parallel()

	input := "candidate at /callback?opaque=hidden&next=/admin#private, /docs#draft-only, then /plain stays"
	got := SanitizeURLsInText(input)
	want := "candidate at /callback?opaque=&next=, /docs, then /plain stays"
	if got != want {
		t.Fatalf("relative URL sanitization = %q, want %q", got, want)
	}
	if strings.Contains(got, "hidden") || strings.Contains(got, "/admin") || strings.Contains(got, "private") || strings.Contains(got, "draft-only") {
		t.Fatalf("relative URL value leaked: %q", got)
	}
}

func TestSanitizeURLsInTextSanitizesBareAndQueryOnlyRelativeURLs(t *testing.T) {
	t.Parallel()

	input := "target=callback?token=secret#private curl ?code=opaque&state=hidden plain=/no-query"
	got := SanitizeURLsInText(input)
	want := "target=callback?token= curl ?code=&state= plain=/no-query"
	if got != want {
		t.Fatalf("bare relative URL sanitization = %q, want %q", got, want)
	}
	for _, secret := range []string{"secret", "private", "opaque", "hidden"} {
		if strings.Contains(got, secret) {
			t.Fatalf("bare relative URL secret %q leaked in %q", secret, got)
		}
	}
}

func TestSanitizeURLsInTextHandlesQuotedCurlURLs(t *testing.T) {
	t.Parallel()

	input := strings.Join([]string{
		`curl --url 'callback?code=opaque&state=hidden#fragment'`,
		`curl "https://user:password@example.com/v1?token=secret#private"`,
		`curl '//alice:hunter2@example.com/private'`,
	}, "\n")
	got := SanitizeURLsInText(input)
	want := strings.Join([]string{
		`curl --url 'callback?code=&state='`,
		`curl "https://example.com/v1?token="`,
		`curl '//example.com/private'`,
	}, "\n")
	if got != want {
		t.Fatalf("quoted curl sanitization =\n%q\nwant\n%q", got, want)
	}
	for _, secret := range []string{"opaque", "hidden", "fragment", "user", "password", "secret", "private\"", "alice", "hunter2"} {
		if strings.Contains(got, secret) {
			t.Fatalf("quoted curl secret %q leaked in %q", secret, got)
		}
	}
}

func TestSanitizeURLsInTextHandlesJSONEscapedURLs(t *testing.T) {
	t.Parallel()

	input := `{"absolute":"https:\/\/user:password@example.com\/v1\u003ftoken\u003dopaque\u0023private","relative":"\/callback?code=secret\u0026state=hidden\u0023fragment"}`
	got := SanitizeURLsInText(input)
	want := `{"absolute":"https://example.com/v1?token=","relative":"/callback?code=&state="}`
	if got != want {
		t.Fatalf("JSON-escaped URL sanitization = %q, want %q", got, want)
	}
	for _, secret := range []string{"user", "password", "opaque", "private", "secret", "hidden", "fragment"} {
		if strings.Contains(got, secret) {
			t.Fatalf("JSON-escaped URL secret %q leaked in %q", secret, got)
		}
	}
}

func TestSanitizeURLsInTextHandlesFullyAndMultiplyEscapedJSONURL(t *testing.T) {
	t.Parallel()

	input := `{"url":"https\u003A\\\/\\\/alice\u003Apassword\u0040example.com\\\/v1\u003Fsig\u003Dopaque\u0023private"}`
	got := SanitizeURLsInText(input)
	want := `{"url":"https://example.com/v1?sig="}`
	if got != want {
		t.Fatalf("multiply escaped JSON URL sanitization = %q, want %q", got, want)
	}
	for _, secret := range []string{"alice", "password", "opaque", "private"} {
		if strings.Contains(got, secret) {
			t.Fatalf("multiply escaped JSON URL secret %q leaked in %q", secret, got)
		}
	}
}

func TestSanitizeURLRedactsLikelyOpaqueQueryKeys(t *testing.T) {
	t.Parallel()

	awsKey := "AKIAIOSFODNN7EXAMPLE"
	hexToken := "0123456789abcdef0123456789abcdef"
	uuidToken := "123e4567-e89b-12d3-a456-426614174000"
	mixedToken := "AbCdEfGhIjKlMnOpQrStUvWxYz012345"
	lowerToken := "abcdefghijklmnopqrstuvwxyzabcdefgh"
	delimitedToken := "opaque-token-value-abcdefghijklmnopqrstuvwxyz0123456789"
	githubToken := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	input := "https://example.com/path?debug&include_archived_resources_for_account&X-Amz-Signature&" + awsKey + "&" +
		hexToken + "&" + uuidToken + "&" + mixedToken + "&" + lowerToken + "&" + delimitedToken + "&" + githubToken + "=value&normal=value"
	got := SanitizeURL(input)
	want := "https://example.com/path?debug&include_archived_resources_for_account&X-Amz-Signature&" + redactedQueryToken + "&" +
		redactedQueryToken + "&" + redactedQueryToken + "&" + redactedQueryToken + "&" +
		redactedQueryToken + "&" + redactedQueryToken + "&" + redactedQueryToken + "=&normal="
	if got != want {
		t.Fatalf("opaque query-key sanitization = %q, want %q", got, want)
	}
	for _, secret := range []string{awsKey, hexToken, uuidToken, mixedToken, lowerToken, delimitedToken, githubToken, "value"} {
		if strings.Contains(got, secret) {
			t.Fatalf("opaque query key/value %q leaked in %q", secret, got)
		}
	}
}

func TestSanitizeURLRedactsMalformedEncodedQueryKey(t *testing.T) {
	t.Parallel()

	input := "https://example.com/path?bad%zz=opaque&%FF=binary&normal=value"
	got := SanitizeURL(input)
	want := "https://example.com/path?" + redactedQueryToken + "=&" + redactedQueryToken + "=&normal="
	if got != want {
		t.Fatalf("malformed query-key sanitization = %q, want %q", got, want)
	}
	if strings.Contains(got, "bad%zz") || strings.Contains(got, "%FF") || strings.Contains(got, "opaque") || strings.Contains(got, "binary") || strings.Contains(got, "value") {
		t.Fatalf("malformed query component leaked in %q", got)
	}
}

func TestSanitizeURLsInTextFailsClosedForEscapedMalformedURL(t *testing.T) {
	t.Parallel()

	input := `evidence={"url":"https:\/\/user:password@example.com\/%zz?token=opaque#private"}`
	got := SanitizeURLsInText(input)
	want := `evidence={"url":"[REDACTED invalid_url]"}`
	if got != want {
		t.Fatalf("malformed escaped URL sanitization = %q, want %q", got, want)
	}
	for _, secret := range []string{"user", "password", "opaque", "private"} {
		if strings.Contains(got, secret) {
			t.Fatalf("malformed escaped URL secret %q leaked in %q", secret, got)
		}
	}
}

func TestSanitizeURLsInTextIsIdempotentAcrossEscapedInputs(t *testing.T) {
	t.Parallel()

	input := `{"url":"https:\/\/user:password@example.com\/path?sig=opaque#fragment","next":"callback?state=secret"}`
	once := SanitizeURLsInText(input)
	twice := SanitizeURLsInText(once)
	if once != twice {
		t.Fatalf("URL text sanitization is not idempotent:\nfirst:  %q\nsecond: %q", once, twice)
	}
}

func TestSanitizeURLsInTextCanComposeWithCredentialMasking(t *testing.T) {
	t.Parallel()

	input := "POST /submit?opaque=hidden HTTP/2\nAuthorization: Bearer bearer-value"
	got := MaskMultiline(SanitizeURLsInText(input))
	if strings.Contains(got, "hidden") || strings.Contains(got, "bearer-value") {
		t.Fatalf("composed sanitizers leaked a secret: %q", got)
	}
	want := "POST /submit?opaque= HTTP/2\nAuthorization: Bearer [REDACTED type=bearer_token]"
	if got != want {
		t.Fatalf("composed sanitizers = %q, want %q", got, want)
	}
}
