package redaction

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

func TestMaskRecognizedHighEntropyTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		typeName SecretType
		secret   string
		input    string
		context  []string
	}{
		{
			name:     "jwt",
			typeName: SecretJWT,
			secret:   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureABC123",
			input:    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureABC123",
			context:  []string{"Authorization: Bearer ", "type=jwt"},
		},
		{
			name:     "aws access key",
			typeName: SecretAWSAccessKey,
			secret:   "AKIAIOSFODNN7EXAMPLE",
			input:    "key=AKIAIOSFODNN7EXAMPLE region=eu-west-1",
			context:  []string{"key=", " region=eu-west-1", "type=aws_access_key"},
		},
		{
			name:     "aws secret key",
			typeName: SecretAWSSecretKey,
			secret:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			input:    `AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"; owner=team`,
			context:  []string{`AWS_SECRET_ACCESS_KEY="`, `"; owner=team`, "type=aws_secret_key"},
		},
		{
			name:     "aws session token",
			typeName: SecretAWSSessionToken,
			secret:   "AQoDYXdzEJr-example-session-token-1234567890",
			input:    "aws_session_token=AQoDYXdzEJr-example-session-token-1234567890 next=value",
			context:  []string{"aws_session_token=", " next=value", "type=aws_session_token"},
		},
		{
			name:     "github classic token",
			typeName: SecretGitHubToken,
			secret:   "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			input:    "github=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij owner=octo",
			context:  []string{"github=", " owner=octo", "type=github_token"},
		},
		{
			name:     "github fine grained token",
			typeName: SecretGitHubToken,
			secret:   "github_pat_11AA0_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH",
			input:    "token github_pat_11AA0_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH done",
			context:  []string{"token ", " done", "type=github_token"},
		},
		{
			name:     "stripe secret key",
			typeName: SecretStripeKey,
			secret:   "sk_live_" + "1234567890ABCDEFGHIJKLMNOP",
			input:    "stripe=sk_live_" + "1234567890ABCDEFGHIJKLMNOP mode=live",
			context:  []string{"stripe=", " mode=live", "type=stripe_key"},
		},
		{
			name:     "stripe webhook secret",
			typeName: SecretStripeKey,
			secret:   "whsec_1234567890ABCDEFGHIJKLMNOP",
			input:    "webhook whsec_1234567890ABCDEFGHIJKLMNOP active",
			context:  []string{"webhook ", " active", "type=stripe_key"},
		},
		{
			name:     "google oauth token",
			typeName: SecretGoogleOAuthToken,
			secret:   "ya29.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
			input:    "google=ya29.ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 account=user",
			context:  []string{"google=", " account=user", "type=google_oauth_token"},
		},
		{
			name:     "slack token",
			typeName: SecretSlackToken,
			secret:   "xoxb-" + "123456789012-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			input:    "slack=xoxb-" + "123456789012-ABCDEFGHIJKLMNOPQRSTUVWXYZ channel=alerts",
			context:  []string{"slack=", " channel=alerts", "type=slack_token"},
		},
		{
			name:     "twilio key",
			typeName: SecretTwilioKey,
			secret:   "SK" + "0123456789abcdef0123456789abcdef",
			input:    "twilio=SK" + "0123456789abcdef0123456789abcdef region=us1",
			context:  []string{"twilio=", " region=us1", "type=twilio_key"},
		},
		{
			name:     "sendgrid key",
			typeName: SecretSendGridKey,
			secret:   "SG." + "ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq",
			input:    "sendgrid=SG." + "ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq owner=mail",
			context:  []string{"sendgrid=", " owner=mail", "type=sendgrid_key"},
		},
		{
			name:     "mailgun key",
			typeName: SecretMailgunKey,
			secret:   "key-" + "0123456789abcdef0123456789abcdef",
			input:    "mailgun=key-" + "0123456789abcdef0123456789abcdef domain=mg.example",
			context:  []string{"mailgun=", " domain=mg.example", "type=mailgun_key"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := MaskWithMetadata(test.input)
			if strings.Contains(result.Text, test.secret) {
				t.Fatalf("secret leaked in masked text: %q", result.Text)
			}
			for _, wanted := range test.context {
				if !strings.Contains(result.Text, wanted) {
					t.Errorf("masked text %q does not preserve %q", result.Text, wanted)
				}
			}
			if len(result.Matches) != 1 {
				t.Fatalf("got %d matches, want 1: %#v", len(result.Matches), result.Matches)
			}
			metadata := result.Matches[0]
			if metadata.Type != test.typeName {
				t.Errorf("type = %q, want %q", metadata.Type, test.typeName)
			}
			if strings.Contains(fmt.Sprintf("%#v", result.Matches), test.secret) {
				t.Fatal("secret leaked through metadata")
			}
		})
	}
}

func TestMaskDetectorAlignedContextualCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		secret   string
		typeName SecretType
		before   string
		after    string
	}{
		{
			name:     "basic authorization",
			input:    "Authorization: Basic dXNlcjpwYXNz request-id=7",
			secret:   "dXNlcjpwYXNz",
			typeName: SecretAuthorization,
			before:   "Authorization: Basic ",
			after:    " request-id=7",
		},
		{
			name:     "token authorization in JSON",
			input:    `{"Authorization":"Token opaque-value","status":"ok"}`,
			secret:   "opaque-value",
			typeName: SecretAuthorization,
			before:   `{"Authorization":"Token `,
			after:    `","status":"ok"}`,
		},
		{
			name:     "generic api key",
			input:    `api_key="opaque-api-value"; service=internal`,
			secret:   "opaque-api-value",
			typeName: SecretGeneric,
			before:   `api_key="`,
			after:    `"; service=internal`,
		},
		{
			name:     "generic access token",
			input:    "access_token=tiny&scope=read",
			secret:   "tiny",
			typeName: SecretGeneric,
			before:   "access_token=",
			after:    "&scope=read",
		},
		{
			name:     "URL credential",
			input:    "fetch https://alice:s3cret@example.com/private safely",
			secret:   "s3cret",
			typeName: SecretURLCredential,
			before:   "fetch https://alice:",
			after:    "@example.com/private safely",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := MaskWithMetadata(test.input)
			if strings.Contains(result.Text, test.secret) {
				t.Fatalf("secret %q leaked in %q", test.secret, result.Text)
			}
			if !strings.Contains(result.Text, test.before) || !strings.Contains(result.Text, test.after) {
				t.Fatalf("unrelated evidence was not preserved: %q", result.Text)
			}
			if len(result.Matches) != 1 || result.Matches[0].Type != test.typeName {
				t.Fatalf("unexpected match metadata: %#v", result.Matches)
			}
		})
	}
}

func TestMaskPreservesCookieStructureWhileRemovingValues(t *testing.T) {
	t.Parallel()

	secrets := []string{
		"opaque-session-cookie-123",
		"opaque-refresh-cookie-456",
		"opaque-request-cookie-789",
		"dark",
	}
	input := strings.Join([]string{
		"HTTP/1.1 200 OK",
		"Set-Cookie: session=opaque-session-cookie-123; Path=/; Secure; HttpOnly; SameSite=Lax",
		"Set-Cookie: refresh=\"opaque-refresh-cookie-456\"; Path=/token; Secure",
		"Cookie: sid=opaque-request-cookie-789; theme=dark",
		"Content-Type: application/json",
	}, "\r\n")

	for _, maskFn := range []struct {
		name string
		fn   func(string) string
	}{
		{name: "single-line", fn: Mask},
		{name: "multiline", fn: MaskMultiline},
	} {
		t.Run(maskFn.name, func(t *testing.T) {
			masked := maskFn.fn(input)
			for _, secret := range secrets {
				if strings.Contains(masked, secret) {
					t.Fatalf("cookie value %q leaked in %q", secret, masked)
				}
			}
			for _, context := range []string{
				"Set-Cookie: session=", "Path=/", "Secure", "HttpOnly", "SameSite=Lax",
				"Set-Cookie: refresh=\"", "Path=/token", "Cookie: sid=", "theme=", "Content-Type: application/json",
			} {
				if !strings.Contains(masked, context) {
					t.Errorf("cookie context %q was not preserved in %q", context, masked)
				}
			}
			if twice := maskFn.fn(masked); twice != masked {
				t.Fatalf("cookie masking is not idempotent:\nfirst:  %q\nsecond: %q", masked, twice)
			}
		})
	}
}

func TestMaskContextualRefreshIDAndSessionTokens(t *testing.T) {
	t.Parallel()

	secrets := []string{"opaque-refresh-value", "opaque-id-value", "opaque-session-value"}
	input := `{"refresh_token":"opaque-refresh-value","id_token":"opaque-id-value","session_id":"opaque-session-value","status":"ok"}`
	masked := Mask(input)
	for _, secret := range secrets {
		if strings.Contains(masked, secret) {
			t.Fatalf("contextual token %q leaked in %q", secret, masked)
		}
	}
	for _, context := range []string{`"refresh_token":"`, `"id_token":"`, `"session_id":"`, `"status":"ok"`} {
		if !strings.Contains(masked, context) {
			t.Errorf("non-secret structure %q was not preserved in %q", context, masked)
		}
	}
}

func TestMaskPrivateKeyReplacesEntirePEM(t *testing.T) {
	t.Parallel()

	privateKey := strings.Join([]string{
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIEowIBAAKCAQEA0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"abcdefghijklmnopqrstuvwxyz0123456789+/==",
		"-----END RSA PRIVATE KEY-----",
	}, "\n")
	input := "before\n" + privateKey + "\nafter"
	result := MaskMultilineWithMetadata(input)

	if strings.Contains(result.Text, "BEGIN RSA PRIVATE KEY") ||
		strings.Contains(result.Text, "MIIEowIB") ||
		strings.Contains(result.Text, "END RSA PRIVATE KEY") {
		t.Fatalf("private-key block leaked in %q", result.Text)
	}
	if result.Text[:7] != "before\n" || !strings.HasSuffix(result.Text, "\nafter") {
		t.Fatalf("surrounding multiline evidence was not preserved: %q", result.Text)
	}
	if len(result.Matches) != 1 || result.Matches[0].Type != SecretPrivateKey {
		t.Fatalf("unexpected private-key metadata: %#v", result.Matches)
	}
}

func TestMaskKnownSecretCoversOpaqueDetectorEvidence(t *testing.T) {
	t.Parallel()

	secret := "opaque-value-with-no-recognizable-prefix"
	result := MaskKnownSecret(secret, SecretGeneric)
	if strings.Contains(result.Text, secret) || result.Text != "[REDACTED type=generic_secret]" {
		t.Fatalf("known opaque value was not safely masked: %#v", result)
	}
	if len(result.Matches) != 1 || result.Matches[0] != (Match{Type: SecretGeneric}) {
		t.Fatalf("unexpected known-secret metadata: %#v", result.Matches)
	}

	emptyType := MaskKnownSecret("short", "")
	if emptyType.Text != "[REDACTED type=generic_secret]" {
		t.Fatalf("empty type did not fall back safely: %#v", emptyType)
	}
	if got := MaskKnownSecret("", SecretGeneric); got.Text != "" || len(got.Matches) != 0 {
		t.Fatalf("empty value should stay empty: %#v", got)
	}
}

func TestMaskMultilinePreservesOnlyLineFeedControls(t *testing.T) {
	t.Parallel()

	input := "first\r\nsecond\rthird\tvalue\x00\u202E"
	result := MaskMultiline(input)
	if result != "first\nsecond\nthird value" {
		t.Fatalf("unexpected multiline sanitization: %q", result)
	}
	for _, r := range result {
		if r != '\n' && (unicode.IsControl(r) || unicode.In(r, unicode.Cf)) {
			t.Fatalf("unsafe control or format rune %U remains in %q", r, result)
		}
	}
}

func TestMaskPasswordsAndDatabaseCredentialsWithoutGuessableMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		secrets  []string
		contains []string
		count    int
	}{
		{
			name:     "json and short password",
			input:    `{"password":"abc","user":"alice"}`,
			secrets:  []string{"abc"},
			contains: []string{`{"password":"`, `","user":"alice"}`},
			count:    1,
		},
		{
			name:     "quoted password with spaces",
			input:    "password='correct horse battery staple'; role=reader",
			secrets:  []string{"correct horse battery staple"},
			contains: []string{"password='", "'; role=reader"},
			count:    1,
		},
		{
			name:     "unquoted query password",
			input:    "POST /login?user=bob&password=hunter2&next=/home",
			secrets:  []string{"hunter2"},
			contains: []string{"POST /login?user=bob&password=", "&next=/home"},
			count:    1,
		},
		{
			name:     "database URI preserves non-secret evidence",
			input:    "DATABASE_URL=postgresql://reporter:p%40ssword@db.example:5432/app?sslmode=require",
			secrets:  []string{"p%40ssword"},
			contains: []string{"DATABASE_URL=postgresql://reporter:", "@db.example:5432/app?sslmode=require"},
			count:    1,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			result := MaskWithMetadata(test.input)
			for _, secret := range test.secrets {
				if strings.Contains(result.Text, secret) {
					t.Fatalf("secret %q leaked in %q", secret, result.Text)
				}
			}
			for _, wanted := range test.contains {
				if !strings.Contains(result.Text, wanted) {
					t.Errorf("masked text %q does not preserve %q", result.Text, wanted)
				}
			}
			if len(result.Matches) != test.count {
				t.Fatalf("got %d matches, want %d: %#v", len(result.Matches), test.count, result.Matches)
			}
		})
	}
}

func TestMaskOpaqueBearerIncludingShortValue(t *testing.T) {
	t.Parallel()

	for _, secret := range []string{"x", "opaque-token-value-123456789"} {
		result := MaskWithMetadata("Authorization: Bearer " + secret + " request-id=42")
		if strings.Contains(result.Text, secret) {
			t.Fatalf("bearer secret %q leaked in %q", secret, result.Text)
		}
		if !strings.Contains(result.Text, "Authorization: Bearer [REDACTED type=bearer_token] request-id=42") {
			t.Fatalf("surrounding bearer evidence was not preserved: %q", result.Text)
		}
		if len(result.Matches) != 1 || result.Matches[0] != (Match{Type: SecretBearerToken}) {
			t.Fatalf("unsafe bearer metadata: %#v", result.Matches)
		}
	}
}

func TestMaskMultipleValuesRetainsOnlyTypes(t *testing.T) {
	t.Parallel()

	awsKey := "AKIAIOSFODNN7EXAMPLE"
	githubToken := "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	input := "first=" + awsKey + " second=" + githubToken + " repeated=" + awsKey
	result := MaskWithMetadata(input)

	if strings.Contains(result.Text, awsKey) || strings.Contains(result.Text, githubToken) {
		t.Fatalf("a secret leaked in %q", result.Text)
	}
	if !strings.Contains(result.Text, "first=") || !strings.Contains(result.Text, " second=") || !strings.Contains(result.Text, " repeated=") {
		t.Fatalf("unrelated evidence was removed: %q", result.Text)
	}
	if len(result.Matches) != 3 {
		t.Fatalf("got %d matches, want 3: %#v", len(result.Matches), result.Matches)
	}
	if result.Matches[0].Type != SecretAWSAccessKey || result.Matches[1].Type != SecretGitHubToken ||
		result.Matches[2].Type != SecretAWSAccessKey {
		t.Errorf("unexpected type-only metadata: %#v", result.Matches)
	}
}

func TestMaskRemovesControlsAndFormatCharacters(t *testing.T) {
	t.Parallel()

	secret := "sk_live_" + "1234567890ABCDEFGHIJKLMNOP"
	input := "line1\nline2\x00\x1b[31m\u202E token=" + secret + "\tend"
	result := Mask(input)

	if strings.Contains(result, secret) {
		t.Fatalf("secret leaked in %q", result)
	}
	for _, r := range result {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			t.Fatalf("control or format rune %U remains in %q", r, result)
		}
	}
	if !strings.Contains(result, "line1 line2[31m token=") || !strings.HasSuffix(result, " end") {
		t.Fatalf("sanitized context was not preserved: %q", result)
	}
}

func TestMaskIsIdempotent(t *testing.T) {
	t.Parallel()

	input := `password="short" Authorization: Bearer opaque123`
	once := Mask(input)
	twice := Mask(once)
	if once != twice {
		t.Fatalf("Mask is not idempotent:\nfirst:  %q\nsecond: %q", once, twice)
	}
}

func TestMaskLeavesBenignLookalikesUntouched(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"the password policy requires twelve characters",
		"stripe publishable key pk_live_1234567890ABCDEFGHIJKLMNOP",
		"short stripe lookalike sk_live_short",
		"short AWS lookalike AKIA1234",
		"postgresql://db.example/app?sslmode=require",
		"github issue prefix ghp_not-a-token",
	}
	for _, input := range inputs {
		if got := Mask(input); got != input {
			t.Errorf("benign input changed:\n got: %q\nwant: %q", got, input)
		}
	}
}

func TestSpecificTokenWinsOverGenericContext(t *testing.T) {
	t.Parallel()

	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signatureABC123"
	result := MaskWithMetadata(`password="` + jwt + `" Authorization: Bearer ` + jwt)
	if strings.Contains(result.Text, jwt) {
		t.Fatalf("JWT leaked in %q", result.Text)
	}
	if len(result.Matches) != 2 {
		t.Fatalf("got %d matches, want 2: %#v", len(result.Matches), result.Matches)
	}
	for _, metadata := range result.Matches {
		if metadata.Type != SecretJWT {
			t.Errorf("specific JWT type lost to generic context: %#v", result.Matches)
		}
	}
}

func TestResultMetadataCannotContainOriginalValues(t *testing.T) {
	t.Parallel()

	password := "a-very-long-but-low-entropy-password"
	result := MaskWithMetadata(`password="` + password + `"`)
	serialized := fmt.Sprintf("%#v", result.Matches)
	if strings.Contains(serialized, password) {
		t.Fatalf("metadata leaked the original password: %s", serialized)
	}
	if result.Matches[0] != (Match{Type: SecretPassword}) {
		t.Fatalf("metadata should contain only the detector type: %s", serialized)
	}
}
