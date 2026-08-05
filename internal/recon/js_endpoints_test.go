package recon

import (
	"strings"
	"testing"
)

func TestMineJSEndpoints(t *testing.T) {
	files := []JSFile{{
		URL: "https://shop.example.com/app.js",
		Content: `
			const api = "https://api.example.com/v1/orders?status=open";
			fetch("/api/user?id=" + uid);
			axios.get('/account/settings');
			const css = "/assets/main.css";
			const one = "/x";
			const img = "https://cdn.example.com/logo.png";
			const tmpl = "/api/item?ref=${x}";
		`,
	}}
	got := mineJSEndpoints(files)
	joined := strings.Join(got, "\n")

	mustHave := []string{
		"https://api.example.com/v1/orders?status=open", // absolute + query
		"https://shop.example.com/api/user?id=",         // relative param path resolved to JS host
		"https://shop.example.com/account/settings",     // 2-segment relative path
		"https://shop.example.com/api/item?ref=",        // template literal terminates cleanly at ${
	}
	for _, m := range mustHave {
		if !strings.Contains(joined, m) {
			t.Errorf("expected mined endpoint %q\n--- got ---\n%s", m, joined)
		}
	}
	mustNotHave := []string{"main.css", "logo.png", `"/x"`, "cdn.example.com/logo"}
	for _, m := range mustNotHave {
		if strings.Contains(joined, m) {
			t.Errorf("did not expect noise %q in results:\n%s", m, joined)
		}
	}
}

func TestLooksLikeEndpoint(t *testing.T) {
	keep := []string{"/api/user?id=5", "/account/settings", "/api/v1/x", "/orders?ref=9", "/graphql"}
	drop := []string{"", "notaurl", "/x", "/main.css", "/logo.png", "/app.js", "/a.map"}
	for _, p := range keep {
		if !looksLikeEndpoint(p) {
			t.Errorf("expected keep: %q", p)
		}
	}
	for _, p := range drop {
		if looksLikeEndpoint(p) {
			t.Errorf("expected drop: %q", p)
		}
	}
}
