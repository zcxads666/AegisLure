package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fixtureRoundTripper struct {
	requests  []*http.Request
	status    int
	responses map[string]string
}

func (f *fixtureRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	f.requests = append(f.requests, request.Clone(request.Context()))
	path := request.URL.Path
	body := f.responses[path]
	if body == "" {
		body = `{"error":"not found"}`
	}
	status := f.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func testProviderConfig(provider Provider) ProviderConfig {
	config := DefaultProviderConfig(provider)
	config.Enabled = true
	config.ClientID = "client-id"
	config.ClientSecret = "client-secret"
	config.RedirectURL = "https://bait.example.test/api/oauth/" + string(provider) + "/callback"
	config.AuthorizationURL = "http://oauth.test/authorize"
	config.TokenURL = "http://oauth.test/token"
	config.IdentityURL = "http://oauth.test/user"
	config.RevokeURL = "http://oauth.test/revoke"
	config.PolicyMode = "local_only"
	return config
}

func TestBrokerUsesOneTimeStatePKCEAndReturnsOnlySubjectHMAC(t *testing.T) {
	fixture := &fixtureRoundTripper{responses: map[string]string{
		"/token": `{"access_token":"access-secret","scope":""}`,
		"/user":  `{"id":123456789,"login":"should-not-be-returned"}`,
	}}
	config := testProviderConfig(GitHub)
	config.UseNonce = true
	config.RequireNonce = true
	config.RevokeURL = ""
	broker, err := New(Config{InstanceKey: "broker-test-key", Providers: map[Provider]ProviderConfig{GitHub: config}, Client: &http.Client{Transport: fixture}, AllowTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := broker.Begin(GitHub)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	state := query.Get("state")
	if len(state) < 40 || query.Get("client_secret") != "" || query.Get("redirect_uri") != config.RedirectURL || query.Get("response_type") != "code" {
		t.Fatalf("unsafe authorization URL: %s", authorization.URL)
	}
	if len(fixture.requests) != 0 {
		t.Fatal("beginning OAuth unexpectedly made an HTTP request")
	}

	nonce := query.Get("nonce")
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"nonce":"` + nonce + `"}`))
	fixture.responses["/token"] = `{"access_token":"access-secret","scope":"","id_token":"` + header + "." + payload + `.signature"}`
	identity, err := broker.Callback(GitHub, state, "authorization-code")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Provider != GitHub || identity.SubjectHMAC == "" || identity.SubjectHMAC == "123456789" || len(identity.Scopes) != 0 {
		t.Fatalf("identity leaked or was incomplete: %#v", identity)
	}
	if identity.CompletedAt.IsZero() {
		t.Fatal("identity completion time missing")
	}
	if len(fixture.requests) != 2 || fixture.requests[0].URL.Path != "/token" || fixture.requests[1].URL.Path != "/user" {
		t.Fatalf("unexpected broker requests: %d", len(fixture.requests))
	}
	tokenBody, _ := io.ReadAll(fixture.requests[0].Body)
	form, err := url.ParseQuery(string(tokenBody))
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("code") != "authorization-code" || form.Get("client_secret") != "client-secret" {
		t.Fatalf("token exchange form is incomplete: %s", tokenBody)
	}
	challenge := sha256.Sum256([]byte(form.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(challenge[:]) != query.Get("code_challenge") {
		t.Fatal("PKCE verifier did not match authorization challenge")
	}
	if auth := fixture.requests[1].Header.Get("Authorization"); auth != "Bearer access-secret" {
		t.Fatalf("identity request authorization = %q", auth)
	}
	if _, err := broker.Callback(GitHub, state, "authorization-code"); err == nil {
		t.Fatal("OAuth state was reusable")
	}
}

func TestBrokerRejectsExtraScopesAndUnsafeProviderConfiguration(t *testing.T) {
	fixture := &fixtureRoundTripper{responses: map[string]string{
		"/token":  `{"access_token":"access-secret","scope":"repo"}`,
		"/user":   `{"id":"user-1"}`,
		"/revoke": `{}`,
	}}
	config := testProviderConfig(GitHub)
	broker, err := New(Config{InstanceKey: "scope-test-key", Providers: map[Provider]ProviderConfig{GitHub: config}, Client: &http.Client{Transport: fixture}, AllowTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := broker.Begin(GitHub)
	if err != nil {
		t.Fatal(err)
	}
	state := mustParseURL(t, authorization.URL).Query().Get("state")
	if _, err := broker.Callback(GitHub, state, "code"); err == nil {
		t.Fatal("broker accepted an unapproved OAuth scope")
	}
	if len(fixture.requests) != 2 || fixture.requests[1].URL.Path != "/revoke" {
		t.Fatalf("broker did not revoke after scope violation: %d", len(fixture.requests))
	}

	unsafe := testProviderConfig(GitHub)
	unsafe.AuthorizationURL = "https://127.0.0.1/authorize"
	unsafe.TokenURL = "https://127.0.0.1/token"
	unsafe.IdentityURL = "https://127.0.0.1/user"
	unsafe.RevokeURL = ""
	if _, err := New(Config{InstanceKey: "unsafe-key", Providers: map[Provider]ProviderConfig{GitHub: unsafe}}); err == nil {
		t.Fatal("broker accepted a private provider endpoint")
	}

	discord := DefaultProviderConfig(Discord)
	discord.Enabled = true
	discord.ClientID = "id"
	discord.ClientSecret = "secret"
	discord.RedirectURL = "https://bait.example.test/callback"
	discord.Scopes = []string{"identify", "email"}
	if _, err := New(Config{InstanceKey: "discord-key", Providers: map[Provider]ProviderConfig{Discord: discord}}); err == nil {
		t.Fatal("broker accepted Discord email scope")
	}
}

func TestBrokerPolicyGuardKeepsDiscordAndLinuxDOLocalOnly(t *testing.T) {
	github := DefaultProviderConfig(GitHub)
	github.Enabled = true
	github.ClientID = "id"
	github.ClientSecret = "secret"
	github.RedirectURL = "https://bait.example.test/github"
	github.PolicyMode = "approved"
	github.PolicyApprovalRef = "review-123"
	github.RevokeURL = ""
	broker, err := New(Config{InstanceKey: "policy-key", Providers: map[Provider]ProviderConfig{
		GitHub:  github,
		Discord: ProviderConfig{PolicyMode: "local_only"},
		LinuxDO: ProviderConfig{PolicyMode: "pending_approval"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !broker.CanExport(GitHub) || broker.CanExport(Discord) || broker.CanExport(LinuxDO) {
		t.Fatal("identity policy guard was bypassed")
	}
	if broker.PolicyMode(Discord) != "local_only" || broker.PolicyMode(LinuxDO) != "pending_approval" {
		t.Fatal("provider policy mode was not preserved")
	}
}

func TestLoadFileKeepsFixedProviderEndpointsAndRejectsLooseSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth.json")
	data := `{"providers":{"github":{"enabled":true,"client_id":"client-id","client_secret":"client-secret","redirect_url":"https://bait.example.test/api/oauth/github/callback","policy_mode":"local_only"}}}`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	broker, err := LoadFile(path, "file-broker-key")
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := broker.Begin(GitHub)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authorization.URL)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.Path != "/login/oauth/authorize" || parsed.Query().Get("client_secret") != "" {
		t.Fatalf("file config changed the fixed authorization endpoint: %s", authorization.URL)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path, "file-broker-key"); err == nil {
		t.Fatal("broker accepted a group/world-readable secret file")
	}
	if err := os.WriteFile(path, []byte(`{"providers":{"github":{"enabled":true,"client_id":"id","client_secret":"secret","redirect_url":"https://bait.example.test/callback","authorization_url":"https://evil.example"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(path, "file-broker-key"); err == nil {
		t.Fatal("broker accepted a user-defined provider endpoint")
	}
}

func mustParseURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
