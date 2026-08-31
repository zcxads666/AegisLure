// Package oauth contains the narrow, opt-in identity broker boundary used by
// the New API profile. It deliberately keeps transactions and provider
// tokens in memory only. A deployment may place the same package behind a
// separate process/network boundary; the public application never accepts a
// provider URL from a request.
package oauth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Provider string

const (
	GitHub  Provider = "github"
	Discord Provider = "discord"
	LinuxDO Provider = "linuxdo"
)

func ParseProvider(value string) (Provider, bool) {
	switch Provider(strings.ToLower(strings.TrimSpace(value))) {
	case GitHub:
		return GitHub, true
	case Discord:
		return Discord, true
	case LinuxDO:
		return LinuxDO, true
	default:
		return "", false
	}
}

type ProviderConfig struct {
	Enabled           bool
	ClientID          string
	ClientSecret      string
	RedirectURL       string
	AuthorizationURL  string
	TokenURL          string
	IdentityURL       string
	RevokeURL         string
	Scopes            []string
	UsePKCE           bool
	UseNonce          bool
	RequireNonce      bool
	UseBasicAuth      bool
	PolicyMode        string
	PolicyApprovalRef string
}

type Config struct {
	InstanceKey        string
	Providers          map[Provider]ProviderConfig
	Client             *http.Client
	AllowTestEndpoints bool
}

// FileConfig is the deliberately small on-disk configuration accepted by the
// optional standalone broker. Provider URLs are not configurable here: the
// loader always starts from DefaultProviderConfig so a secret file cannot turn
// the broker into an arbitrary HTTP proxy.
type FileConfig struct {
	Providers map[string]FileProviderConfig `json:"providers"`
}

type FileProviderConfig struct {
	Enabled           bool     `json:"enabled"`
	ClientID          string   `json:"client_id"`
	ClientSecret      string   `json:"client_secret"`
	RedirectURL       string   `json:"redirect_url"`
	Scopes            []string `json:"scopes,omitempty"`
	PolicyMode        string   `json:"policy_mode,omitempty"`
	PolicyApprovalRef string   `json:"policy_approval_ref,omitempty"`
}

type Authorization struct {
	Provider  Provider
	URL       string
	ExpiresAt time.Time
}

// Identity intentionally contains no provider user ID, handle, email, or
// token. SubjectHMAC is the only stable cross-request identity value.
type Identity struct {
	Provider    Provider
	SubjectHMAC string
	Scopes      []string
	CompletedAt time.Time
}

type transaction struct {
	Provider     Provider
	RedirectURL  string
	Verifier     string
	Nonce        string
	RequireNonce bool
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

type Broker struct {
	mu           sync.Mutex
	instanceKey  string
	providers    map[Provider]ProviderConfig
	transactions map[string]transaction
	client       *http.Client
	now          func() time.Time
}

func DefaultProviderConfig(provider Provider) ProviderConfig {
	switch provider {
	case GitHub:
		return ProviderConfig{
			AuthorizationURL: "https://github.com/login/oauth/authorize",
			TokenURL:         "https://github.com/login/oauth/access_token",
			IdentityURL:      "https://api.github.com/user",
			UsePKCE:          true,
			PolicyMode:       "off",
		}
	case Discord:
		return ProviderConfig{
			AuthorizationURL: "https://discord.com/oauth2/authorize",
			TokenURL:         "https://discord.com/api/oauth2/token",
			IdentityURL:      "https://discord.com/api/users/@me",
			RevokeURL:        "https://discord.com/api/oauth2/token/revoke",
			Scopes:           []string{"identify"},
			PolicyMode:       "local_only",
			UseBasicAuth:     true,
		}
	case LinuxDO:
		return ProviderConfig{
			AuthorizationURL: "https://connect.linux.do/oauth2/authorize",
			TokenURL:         "https://connect.linux.do/oauth2/token",
			IdentityURL:      "https://connect.linux.do/api/user",
			Scopes:           []string{"openid"},
			UsePKCE:          true,
			UseNonce:         true,
			PolicyMode:       "pending_approval",
			UseBasicAuth:     true,
		}
	default:
		return ProviderConfig{}
	}
}

func New(cfg Config) (*Broker, error) {
	if strings.TrimSpace(cfg.InstanceKey) == "" {
		return nil, errors.New("oauth broker instance key is required")
	}
	providers := make(map[Provider]ProviderConfig, len(cfg.Providers))
	for provider, providerCfg := range cfg.Providers {
		if providerCfg.RedirectURL != "" {
			providerCfg.RedirectURL = strings.TrimSpace(providerCfg.RedirectURL)
		}
		providerCfg.Scopes = normalizedScopes(providerCfg.Scopes)
		if len(providerCfg.Scopes) == 0 {
			providerCfg.Scopes = normalizedScopes(DefaultProviderConfig(provider).Scopes)
		}
		if !providerCfg.Enabled {
			providers[provider] = providerCfg
			continue
		}
		if err := validateProvider(provider, providerCfg, cfg.AllowTestEndpoints); err != nil {
			return nil, err
		}
		providers[provider] = providerCfg
	}
	client := cfg.Client
	if client == nil {
		client = safeHTTPClient()
	} else {
		clone := *client
		clone.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
			return errors.New("oauth redirects are disabled")
		}
		if clone.Timeout == 0 {
			clone.Timeout = 8 * time.Second
		}
		client = &clone
	}
	return &Broker{instanceKey: cfg.InstanceKey, providers: providers, transactions: make(map[string]transaction), client: client, now: func() time.Time { return time.Now().UTC() }}, nil
}

// LoadFile loads the optional broker credentials from a local, mode-restricted
// JSON file. Only client credentials, exact callback URLs, scopes and policy
// metadata are accepted. Endpoint URLs remain the provider defaults and the
// file is never copied into a backup archive by the standalone CLI.
func LoadFile(path, instanceKey string) (*Broker, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("oauth config path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("oauth config must be a regular file readable only by its owner")
	}
	if info.Size() <= 0 || info.Size() > 64*1024 {
		return nil, errors.New("oauth config exceeds the 64 KiB limit")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		for index := range data {
			data[index] = 0
		}
	}()
	var fileConfig FileConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fileConfig); err != nil {
		return nil, fmt.Errorf("decode oauth config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return nil, errors.New("oauth config contains trailing JSON")
	} else if err != io.EOF {
		return nil, fmt.Errorf("decode oauth config tail: %w", err)
	}
	if len(fileConfig.Providers) > 3 {
		return nil, errors.New("oauth config contains too many providers")
	}
	providers := make(map[Provider]ProviderConfig, len(fileConfig.Providers))
	for name, fileProvider := range fileConfig.Providers {
		provider, ok := ParseProvider(name)
		if !ok {
			return nil, fmt.Errorf("unsupported oauth provider %q", name)
		}
		providerConfig := DefaultProviderConfig(provider)
		providerConfig.Enabled = fileProvider.Enabled
		providerConfig.ClientID = strings.TrimSpace(fileProvider.ClientID)
		providerConfig.ClientSecret = fileProvider.ClientSecret
		providerConfig.RedirectURL = strings.TrimSpace(fileProvider.RedirectURL)
		providerConfig.PolicyMode = strings.TrimSpace(fileProvider.PolicyMode)
		providerConfig.PolicyApprovalRef = strings.TrimSpace(fileProvider.PolicyApprovalRef)
		if len(fileProvider.Scopes) > 0 {
			providerConfig.Scopes = append([]string(nil), fileProvider.Scopes...)
		}
		for label, value := range map[string]string{"client_id": providerConfig.ClientID, "client_secret": providerConfig.ClientSecret, "redirect_url": providerConfig.RedirectURL, "policy_mode": providerConfig.PolicyMode, "policy_approval_ref": providerConfig.PolicyApprovalRef} {
			if len(value) > 4096 || strings.ContainsAny(value, "\r\n") {
				return nil, fmt.Errorf("oauth provider %s %s is invalid", provider, label)
			}
		}
		providers[provider] = providerConfig
	}
	return New(Config{InstanceKey: instanceKey, Providers: providers})
}

func (b *Broker) Begin(provider Provider) (Authorization, error) {
	providerCfg, ok := b.providers[provider]
	if !ok || !providerCfg.Enabled {
		return Authorization{}, errors.New("oauth provider is disabled")
	}
	now := b.now().UTC()
	state, err := randomString(32)
	if err != nil {
		return Authorization{}, errors.New("oauth transaction unavailable")
	}
	verifier := ""
	if providerCfg.UsePKCE {
		verifier, err = randomString(32)
		if err != nil {
			return Authorization{}, errors.New("oauth transaction unavailable")
		}
	}
	nonce := ""
	if providerCfg.UseNonce {
		nonce, err = randomString(24)
		if err != nil {
			return Authorization{}, errors.New("oauth transaction unavailable")
		}
	}
	stateHash := keyedHash(b.instanceKey, state)
	tx := transaction{Provider: provider, RedirectURL: providerCfg.RedirectURL, Verifier: verifier, Nonce: nonce, RequireNonce: providerCfg.RequireNonce, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	b.mu.Lock()
	for key, existing := range b.transactions {
		if !existing.ExpiresAt.After(now) {
			delete(b.transactions, key)
		}
	}
	if len(b.transactions) >= 2048 {
		return Authorization{}, errors.New("oauth transaction capacity reached")
	}
	b.transactions[stateHash] = tx
	b.mu.Unlock()

	authorizationURL, err := url.Parse(providerCfg.AuthorizationURL)
	if err != nil {
		b.deleteTransaction(stateHash)
		return Authorization{}, errors.New("oauth provider configuration invalid")
	}
	query := authorizationURL.Query()
	query.Set("client_id", providerCfg.ClientID)
	query.Set("redirect_uri", providerCfg.RedirectURL)
	query.Set("response_type", "code")
	query.Set("state", state)
	if len(providerCfg.Scopes) > 0 {
		query.Set("scope", strings.Join(providerCfg.Scopes, " "))
	}
	if verifier != "" {
		challenge := sha256.Sum256([]byte(verifier))
		query.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
		query.Set("code_challenge_method", "S256")
	}
	if nonce != "" {
		query.Set("nonce", nonce)
	}
	authorizationURL.RawQuery = query.Encode()
	return Authorization{Provider: provider, URL: authorizationURL.String(), ExpiresAt: tx.ExpiresAt}, nil
}

func (b *Broker) Callback(provider Provider, state, code string) (identity Identity, err error) {
	if len(state) < 32 || len(state) > 256 || len(code) == 0 || len(code) > 4096 || strings.ContainsAny(state+code, "\r\n") {
		return Identity{}, errors.New("invalid oauth callback")
	}
	stateHash := keyedHash(b.instanceKey, state)
	b.mu.Lock()
	tx, ok := b.transactions[stateHash]
	if ok {
		delete(b.transactions, stateHash)
	}
	b.mu.Unlock()
	if !ok || tx.Provider != provider || !tx.ExpiresAt.After(b.now().UTC()) {
		return Identity{}, errors.New("invalid or expired oauth transaction")
	}
	providerCfg, ok := b.providers[provider]
	if !ok || !providerCfg.Enabled {
		return Identity{}, errors.New("oauth provider is disabled")
	}
	defer func() {
		// These assignments make the intended lifetime explicit. The broker
		// never puts the values in a returned struct, error, or log record.
		code = ""
	}()
	token, err := b.exchangeCode(providerCfg, tx, code)
	if err != nil {
		return Identity{}, err
	}
	accessToken := token.AccessToken
	defer func() {
		accessToken = ""
		token.AccessToken = ""
		token.RefreshToken = ""
		token.IDToken = ""
	}()
	if token.IDToken != "" && tx.Nonce != "" {
		if err := verifyNonce(token.IDToken, tx.Nonce); err != nil {
			b.revokeToken(providerCfg, accessToken)
			return Identity{}, err
		}
	} else if tx.RequireNonce {
		b.revokeToken(providerCfg, accessToken)
		return Identity{}, errors.New("oauth nonce was not verified")
	}
	grantedScopes := normalizedScopes(parseScopeString(token.Scope))
	if len(grantedScopes) == 0 {
		grantedScopes = append([]string(nil), providerCfg.Scopes...)
	}
	if !scopesAllowed(grantedScopes, providerCfg.Scopes) {
		b.revokeToken(providerCfg, accessToken)
		return Identity{}, errors.New("oauth provider granted an unapproved scope")
	}
	subject, err := b.fetchSubject(providerCfg, accessToken)
	if err != nil {
		b.revokeToken(providerCfg, accessToken)
		return Identity{}, err
	}
	subjectHMAC := keyedHash(b.instanceKey, string(provider)+"\x00"+subject)
	subject = ""
	return Identity{Provider: provider, SubjectHMAC: subjectHMAC, Scopes: grantedScopes, CompletedAt: b.now().UTC()}, nil
}

func (b *Broker) Revoke(provider Provider, accessToken string) error {
	providerCfg, ok := b.providers[provider]
	if !ok || !providerCfg.Enabled || providerCfg.RevokeURL == "" || len(accessToken) == 0 || len(accessToken) > 4096 {
		return errors.New("oauth revoke is unavailable")
	}
	defer func() { accessToken = "" }()
	return b.revokeToken(providerCfg, accessToken)
}

func (b *Broker) CanExport(provider Provider) bool {
	providerCfg, ok := b.providers[provider]
	return ok && provider == GitHub && providerCfg.PolicyMode == "approved" && strings.TrimSpace(providerCfg.PolicyApprovalRef) != ""
}

func (b *Broker) PolicyMode(provider Provider) string {
	if providerCfg, ok := b.providers[provider]; ok && providerCfg.PolicyMode != "" {
		return providerCfg.PolicyMode
	}
	return "local_only"
}

func (b *Broker) exchangeCode(providerCfg ProviderConfig, tx transaction, code string) (oauthToken, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", tx.RedirectURL)
	if tx.Verifier != "" {
		form.Set("code_verifier", tx.Verifier)
	}
	if !providerCfg.UseBasicAuth {
		form.Set("client_id", providerCfg.ClientID)
		form.Set("client_secret", providerCfg.ClientSecret)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, providerCfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauthToken{}, errors.New("oauth exchange failed")
	}
	if providerCfg.UseBasicAuth {
		request.SetBasicAuth(providerCfg.ClientID, providerCfg.ClientSecret)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := b.client.Do(request)
	if err != nil {
		return oauthToken{}, errors.New("oauth exchange failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if err != nil || len(body) > 64*1024 || response.StatusCode < 200 || response.StatusCode >= 300 {
		return oauthToken{}, errors.New("oauth exchange failed")
	}
	token, err := parseTokenResponse(body)
	for i := range body {
		body[i] = 0
	}
	if err != nil || token.AccessToken == "" || len(token.AccessToken) > 4096 {
		return oauthToken{}, errors.New("oauth exchange failed")
	}
	return token, nil
}

func (b *Broker) fetchSubject(providerCfg ProviderConfig, accessToken string) (string, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, providerCfg.IdentityURL, nil)
	if err != nil {
		return "", errors.New("oauth identity lookup failed")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err := b.client.Do(request)
	if err != nil {
		return "", errors.New("oauth identity lookup failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 128*1024+1))
	if err != nil || len(body) > 128*1024 || response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", errors.New("oauth identity lookup failed")
	}
	defer func() {
		for i := range body {
			body[i] = 0
		}
	}()
	var object map[string]json.RawMessage
	if json.Unmarshal(body, &object) != nil {
		return "", errors.New("oauth identity lookup failed")
	}
	for _, field := range []string{"id", "sub"} {
		if raw, ok := object[field]; ok {
			subject, ok := stableSubject(raw)
			if ok {
				return subject, nil
			}
		}
	}
	return "", errors.New("oauth identity lookup failed")
}

type oauthToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

func parseTokenResponse(body []byte) (oauthToken, error) {
	var token oauthToken
	if json.Unmarshal(body, &token) == nil && token.AccessToken != "" {
		return token, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return oauthToken{}, errors.New("invalid oauth token response")
	}
	token.AccessToken = values.Get("access_token")
	token.RefreshToken = values.Get("refresh_token")
	token.IDToken = values.Get("id_token")
	token.Scope = values.Get("scope")
	if token.AccessToken == "" {
		return oauthToken{}, errors.New("invalid oauth token response")
	}
	return token, nil
}

func stableSubject(raw json.RawMessage) (string, bool) {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 || len(value) > 256 {
		return "", false
	}
	if value[0] == '"' {
		var text string
		if json.Unmarshal(value, &text) != nil {
			return "", false
		}
		text = strings.TrimSpace(text)
		if text == "" || len(text) > 128 || strings.ContainsAny(text, "\r\n") {
			return "", false
		}
		return text, true
	}
	for _, r := range string(value) {
		if (r < '0' || r > '9') && r != '-' {
			return "", false
		}
	}
	return string(value), len(value) <= 128
}

func verifyNonce(idToken, nonce string) error {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return errors.New("oauth nonce was not verified")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return errors.New("oauth nonce was not verified")
	}
	defer func() {
		for i := range payload {
			payload[i] = 0
		}
	}()
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if json.Unmarshal(payload, &claims) != nil || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return errors.New("oauth nonce was not verified")
	}
	return nil
}

func (b *Broker) revokeToken(providerCfg ProviderConfig, accessToken string) error {
	if providerCfg.RevokeURL == "" || accessToken == "" {
		return nil
	}
	form := url.Values{"token": {accessToken}, "token_type_hint": {"access_token"}}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, providerCfg.RevokeURL, strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("oauth revoke failed")
	}
	if providerCfg.UseBasicAuth {
		request.SetBasicAuth(providerCfg.ClientID, providerCfg.ClientSecret)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := b.client.Do(request)
	if err != nil {
		return errors.New("oauth revoke failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 8*1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("oauth revoke failed")
	}
	return nil
}

func validateProvider(provider Provider, providerCfg ProviderConfig, allowTestEndpoints bool) error {
	if provider != GitHub && provider != Discord && provider != LinuxDO {
		return fmt.Errorf("unsupported oauth provider %q", provider)
	}
	if providerCfg.ClientID == "" || providerCfg.ClientSecret == "" || providerCfg.RedirectURL == "" {
		return fmt.Errorf("oauth provider %s credentials and redirect are required", provider)
	}
	if err := validateRedirectURL(providerCfg.RedirectURL); err != nil {
		return fmt.Errorf("oauth provider %s redirect: %w", provider, err)
	}
	defaults := DefaultProviderConfig(provider)
	for name, endpoint := range map[string]string{"authorization": providerCfg.AuthorizationURL, "token": providerCfg.TokenURL, "identity": providerCfg.IdentityURL, "revoke": providerCfg.RevokeURL} {
		if endpoint == "" && name == "revoke" {
			continue
		}
		if !allowTestEndpoints && endpoint != map[string]string{"authorization": defaults.AuthorizationURL, "token": defaults.TokenURL, "identity": defaults.IdentityURL, "revoke": defaults.RevokeURL}[name] {
			return fmt.Errorf("oauth provider %s %s endpoint is not an approved fixed endpoint", provider, name)
		}
		if err := validateEndpoint(endpoint, allowTestEndpoints); err != nil {
			return fmt.Errorf("oauth provider %s %s endpoint: %w", provider, name, err)
		}
	}
	allowedScopes := normalizedScopes(defaults.Scopes)
	if !scopesAllowed(providerCfg.Scopes, allowedScopes) {
		return fmt.Errorf("oauth provider %s requests a non-minimal scope", provider)
	}
	return nil
}

func validateRedirectURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(value, "\r\n") {
		return errors.New("redirect must be an exact HTTPS URL without query or fragment")
	}
	return nil
}

func validateEndpoint(value string, allowTestEndpoints bool) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(value, "\r\n") {
		return errors.New("endpoint URL is invalid")
	}
	if allowTestEndpoints {
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return errors.New("test endpoint must use HTTP or HTTPS")
		}
		return nil
	}
	if parsed.Scheme != "https" || isPrivateHost(parsed.Hostname()) {
		return errors.New("endpoint must use HTTPS and a public host")
	}
	return nil
}

func isPrivateHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast())
}

func normalizedScopes(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func parseScopeString(value string) []string {
	return normalizedScopes(strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' }))
}

func scopesAllowed(granted, allowed []string) bool {
	allowedSet := make(map[string]bool, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = true
	}
	for _, scope := range granted {
		if !allowedSet[scope] {
			return false
		}
	}
	return true
}

func randomString(size int) (string, error) {
	if size <= 0 || size > 128 {
		return "", errors.New("invalid random size")
	}
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func keyedHash(key, value string) string {
	digest := hmac.New(sha256.New, []byte(key))
	_, _ = digest.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func (b *Broker) deleteTransaction(stateHash string) {
	b.mu.Lock()
	delete(b.transactions, stateHash)
	b.mu.Unlock()
}

func safeHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           safeDialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("oauth redirects are disabled")
		},
	}
}

func safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" || isPrivateHost(host) {
		return nil, errors.New("oauth destination is not allowed")
	}
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("oauth destination lookup failed")
	}
	for _, address := range addresses {
		if isPrivateHost(address.IP.String()) {
			return nil, errors.New("oauth destination is not allowed")
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var lastErr error
	for _, address := range addresses {
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("oauth destination connection failed")
	}
	return nil, lastErr
}
