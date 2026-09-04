package app

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
)

func sub2APIProfileForTest(a *App, cfg *config.Config) profiles.Profile {
	if cfg.ProfilePorts == nil {
		cfg.ProfilePorts = make(map[string]int)
	}
	cfg.ProfilePorts[model.ProductSub2API] = 8081
	if cfg.Scenario == nil {
		cfg.Scenario = make(map[string]string)
	}
	cfg.Scenario[model.ProductSub2API] = "fresh"
	profile := profiles.Build(cfg)[model.ProductSub2API]
	a.profiles[model.ProductSub2API] = profile
	return profile
}

func decodeSub2APIJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatalf("decode Sub2API JSON: %v: %s", err, body)
	}
	return value
}

func TestSub2APICompatibilitySharesStateAndRecordsSafeTelemetry(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	profile := sub2APIProfileForTest(a, cfg)
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}

	resp, body := doRawJSON(t, client, http.MethodGet, "/health", nil, nil)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != `{"status":"ok"}` {
		t.Fatalf("health contract = %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `<div id="app"></div>`) || !strings.Contains(string(body), `src="/assets/`) || !strings.Contains(string(body), `href="/logo.svg"`) {
		t.Fatalf("official home shell contract = %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/login", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `<div id="app"></div>`) || !strings.Contains(string(body), `src="/assets/`) || !strings.Contains(string(body), `Sub2API - AI API Gateway`) {
		t.Fatalf("official login shell contract = %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/v1/settings/public", nil, nil)
	settingsEnvelope := decodeSub2APIJSON(t, body)
	settings, ok := settingsEnvelope["data"].(map[string]any)
	if resp.StatusCode != http.StatusOK || !ok || settings["site_name"] != "Sub2API" || settings["version"] != "0.2.0" || settings["google_oauth_enabled"] != false {
		t.Fatalf("public settings contract = %d %#v", resp.StatusCode, settingsEnvelope)
	}

	password := "CorrectHorse123!"
	resp, body = doRawJSON(t, client, http.MethodPost, "/api/v1/auth/register", map[string]any{"email": "analyst@example.com", "password": password}, nil)
	registration := decodeSub2APIJSON(t, body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("registration = %d %#v", resp.StatusCode, registration)
	}
	registrationData, ok := registration["data"].(map[string]any)
	if !ok || registrationData["access_token"] == "" {
		t.Fatalf("registration bundle = %#v", registration)
	}
	accessToken := registrationData["access_token"].(string)
	resp, _ = doRawJSON(t, client, http.MethodPost, "/api/v1/auth/login", map[string]any{"email": "analyst@example.com", "password": password}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d", resp.StatusCode)
	}
	// The returned synthetic access token is fingerprint-indexed, so a client
	// can use the official bearer shape without depending on a public cookie.
	accessClient := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	resp, _ = doRawJSON(t, accessClient, http.MethodGet, "/api/v1/auth/me", nil, map[string]string{"Authorization": "Bearer " + accessToken})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer-backed auth/me = %d", resp.StatusCode)
	}

	resp, body = doRawJSON(t, client, http.MethodPost, "/api/v1/keys", map[string]any{"name": "integration-key"}, nil)
	keyEnvelope := decodeSub2APIJSON(t, body)
	keyData, ok := keyEnvelope["data"].(map[string]any)
	if resp.StatusCode != http.StatusOK || !ok {
		t.Fatalf("key creation = %d %#v", resp.StatusCode, keyEnvelope)
	}
	rawKey, ok := keyData["key"].(string)
	if !ok || !strings.HasPrefix(rawKey, "sk-sub2api-") {
		t.Fatalf("generated key = %#v", keyData["key"])
	}

	if resp, _ := doRawJSON(t, client, http.MethodGet, "/api/v1/models", nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("panel model list = %d", resp.StatusCode)
	}
	resp, body = doRawJSON(t, client, http.MethodPost, "/v1/messages/count_tokens", map[string]any{"model": "claude-3-5-sonnet", "messages": []any{map[string]any{"role": "user", "content": "hello"}}}, map[string]string{"x-api-key": rawKey})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"total_tokens"`) {
		t.Fatalf("count tokens = %d %s", resp.StatusCode, body)
	}
	if resp, _ := doRawJSON(t, client, http.MethodGet, "/v1/sub2api/billing", nil, map[string]string{"x-goog-api-key": rawKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("billing = %d", resp.StatusCode)
	}
	if resp, _ := doRawJSON(t, client, http.MethodPost, "/v1/alpha/search", map[string]any{"query": "models"}, map[string]string{"Authorization": "Bearer " + rawKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("alpha search = %d", resp.StatusCode)
	}

	request := map[string]any{"model": "gpt-4o-mini", "messages": []any{map[string]any{"role": "user", "content": "hello"}}, "stream": false}
	if resp, _ := doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", request, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing gateway key status = %d", resp.StatusCode)
	}
	resp, body = doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", request, map[string]string{"Authorization": "Bearer " + rawKey})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"chat.completion"`) {
		t.Fatalf("chat completion = %d %s", resp.StatusCode, body)
	}
	streamRequest := map[string]any{"model": "gpt-4o-mini", "messages": []any{map[string]any{"role": "user", "content": "stream"}}, "stream": true}
	resp, body = doRawJSON(t, client, http.MethodPost, "/chat/completions", streamRequest, map[string]string{"Authorization": "Bearer " + rawKey})
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") || !strings.Contains(string(body), "[DONE]") {
		t.Fatalf("chat streaming = %d %#v %s", resp.StatusCode, resp.Header, body)
	}
	if resp, _ := doRawJSON(t, client, http.MethodPost, "/v1/embeddings", map[string]any{"model": "gpt-4o-mini", "input": "hello"}, map[string]string{"x-api-key": rawKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("embedding gateway = %d", resp.StatusCode)
	}
	otherClient := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	if resp, _ := doRawJSON(t, otherClient, http.MethodPost, "/v1/chat/completions", request, map[string]string{"Authorization": "Bearer " + rawKey, "User-Agent": "sub2api-sdk/1.0"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("cross-client gateway call = %d", resp.StatusCode)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/v1/usage", nil, nil)
	usageEnvelope := decodeSub2APIJSON(t, body)
	usageData, ok := usageEnvelope["data"].(map[string]any)
	total, totalOK := usageData["total"].(float64)
	if resp.StatusCode != http.StatusOK || !ok || !totalOK || total < 1 {
		t.Fatalf("account-scoped usage = %d %#v", resp.StatusCode, usageEnvelope)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/v1/usage/dashboard/stats", nil, nil)
	dashboardEnvelope := decodeSub2APIJSON(t, body)
	dashboard, ok := dashboardEnvelope["data"].(map[string]any)
	if resp.StatusCode != http.StatusOK || !ok {
		t.Fatalf("dashboard stats = %d %#v", resp.StatusCode, dashboardEnvelope)
	}
	for _, field := range []string{"total_api_keys", "active_api_keys", "total_input_tokens", "total_output_tokens", "total_actual_cost", "today_requests", "today_tokens", "average_duration_ms", "rpm", "tpm", "by_platform"} {
		if _, exists := dashboard[field]; !exists {
			t.Fatalf("dashboard stats missing official field %q: %#v", field, dashboard)
		}
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/v1/usage/stats?start_date=2020-01-01&end_date=2099-01-01", nil, nil)
	statsEnvelope := decodeSub2APIJSON(t, body)
	stats, ok := statsEnvelope["data"].(map[string]any)
	if resp.StatusCode != http.StatusOK || !ok {
		t.Fatalf("usage stats = %d %#v", resp.StatusCode, statsEnvelope)
	}
	if endpoints, ok := stats["endpoints"].([]any); !ok || len(endpoints) == 0 {
		t.Fatalf("usage endpoint aggregation = %#v", stats)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/v1/usage/dashboard/trend?granularity=day", nil, nil)
	trendEnvelope := decodeSub2APIJSON(t, body)
	trend, ok := trendEnvelope["data"].(map[string]any)
	if resp.StatusCode != http.StatusOK || !ok {
		t.Fatalf("dashboard trend = %d %#v", resp.StatusCode, trendEnvelope)
	}
	if _, ok := trend["trend"].([]any); !ok {
		t.Fatalf("dashboard trend shape = %#v", trend)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/v1/usage/dashboard/models", nil, nil)
	modelsEnvelope := decodeSub2APIJSON(t, body)
	models, ok := modelsEnvelope["data"].(map[string]any)
	if resp.StatusCode != http.StatusOK || !ok {
		t.Fatalf("dashboard models = %d %#v", resp.StatusCode, modelsEnvelope)
	}
	if _, ok := models["models"].([]any); !ok {
		t.Fatalf("dashboard models shape = %#v", models)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/v1/usage/dashboard/snapshot-v2?start_date=2020-01-01&end_date=2099-01-01&granularity=day&include_trend=true&include_group_stats=true", nil, nil)
	snapshotEnvelope := decodeSub2APIJSON(t, body)
	snapshot, ok := snapshotEnvelope["data"].(map[string]any)
	if resp.StatusCode != http.StatusOK || !ok {
		t.Fatalf("dashboard snapshot = %d %#v", resp.StatusCode, snapshotEnvelope)
	}
	if trend, ok := snapshot["trend"].([]any); !ok || len(trend) == 0 {
		t.Fatalf("dashboard snapshot trend = %#v", snapshot)
	}
	if groups, ok := snapshot["groups"].([]any); !ok || len(groups) == 0 {
		t.Fatalf("dashboard snapshot groups = %#v", snapshot)
	}
	ssrfRequest := map[string]any{"model": "gpt-4o-mini", "messages": []any{map[string]any{"role": "user", "content": "inspect"}}, "image_url": "http://127.0.0.1:9/internal"}
	if resp, _ := doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", ssrfRequest, map[string]string{"Authorization": "Bearer " + rawKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("SSRF-shaped synthetic request = %d", resp.StatusCode)
	}
	resp, body = doRawJSON(t, client, http.MethodPost, "/api/v1/auth/register", map[string]any{"email": "isolation@example.com", "password": password}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second account registration = %d", resp.StatusCode)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/v1/usage/stats?start_date=2020-01-01&end_date=2099-01-01", nil, nil)
	isolationUsage := decodeSub2APIJSON(t, body)
	isolationData, _ := isolationUsage["data"].(map[string]any)
	if total, _ := isolationData["total"].(float64); resp.StatusCode != http.StatusOK || total != 0 {
		t.Fatalf("usage crossed account boundary = %d %#v", resp.StatusCode, isolationUsage)
	}

	events, err := st.Events(-1, model.ProductSub2API, "")
	if err != nil || len(events) < 10 {
		t.Fatalf("Sub2API events = %d, %v", len(events), err)
	}
	encodedEvents, _ := json.Marshal(events)
	if strings.Contains(string(encodedEvents), password) || strings.Contains(string(encodedEvents), rawKey) || strings.Contains(string(encodedEvents), accessToken) {
		t.Fatalf("raw Sub2API credential appeared in event payload: %s", encodedEvents)
	}
	var sawRegister, sawKey, sawAccepted, sawSSRF, sawChain bool
	for _, event := range events {
		if event.Product != model.ProductSub2API || event.RouteTemplate == "" || event.Metadata["outbound_network"] != "none" {
			t.Fatalf("event compatibility metadata = %#v", event)
		}
		switch event.EventType {
		case "sub2api.user.register.success":
			sawRegister = true
		case "sub2api.key.created":
			sawKey = true
		case "sub2api.gateway.chat.accepted":
			if event.InvocationID == "" || event.AuthOutcome != "valid_honey_key" || event.ModelID == "" {
				t.Fatalf("accepted invocation fields = %#v", event)
			}
			sawAccepted = true
		}
		if containsString(event.MatchedRuleIDs, "SUB2API_AUTH_SSRF_V1") {
			sawSSRF = true
		}
		if containsString(event.MatchedRuleIDs, "SUB2API_ACCOUNT_TO_GATEWAY_V1") {
			sawChain = true
		}
		if event.RawRequest != nil {
			decoded, decodeErr := base64.StdEncoding.DecodeString(event.RawRequest.BodyBase64)
			if decodeErr != nil || strings.Contains(string(decoded), password) || strings.Contains(string(decoded), rawKey) {
				t.Fatalf("raw credential in captured request: %#v", event.RawRequest)
			}
		}
	}
	if !sawRegister || !sawKey || !sawAccepted || !sawSSRF || !sawChain {
		t.Fatalf("Sub2API event/rule coverage register=%t key=%t accepted=%t ssrf=%t chain=%t", sawRegister, sawKey, sawAccepted, sawSSRF, sawChain)
	}
}

func TestSub2APIOAuthPolicyControlsPublicFlagsAndAuditSurface(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	profile := sub2APIProfileForTest(a, cfg)
	public := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login = %d", resp.StatusCode)
	}
	resp, policies := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/identity-policies", nil)
	if resp.StatusCode != http.StatusOK || len(policies["providers"].([]any)) != 3 || len(policies["sub2api_providers"].([]any)) != 6 {
		t.Fatalf("identity policy compatibility = %d %#v", resp.StatusCode, policies)
	}
	resp, updated := doJSON(t, admin, http.MethodPatch, cfg.AdminPath+"admin/api/v1/identity-policies/google", map[string]any{"enabled": true})
	if resp.StatusCode != http.StatusOK || updated["enabled"] != true {
		t.Fatalf("enable Sub2API Google policy = %d %#v", resp.StatusCode, updated)
	}
	resp, settingsBody := doRawJSON(t, public, http.MethodGet, "/api/v1/settings/public", nil, nil)
	settings := decodeSub2APIJSON(t, settingsBody)["data"].(map[string]any)
	if resp.StatusCode != http.StatusOK || settings["google_oauth_enabled"] != true {
		t.Fatalf("enabled public OAuth flag = %d %#v", resp.StatusCode, settings)
	}
	if resp, _ := doRawJSON(t, public, http.MethodGet, "/api/v1/auth/oauth/google/start", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("enabled OAuth remains synthetic/local-only, status = %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, admin, http.MethodPatch, cfg.AdminPath+"admin/api/v1/identity-policies/google", map[string]any{"enabled": false}); resp.StatusCode != http.StatusOK {
		t.Fatalf("disable Sub2API Google policy = %d", resp.StatusCode)
	}
	resp, settingsBody = doRawJSON(t, public, http.MethodGet, "/api/v1/settings/public", nil, nil)
	settings = decodeSub2APIJSON(t, settingsBody)["data"].(map[string]any)
	if resp.StatusCode != http.StatusOK || settings["google_oauth_enabled"] != false {
		t.Fatalf("disabled public OAuth flag = %d %#v", resp.StatusCode, settings)
	}
	if resp, _ := doJSON(t, admin, http.MethodPatch, cfg.AdminPath+"admin/api/v1/identity-policies/linuxdo", map[string]any{"enabled": true}); resp.StatusCode != http.StatusOK {
		t.Fatalf("legacy/shared LinuxDO policy update = %d", resp.StatusCode)
	}
	if policy, ok := st.GetSub2APIOAuthChannelPolicy("linuxdo"); !ok || !policy.Enabled {
		t.Fatalf("LinuxDO policy was not shared with Sub2API: %#v %t", policy, ok)
	}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/identity-policies/google:validate", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("Sub2API provider validation = %d", resp.StatusCode)
	}
	auditEntries, err := st.AuditEntries(50)
	if err != nil {
		t.Fatalf("identity policy audit entries = %v", err)
	}
	var sawGoogleUpdate, sawLinuxDOUpdate bool
	for _, entry := range auditEntries {
		if entry.Action != "identity.policy.update" {
			continue
		}
		switch entry.Target {
		case "identity-policy/google":
			sawGoogleUpdate = true
		case "identity-policy/linuxdo":
			sawLinuxDOUpdate = true
		}
	}
	if !sawGoogleUpdate || !sawLinuxDOUpdate {
		t.Fatalf("identity policy changes were not audited: google=%t linuxdo=%t entries=%#v", sawGoogleUpdate, sawLinuxDOUpdate, auditEntries)
	}
}
