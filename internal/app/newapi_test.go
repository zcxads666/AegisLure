package app

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/oauth"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
)

type appOAuthRoundTripper struct{}

func (appOAuthRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	body := `{"id":"provider-stable-id"}`
	if request.URL.Path == "/token" {
		body = `{"access_token":"provider-access-token","scope":""}`
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func TestNewAPIPublicPagesAndStatusContract(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	cfg.ProfilePorts[model.ProductNewAPI] = 3000
	profile := profiles.Build(cfg)[model.ProductNewAPI]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}

	pages := []string{"/", "/login", "/register", "/sign-in", "/sign-up", "/forgot-password", "/dashboard", "/dashboard/overview", "/dashboard/models", "/pricing", "/rankings", "/docs", "/about", "/keys", "/usage", "/usage-logs/common", "/profile"}
	for _, path := range pages {
		resp, body := doRawJSON(t, client, http.MethodGet, path, nil, nil)
		if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("New API page %s failed: %d content-type=%q", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		if len(resp.Cookies()) != 0 || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
			t.Fatalf("New API page %s security headers/cookies failed: headers=%#v", path, resp.Header)
		}
		if !strings.Contains(string(body), "New API") || !strings.Contains(string(body), "/static/") {
			t.Fatalf("New API page %s is missing shell attribution: %s", path, body)
		}
		assertPublicResponseClean(t, resp, body)
	}

	resp, body := doRawJSON(t, client, http.MethodGet, "/api/status", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"system_name":"New API"`) || !strings.Contains(string(body), `"email_verification":false`) || !strings.Contains(string(body), `"footer_html"`) || strings.Contains(string(body), "AegisLure") {
		t.Fatalf("public New API status failed: %d %s", resp.StatusCode, body)
	}
	if len(resp.Cookies()) != 0 {
		t.Fatalf("public New API status set a cookie: %#v", resp.Cookies())
	}

	resp, body = doRawJSON(t, client, http.MethodPost, "/api/user/auth/refresh", nil, nil)
	if resp.StatusCode != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("anonymous New API auth refresh was not a quiet no-content response: %d %s", resp.StatusCode, body)
	}

	resp, body = doRawJSON(t, client, http.MethodGet, "/api/about", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"data":""`) {
		t.Fatalf("public New API about content was not left unconfigured: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/notice", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"data":""`) {
		t.Fatalf("public New API notice was not empty: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/pricing", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"icon":"OpenAI.Color"`) || !strings.Contains(string(body), `"icon":"Claude.Color"`) || !strings.Contains(string(body), `"icon":"Gemini.Color"`) {
		t.Fatalf("public New API pricing did not expose local vendor icons: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/perf-metrics/summary?hours=24", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"models"`) {
		t.Fatalf("public New API performance summary failed: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/api/perf-metrics?model=gpt-5.6-sol&hours=24", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"model_name":"gpt-5.6-sol"`) || !strings.Contains(string(body), `"groups":[]`) {
		t.Fatalf("public New API performance detail failed: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/static/cc-switch.svg", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "image/svg+xml") || !strings.Contains(string(body), "CC Switch") {
		t.Fatalf("local CC Switch asset was not served: %d content-type=%q body=%s", resp.StatusCode, resp.Header.Get("Content-Type"), body)
	}

	for _, path := range []string{"/admin", "/billing", "/payment", "/wallet", "/channels", "/models", "/users", "/redemption-codes", "/subscriptions", "/system-info", "/system-settings", "/playground", "/setup", "/oauth", "/webhook"} {
		resp, body := doRawJSON(t, client, http.MethodGet, path, nil, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unsafe New API surface %s was exposed: %d %s", path, resp.StatusCode, body)
		}
	}
}

func TestNewAPINativeBrowserContractUsesSafeNumericIDs(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	cfg.ProfilePorts[model.ProductNewAPI] = 3000
	profile := profiles.Build(cfg)[model.ProductNewAPI]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}

	password := "Password123!"
	resp, body := doJSON(t, client, http.MethodPost, "/api/user/register", map[string]string{
		"username": "native-browser-user",
		"password": password,
	})
	if resp.StatusCode != http.StatusOK || body["success"] != true {
		t.Fatalf("native registration failed: %d %#v", resp.StatusCode, body)
	}
	registeredUserID := body["data"].(map[string]any)["id"].(string)

	resp, body = doJSON(t, client, http.MethodPost, "/api/user/login", map[string]string{
		"username": "native-browser-user",
		"password": password,
	})
	if resp.StatusCode != http.StatusOK || body["success"] != true {
		t.Fatalf("native login failed: %d %#v", resp.StatusCode, body)
	}
	auth := body["data"].(map[string]any)
	userView := auth["user"].(map[string]any)
	if id, ok := userView["id"].(float64); !ok || id <= 0 || id > 1<<53-1 {
		t.Fatalf("user id is not browser-safe: %#v", userView["id"])
	}
	if sessionView := auth["session"].(map[string]any); sessionView["sid"] == "" {
		t.Fatalf("login session is missing: %#v", sessionView)
	}

	resp, _ = doJSON(t, client, http.MethodPost, "/api/user/checkin", map[string]any{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("native check-in failed: %d", resp.StatusCode)
	}
	resp, createdBody := doJSON(t, client, http.MethodPost, "/api/token/", map[string]any{"name": "native-browser"})
	if resp.StatusCode != http.StatusOK || createdBody["success"] != true {
		t.Fatalf("native token creation failed: %d %#v", resp.StatusCode, createdBody)
	}
	created := createdBody["data"].(map[string]any)
	tokenID, ok := created["id"].(float64)
	if !ok || tokenID <= 0 || tokenID > 1<<53-1 {
		t.Fatalf("token id is not browser-safe: %#v", created["id"])
	}
	tokenPath := "/api/token/" + strconv.FormatInt(int64(tokenID), 10)

	resp, listBody := doJSON(t, client, http.MethodGet, "/api/token/?p=1&size=10", nil)
	if resp.StatusCode != http.StatusOK || listBody["success"] != true {
		t.Fatalf("native token list failed: %d %#v", resp.StatusCode, listBody)
	}
	listData := listBody["data"].(map[string]any)
	if listData["total"].(float64) != 1 {
		t.Fatalf("native token list total = %#v", listData["total"])
	}

	resp, keyBody := doJSON(t, client, http.MethodPost, tokenPath+"/key", nil)
	if resp.StatusCode != http.StatusOK || keyBody["success"] != true {
		t.Fatalf("native key reveal failed after numeric URL round-trip: %d %#v", resp.StatusCode, keyBody)
	}
	suffix := keyBody["data"].(map[string]any)["key"].(string)
	if !strings.HasPrefix(suffix, "proj-") || len(suffix) < 12 {
		t.Fatalf("native key reveal returned an invalid suffix: %q", suffix)
	}
	rawKey := "sk-" + suffix

	resp, invocationBody := doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model":    "gpt-5.6-sol",
		"messages": []any{map[string]string{"role": "user", "content": "hello"}},
	}, map[string]string{"Authorization": "Bearer " + rawKey})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(invocationBody), `"choices"`) {
		t.Fatalf("native invocation failed: %d %s", resp.StatusCode, invocationBody)
	}

	resp, logsBody := doJSON(t, client, http.MethodGet, "/api/log/self?p=1&page_size=20", nil)
	if resp.StatusCode != http.StatusOK || logsBody["success"] != true {
		t.Fatalf("native usage log request failed: %d %#v", resp.StatusCode, logsBody)
	}
	logsData := logsBody["data"].(map[string]any)
	if logsData["total"].(float64) < 1 {
		t.Fatalf("native invocation did not create a usage log: %#v", logsData)
	}
	user, ok := st.GetHoneyUser(registeredUserID)
	if !ok || user.VirtualQuota >= 1000 {
		t.Fatalf("native invocation did not consume virtual quota: %#v", user)
	}
}

func TestNewAPILogoutClearsServerAssociatedUser(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	cfg.ProfilePorts[model.ProductNewAPI] = 3000
	profile := profiles.Build(cfg)[model.ProductNewAPI]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}

	resp, _ := doJSON(t, client, http.MethodPost, "/api/user/register", map[string]string{
		"username":          "logout-user",
		"email":             "logout@example.test",
		"password":          "Password123!",
		"verification_code": "123456",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("registration for logout test failed: %d", resp.StatusCode)
	}
	resp, _ = doRawJSON(t, client, http.MethodPost, "/api/user/auth/logout", map[string]any{}, nil)
	if resp.StatusCode != http.StatusOK || len(resp.Cookies()) != 0 {
		t.Fatalf("logout failed: %d cookies=%#v", resp.StatusCode, resp.Cookies())
	}
	resp, _ = doRawJSON(t, client, http.MethodGet, "/api/user/self", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("logout left the server-associated user active: %d", resp.StatusCode)
	}
}

func TestNewAPITenantTokenLifecycleAndPrivacy(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	cfg.ProfilePorts[model.ProductNewAPI] = 3000
	profile := profiles.Build(cfg)[model.ProductNewAPI]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}

	password := "Password123!"
	resp, registration := doJSON(t, client, http.MethodPost, "/api/user/register", map[string]string{
		"username":          "Alice",
		"email":             "Alice.Local@example.test",
		"password":          password,
		"verification_code": "123456",
	})
	if resp.StatusCode != http.StatusOK || registration["success"] != true {
		t.Fatalf("registration failed: %d %#v", resp.StatusCode, registration)
	}
	userID := registration["data"].(map[string]any)["id"].(string)
	user, ok := st.GetHoneyUser(userID)
	if !ok {
		t.Fatalf("registered user was not persisted: %q", userID)
	}
	if user.PasswordFP == password || user.PasswordFP == "" {
		t.Fatalf("password was stored unsafely: %#v", user)
	}
	if user.EmailLocalFP != security.Fingerprint(cfg.InstanceKey, "alice.local") || user.EmailDomain != "example.test" {
		t.Fatalf("email privacy fields are incorrect: %#v", user)
	}
	if user.PasswordLengthBucket != "12_15" || !containsString(user.PasswordClasses, "upper") || !containsString(user.PasswordClasses, "digit") || !containsString(user.PasswordClasses, "symbol") || user.PasswordWeakClass != "" {
		t.Fatalf("password profile is incomplete: %#v", user)
	}

	resp, _ = doJSON(t, client, http.MethodPost, "/api/user/checkin", map[string]any{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("check-in failed: %d", resp.StatusCode)
	}
	resp, tokenResponse := doJSON(t, client, http.MethodPost, "/api/token", map[string]any{
		"name":            "primary",
		"model_allowlist": []string{"gpt-5.6-sol"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token creation failed: %d %#v", resp.StatusCode, tokenResponse)
	}
	created := tokenResponse["data"].(map[string]any)
	tokenID := created["id"].(string)
	rawKey := created["key"].(string)
	if rawKey == "" || created["prefix_hint"] == nil {
		t.Fatalf("token response did not expose one-time key metadata: %#v", created)
	}

	resp, listBody := doRawJSON(t, client, http.MethodGet, "/api/token?search=primary", nil, nil)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(listBody), "\"hash\"") || strings.Contains(string(listBody), rawKey) {
		t.Fatalf("token list leaked secret material: %d %s", resp.StatusCode, listBody)
	}
	if !strings.Contains(string(listBody), tokenID) || !strings.Contains(string(listBody), "gpt-5.6-sol") {
		t.Fatalf("token list missed public metadata: %s", listBody)
	}

	resp, _ = doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model":    "claude-sonnet-5",
		"messages": []any{map[string]string{"role": "user", "content": "reply with ok"}},
	}, map[string]string{"Authorization": "Bearer " + rawKey})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("model allowlist was not enforced: %d", resp.StatusCode)
	}
	resp, _ = doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model":    "gpt-5.6-sol",
		"messages": []any{map[string]string{"role": "user", "content": "reply with ok"}},
	}, map[string]string{"Authorization": "Bearer " + rawKey})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowed model invocation failed: %d", resp.StatusCode)
	}
	storedToken, ok := findHoneyToken(st.ListTokens(userID), tokenID)
	if !ok || storedToken.LastUsedAt.IsZero() {
		t.Fatalf("token last-used timestamp was not persisted: %#v", storedToken)
	}

	resp, _ = doRawJSON(t, client, http.MethodPatch, "/api/token/"+tokenID, map[string]any{"name": "disabled-primary", "disabled": true}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token update failed: %d", resp.StatusCode)
	}
	resp, _ = doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model":    "gpt-5.6-sol",
		"messages": []any{map[string]string{"role": "user", "content": "reply with ok"}},
	}, map[string]string{"Authorization": "Bearer " + rawKey})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled token remained usable: %d", resp.StatusCode)
	}

	resp, _ = doRawJSON(t, client, http.MethodPatch, "/api/token/"+tokenID, map[string]any{"disabled": false, "model_allowlist": []string{}}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token re-enable failed: %d", resp.StatusCode)
	}
	before, _ := st.GetHoneyUser(userID)
	resp, _ = doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model":      "gpt-5.6-sol",
		"max_tokens": 9223372036854775807,
		"messages":   []any{map[string]string{"role": "user", "content": "reply with ok"}},
	}, map[string]string{"Authorization": "Bearer " + rawKey})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("quota overflow probe was accepted: %d", resp.StatusCode)
	}
	after, _ := st.GetHoneyUser(userID)
	if before.VirtualQuota != after.VirtualQuota {
		t.Fatalf("rejected quota overflow changed balance: before=%d after=%d", before.VirtualQuota, after.VirtualQuota)
	}

	resp, _ = doRawJSON(t, client, http.MethodDelete, "/api/token/"+tokenID, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token deletion failed: %d", resp.StatusCode)
	}
	if _, ok := findHoneyToken(st.ListTokens(userID), tokenID); ok {
		t.Fatal("deleted token remained in store")
	}

	resp, _ = doRawJSON(t, client, http.MethodPost, "/api/user/forgot-password", map[string]string{"email": "unknown@example.test"}, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("forgot-password response = %d", resp.StatusCode)
	}
	resp, _ = doRawJSON(t, client, http.MethodPost, "/api/user/forgot-password", map[string]string{"email": "Alice.Local@example.test"}, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("forgot-password response differed for known email: %d", resp.StatusCode)
	}
}

func TestNewAPINativeClaudeAndGeminiProtocolContracts(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	cfg.ProfilePorts[model.ProductNewAPI] = 3000
	profile := profiles.Build(cfg)[model.ProductNewAPI]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}

	resp, _ := doJSON(t, client, http.MethodPost, "/api/user/register", map[string]string{
		"username":          "native-protocol-user",
		"email":             "native-protocol@example.test",
		"password":          "Password123!",
		"verification_code": "123456",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("native protocol registration failed: %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, client, http.MethodPost, "/api/user/checkin", map[string]any{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("native protocol check-in failed: %d", resp.StatusCode)
	}
	resp, tokenBody := doJSON(t, client, http.MethodPost, "/api/token", map[string]any{"name": "native-protocol"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("native protocol token creation failed: %d", resp.StatusCode)
	}
	rawKey := tokenBody["data"].(map[string]any)["key"].(string)

	resp, body := doRawJSON(t, client, http.MethodGet, "/v1/models", nil, map[string]string{"x-api-key": rawKey, "anthropic-version": "2023-06-01"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"created_at"`) || !strings.Contains(string(body), `"display_name"`) || strings.Contains(string(body), rawKey) {
		t.Fatalf("Anthropic model list contract failed: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/v1beta/models", nil, map[string]string{"x-goog-api-key": rawKey})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"models"`) || !strings.Contains(string(body), `"supportedGenerationMethods"`) || strings.Contains(string(body), rawKey) {
		t.Fatalf("Gemini model list contract failed: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/v1/models/claude-sonnet-5", nil, map[string]string{"x-api-key": rawKey, "anthropic-version": "2023-06-01"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"id":"claude-sonnet-5"`) || !strings.Contains(string(body), `"created_at"`) {
		t.Fatalf("Anthropic model detail contract failed: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/v1beta/openai/models", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"object":"list"`) || !strings.Contains(string(body), `"gpt-5.6-sol"`) {
		t.Fatalf("Gemini OpenAI-compatible model list alias failed: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, client, http.MethodPost, "/v1/messages", map[string]any{
		"model":      "claude-sonnet-5",
		"max_tokens": 64,
		"messages":   []any{map[string]string{"role": "user", "content": "hello"}},
	}, map[string]string{"x-api-key": rawKey})
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), `"type":"error"`) {
		t.Fatalf("Claude version header was not required: %d %s", resp.StatusCode, body)
	}

	resp, body = doRawJSON(t, client, http.MethodPost, "/v1/messages", map[string]any{
		"model":      "claude-sonnet-5",
		"max_tokens": 64,
		"messages":   []any{map[string]string{"role": "user", "content": "reply with ok"}},
	}, map[string]string{"x-api-key": rawKey, "anthropic-version": "2023-06-01"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"type":"message"`) || !strings.Contains(string(body), `"stop_reason":"end_turn"`) || !strings.Contains(string(body), `"input_tokens"`) || strings.Contains(string(body), rawKey) {
		t.Fatalf("Claude response contract failed: %d %s", resp.StatusCode, body)
	}

	resp, body = doRawJSON(t, client, http.MethodPost, "/v1beta/models/gemini-3.7-flash:generateContent", map[string]any{
		"contents": []any{map[string]any{"role": "user", "parts": []any{map[string]string{"text": "reply with ok"}}}},
	}, map[string]string{"x-goog-api-key": rawKey})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"candidates"`) || !strings.Contains(string(body), `"finishReason":"STOP"`) || !strings.Contains(string(body), `"usageMetadata"`) || strings.Contains(string(body), rawKey) {
		t.Fatalf("Gemini response contract failed: %d %s", resp.StatusCode, body)
	}

	streamBody := `{"model":"claude-sonnet-5","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hello"}]}`
	resp = client.doWithHeaders(t, http.MethodPost, "/v1/messages", strings.NewReader(streamBody), "application/json", map[string]string{"x-api-key": rawKey, "anthropic-version": "2023-06-01"})
	streamData, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(streamData), "event: message_start") || !strings.Contains(string(streamData), "event: content_block_delta") || !strings.Contains(string(streamData), "event: message_stop") || strings.Contains(string(streamData), rawKey) {
		t.Fatalf("Claude SSE contract failed: %d %s", resp.StatusCode, streamData)
	}

	resp = client.doWithHeaders(t, http.MethodPost, "/v1beta/models/gemini-3.7-flash:streamGenerateContent", strings.NewReader(`{"contents":[{"parts":[{"text":"hello"}]}]}`), "application/json", map[string]string{"x-goog-api-key": rawKey})
	streamData, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(streamData), "data:") || !strings.Contains(string(streamData), `"finishReason":"STOP"`) || strings.Contains(string(streamData), rawKey) {
		t.Fatalf("Gemini SSE contract failed: %d %s", resp.StatusCode, streamData)
	}

	if events, err := st.Events(-1, model.ProductNewAPI, ""); err != nil {
		t.Fatal(err)
	} else {
		foundClaude, foundGemini := false, false
		for _, event := range events {
			if event.RouteTemplate == "anthropic.messages" && event.InvocationID != "" && event.SimulatedCost > 0 {
				foundClaude = true
			}
			if (event.RouteTemplate == "gemini.generate" || event.RouteTemplate == "gemini.stream") && event.InvocationID != "" && event.SimulatedCost > 0 {
				foundGemini = true
			}
		}
		if !foundClaude || !foundGemini {
			t.Fatalf("native protocol invocations were not recorded: claude=%t gemini=%t", foundClaude, foundGemini)
		}
	}
}

func TestNewAPIRegistrationRejectsMalformedVerificationWithoutRawPassword(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	cfg.ProfilePorts[model.ProductNewAPI] = 3000
	profile := profiles.Build(cfg)[model.ProductNewAPI]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	resp, body := doRawJSON(t, client, http.MethodPost, "/api/user/register", map[string]any{
		"username":          "probe-user",
		"email":             "probe@example.test",
		"password":          "password123",
		"verification_code": "12345x",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest || strings.Contains(string(body), "password123") {
		t.Fatalf("malformed registration was not safely rejected: %d %s", resp.StatusCode, body)
	}
}

func TestNewAPIOAuthBindsHoneyIdentityWithoutRiskOrOutboundByDefault(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	cfg.ProfilePorts[model.ProductNewAPI] = 3000
	profile := profiles.Build(cfg)[model.ProductNewAPI]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}

	resp := client.do(t, http.MethodGet, "/api/oauth/github", nil, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("OAuth was enabled without a broker: %d", resp.StatusCode)
	}

	providerConfig := oauth.DefaultProviderConfig(oauth.GitHub)
	providerConfig.Enabled = true
	providerConfig.ClientID = "client-id"
	providerConfig.ClientSecret = "client-secret"
	providerConfig.RedirectURL = "https://admin.test/api/oauth/github/callback"
	providerConfig.AuthorizationURL = "http://oauth.test/authorize"
	providerConfig.TokenURL = "http://oauth.test/token"
	providerConfig.IdentityURL = "http://oauth.test/user"
	providerConfig.RevokeURL = ""
	broker, err := oauth.New(oauth.Config{InstanceKey: cfg.InstanceKey, Providers: map[oauth.Provider]oauth.ProviderConfig{oauth.GitHub: providerConfig}, Client: &http.Client{Transport: appOAuthRoundTripper{}}, AllowTestEndpoints: true})
	if err != nil {
		t.Fatal(err)
	}
	a.SetOAuthBroker(broker)

	resp = client.do(t, http.MethodGet, "/api/oauth/github/start", nil, "")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("OAuth start status = %d", resp.StatusCode)
	}
	authorizationURL, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	if authorizationURL.Query().Get("client_secret") != "" || authorizationURL.Query().Get("state") == "" {
		t.Fatalf("unsafe OAuth redirect: %s", authorizationURL)
	}
	state := authorizationURL.Query().Get("state")
	resp, body := doRawJSON(t, client, http.MethodGet, "/api/oauth/github/callback?state="+url.QueryEscape(state)+"&code="+url.QueryEscape("one-time-code"), nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"success":true`) {
		t.Fatalf("OAuth callback failed: %d %s", resp.StatusCode, body)
	}
	identities := st.ListHoneyIdentities()
	if len(identities) != 1 || identities[0].SubjectHMAC == "provider-stable-id" || identities[0].Provider != "github" {
		t.Fatalf("OAuth identity was not safely persisted: %#v", identities)
	}
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login for identity controls failed: %d", resp.StatusCode)
	}
	resp, body = doRawJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/identities", nil, nil)
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "provider-stable-id") {
		t.Fatalf("identity admin list leaked provider identity: %d %s", resp.StatusCode, body)
	}
	identityID := identities[0].ID
	resp, _ = doRawJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/identities/"+url.PathEscape(identityID)+"/revoke", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("identity revoke failed: %d", resp.StatusCode)
	}
	resp, _ = doRawJSON(t, admin, http.MethodDelete, cfg.AdminPath+"admin/api/v1/identities/"+url.PathEscape(identityID), nil, nil)
	if resp.StatusCode != http.StatusOK || len(st.ListHoneyIdentities()) != 0 {
		t.Fatalf("identity deletion failed: %d %#v", resp.StatusCode, st.ListHoneyIdentities())
	}
	events, err := st.Events(-1, model.ProductNewAPI, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.RouteTemplate == "newapi.oauth.callback" && event.Score != 0 {
			t.Fatalf("ordinary OAuth callback gained risk score: %+v", event)
		}
	}
}
