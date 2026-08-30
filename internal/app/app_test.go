package app

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
	"github.com/zcxads666/AegisLure/internal/store"
)

func newTestApp(t *testing.T, initialized bool) (*App, *config.Config, *store.Store) {
	t.Helper()
	t.Setenv("HP_COOKIE_SECURE", "0")
	t.Setenv("HP_CONFIG", t.TempDir()+"/config.json")
	cfg := &config.Config{
		InstanceID:  "test-instance",
		InstanceKey: "test-instance-key",
		DataDir:     t.TempDir(),
		AdminBind:   "127.0.0.1",
		AdminPort:   56865,
		AdminPath:   "/test-admin-entry/",
		ProfilePorts: map[string]int{
			model.ProductOllama: 11434,
			model.ProductVLLM:   8000,
		},
		EnabledProfiles: []string{model.ProductOllama, model.ProductVLLM},
		Scenario: map[string]string{
			model.ProductOllama: "no-key",
			model.ProductVLLM:   "legacy-gap",
		},
	}
	if initialized {
		passwordHash, err := security.HashPassword("correct horse battery staple")
		if err != nil {
			t.Fatal(err)
		}
		st, err := store.Open(cfg.DataDir, cfg.InstanceKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Update(func(state *model.State) error {
			state.Admin = model.AdminState{Initialized: true, OwnerUsername: "owner", PasswordHash: passwordHash}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return New(cfg, st), cfg, st
	}
	st, err := store.Open(cfg.DataDir, cfg.InstanceKey)
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, st), cfg, st
}

type inProcessClient struct {
	handler http.Handler
	cookies map[string]string
}

func (c *inProcessClient) do(t *testing.T, method, path string, body io.Reader, contentType string) *http.Response {
	return c.doWithHeaders(t, method, path, body, contentType, nil)
}

func (c *inProcessClient) doWithHeaders(t *testing.T, method, path string, body io.Reader, contentType string, headers map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, "https://admin.test"+path, body)
	for name, value := range c.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rr := httptest.NewRecorder()
	c.handler.ServeHTTP(rr, req)
	response := rr.Result()
	if c.cookies == nil {
		c.cookies = map[string]string{}
	}
	for _, cookie := range response.Cookies() {
		if cookie.MaxAge < 0 || cookie.Value == "" {
			delete(c.cookies, cookie.Name)
		} else {
			c.cookies[cookie.Name] = cookie.Value
		}
	}
	return response
}

func doRawJSON(t *testing.T, client *inProcessClient, method, endpoint string, value any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var body io.Reader
	contentType := ""
	if value != nil {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		body = strings.NewReader(string(encoded))
		contentType = "application/json"
	}
	resp := client.doWithHeaders(t, method, endpoint, body, contentType, headers)
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

func doJSON(t *testing.T, client *inProcessClient, method, endpoint string, value any) (*http.Response, map[string]any) {
	t.Helper()
	var body io.Reader
	if value != nil {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		body = strings.NewReader(string(encoded))
	}
	resp := client.do(t, method, endpoint, body, map[bool]string{true: "application/json"}[value != nil])
	defer resp.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil && resp.StatusCode != http.StatusNoContent {
		t.Fatal(err)
	}
	return resp, decoded
}

func TestAdminPageUsesNonceAndCompletesOwnerSetupLogin(t *testing.T) {
	a, cfg, _ := newTestApp(t, false)
	client := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}

	pageResp := client.do(t, http.MethodGet, cfg.AdminPath, nil, "")
	pageBody, _ := io.ReadAll(pageResp.Body)
	_ = pageResp.Body.Close()
	if pageResp.StatusCode != http.StatusOK {
		t.Fatalf("admin page status = %d", pageResp.StatusCode)
	}
	if !strings.Contains(pageResp.Header.Get("Content-Security-Policy"), "script-src 'nonce-") {
		t.Fatalf("admin page did not receive nonce CSP: %q", pageResp.Header.Get("Content-Security-Policy"))
	}
	if !strings.Contains(pageResp.Header.Get("Content-Security-Policy"), "connect-src 'self'") {
		t.Fatalf("admin page did not allow same-origin API connections: %q", pageResp.Header.Get("Content-Security-Policy"))
	}
	if strings.Contains(string(pageBody), "script-src 'unsafe-inline'") || !strings.Contains(string(pageBody), "nonce=\"") {
		t.Fatal("admin page did not contain a nonce-protected script")
	}
	if strings.Contains(string(pageBody), "bootstrap-code") || strings.Contains(string(pageBody), "totp-code") || strings.Contains(string(pageBody), "totp-secret") {
		t.Fatal("admin page still exposes removed bootstrap or TOTP controls")
	}
	if strings.Contains(string(pageBody), "%%") {
		t.Fatal("admin page contains an unrendered CSS percentage escape")
	}
	if strings.Count(string(pageBody), "<!doctype html>") != 1 {
		t.Fatalf("admin page should contain one document root, got %d", strings.Count(string(pageBody), "<!doctype html>"))
	}
	if !strings.Contains(string(pageBody), "font-family:\"Inter\",\"Noto Sans SC\"") || !strings.Contains(string(pageBody), "pointer-events:none") {
		t.Fatal("admin page is missing the local font stack or non-blocking decoration layer")
	}

	base := cfg.AdminPath
	resp, status := doJSON(t, client, http.MethodGet, base+"setup/status", nil)
	if resp.StatusCode != http.StatusOK || status["initialized"] != false || status["setup_available"] != true {
		t.Fatalf("unexpected setup status: %d %#v", resp.StatusCode, status)
	}
	resp, owner := doJSON(t, client, http.MethodPost, base+"setup/create-owner", map[string]string{"username": "owner", "password": "short8!!"})
	if resp.StatusCode != http.StatusOK || owner["success"] != true {
		t.Fatalf("owner setup status = %d %#v", resp.StatusCode, owner)
	}
	if _, hasTOTP := owner["totp_secret"]; hasTOTP {
		t.Fatal("owner setup unexpectedly returned TOTP material")
	}
	resp, login := doJSON(t, client, http.MethodPost, base+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "short8!!"})
	if resp.StatusCode != http.StatusOK || login["success"] != true {
		t.Fatalf("login status = %d %#v", resp.StatusCode, login)
	}
	resp, dashboard := doJSON(t, client, http.MethodGet, base+"admin/api/v1/dashboard", nil)
	if resp.StatusCode != http.StatusOK || dashboard["synthetic_only"] != true {
		t.Fatalf("dashboard status = %d %#v", resp.StatusCode, dashboard)
	}
	resp, _ = doJSON(t, client, http.MethodPost, base+"admin/api/v1/auth/logout", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, client, http.MethodGet, base+"admin/api/v1/dashboard", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("dashboard after logout status = %d", resp.StatusCode)
	}
}

func TestOllamaNativeAndVLLMGapRecordInvocationFacts(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	profilesByName := profiles.Build(cfg)

	ollamaClient := &inProcessClient{handler: a.publicHandler(profilesByName[model.ProductOllama]), cookies: map[string]string{}}
	resp, ollama := doJSON(t, ollamaClient, http.MethodPost, "/api/generate", map[string]any{"model": "qwen3.6:35b-a3b", "prompt": "reply with ok"})
	if resp.StatusCode != http.StatusOK || ollama["response"] != "OK" || ollama["done"] != true {
		t.Fatalf("unexpected Ollama response: %d %#v", resp.StatusCode, ollama)
	}

	vllmClient := &inProcessClient{handler: a.publicHandler(profilesByName[model.ProductVLLM]), cookies: map[string]string{}}
	resp, _ = doJSON(t, vllmClient, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "Qwen/Qwen3.6-35B-A3B", "messages": []any{map[string]string{"role": "user", "content": "hello"}}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("vLLM missing-key status = %d", resp.StatusCode)
	}
	resp, bypass := doJSON(t, vllmClient, http.MethodPost, "/invocations", map[string]any{"model": "Qwen/Qwen3.6-35B-A3B", "prompt": "reply with ok", "stream": false})
	if resp.StatusCode != http.StatusOK || bypass["object"] != "chat.completion" {
		t.Fatalf("unexpected vLLM invocation response: %d %#v", resp.StatusCode, bypass)
	}
	events, err := st.Events(20, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var foundBypass, foundOllama bool
	for _, event := range events {
		if event.Product == model.ProductVLLM && event.AuthOutcome == "bypass_simulated" && event.InvocationLevel == model.L2 {
			foundBypass = true
		}
		if event.Product == model.ProductOllama && event.ExecutionOutcome == "synthetic_accepted" && event.ModelResolved {
			foundOllama = true
		}
	}
	if !foundBypass || !foundOllama {
		t.Fatalf("invocation facts missing: bypass=%v ollama=%v events=%+v", foundBypass, foundOllama, events)
	}
}

func TestOllamaCompatibilityAndVirtualEffectVerification(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	profile := profiles.Build(cfg)[model.ProductOllama]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	resp, tags := doJSON(t, client, http.MethodGet, "/api/tags", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tags status = %d", resp.StatusCode)
	}
	models, ok := tags["models"].([]any)
	if !ok || len(models) != 3 {
		t.Fatalf("unexpected Ollama catalog: %#v", tags)
	}
	resp, _ = doJSON(t, client, http.MethodPost, "/api/generate", map[string]any{"model": "qwen3.6:35b-a3b", "prompt": "hello"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("generate status = %d", resp.StatusCode)
	}
	resp, ps := doJSON(t, client, http.MethodGet, "/api/ps", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ps status = %d", resp.StatusCode)
	}
	if loaded, ok := ps["models"].([]any); !ok || len(loaded) != 1 {
		t.Fatalf("virtual model was not visible in ps: %#v", ps)
	}
	resp, completion := doJSON(t, client, http.MethodPost, "/v1/completions", map[string]any{"model": "qwen3.6:35b-a3b", "prompt": "reply with ok"})
	if resp.StatusCode != http.StatusOK || completion["object"] != "text_completion" {
		t.Fatalf("completion compatibility failed: %d %#v", resp.StatusCode, completion)
	}
	resp, embedding := doJSON(t, client, http.MethodPost, "/v1/embeddings", map[string]any{"model": "qwen3.6:35b-a3b", "input": "hello"})
	if resp.StatusCode != http.StatusOK || embedding["object"] != "list" {
		t.Fatalf("embedding compatibility failed: %d %#v", resp.StatusCode, embedding)
	}
	resp, body := doRawJSON(t, client, http.MethodPost, "/api/pull", map[string]any{"model": "qwen3.6:35b-a3b", "stream": true}, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "pulling manifest") || !strings.Contains(string(body), "success") {
		t.Fatalf("pull NDJSON compatibility failed: %d %s", resp.StatusCode, body)
	}
	resp, _ = doRawJSON(t, client, http.MethodHead, "/api/blobs/sha256:test", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("blob HEAD status = %d", resp.StatusCode)
	}
	events, err := st.Events(-1, model.ProductOllama, "")
	if err != nil {
		t.Fatal(err)
	}
	var verified bool
	for _, event := range events {
		if event.RouteTemplate == "ollama.ps" && event.EffectOutcome == "verified" {
			verified = true
		}
	}
	if !verified {
		t.Fatalf("expected post-call effect verification in events: %+v", events)
	}
}

func TestVLLMSimulatedWorkerFailureIsScopedToSession(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	profile := profiles.Build(cfg)[model.ProductVLLM]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	malicious := map[string]any{"model": "Qwen/Qwen3.6-35B-A3B", "prompt": "pickle __reduce__ image_url http://169.254.169.254/latest"}
	resp, _ := doJSON(t, client, http.MethodPost, "/invocations", malicious)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invocations status = %d", resp.StatusCode)
	}
	resp, _ = doRawJSON(t, client, http.MethodGet, "/health", nil, nil)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("degraded session health status = %d", resp.StatusCode)
	}
	other := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	resp = other.doWithHeaders(t, http.MethodGet, "/health", nil, "", map[string]string{"User-Agent": "different-client"})
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("other session health status = %d", resp.StatusCode)
	}
}

func TestNewAPINormalUsageChainWritesVirtualLedger(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	cfg.ProfilePorts[model.ProductNewAPI] = 3000
	profile := profiles.Build(cfg)[model.ProductNewAPI]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	resp, _ := doJSON(t, client, http.MethodPost, "/api/user/register", map[string]string{"username": "alice", "email": "alice@example.test", "password": "a-password-that-is-not-stored"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register status = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, client, http.MethodPost, "/api/user/checkin", map[string]any{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("checkin status = %d", resp.StatusCode)
	}
	resp, tokenResponse := doJSON(t, client, http.MethodPost, "/api/token", map[string]any{})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token status = %d", resp.StatusCode)
	}
	data := tokenResponse["data"].(map[string]any)
	rawKey := data["key"].(string)
	resp, body := doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "gpt-5.6-sol", "messages": []any{map[string]string{"role": "user", "content": "reply with ok"}}, "stream": true}, map[string]string{"Authorization": "Bearer " + rawKey})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "[DONE]") {
		t.Fatalf("New API stream failed: %d %s", resp.StatusCode, body)
	}
	resp, _ = doJSON(t, client, http.MethodGet, "/api/log", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("usage log status = %d", resp.StatusCode)
	}
	stateEvents, err := st.Events(-1, model.ProductNewAPI, "")
	if err != nil {
		t.Fatal(err)
	}
	var completed bool
	for _, event := range stateEvents {
		if event.EventType == "llm.stream.completed" && event.InvocationID != "" && event.SimulatedCost > 0 {
			completed = true
		}
	}
	if !completed {
		t.Fatalf("missing completed synthetic invocation: %+v", stateEvents)
	}
}

func TestAdminRecoveryCodeResetsPassword(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	code := "local-rescue-code"
	if err := st.Update(func(state *model.State) error {
		state.Admin.RescueHashes = []string{security.Fingerprint(cfg.InstanceKey, code)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	client := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	resp, result := doJSON(t, client, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/recovery-code/reset", map[string]string{"username": "owner", "recovery_code": code, "new_password": "new-correct-password-for-owner"})
	if resp.StatusCode != http.StatusOK || result["success"] != true {
		t.Fatalf("recovery reset status = %d %#v", resp.StatusCode, result)
	}
	resp, _ = doJSON(t, client, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "new-correct-password-for-owner"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login after recovery status = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, client, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/recovery-code/reset", map[string]string{"username": "owner", "recovery_code": code, "new_password": "another-new-password"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused recovery code status = %d", resp.StatusCode)
	}
}

func TestPublicRequestBudgetsAndSecurityHeaders(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	profile := profiles.Build(cfg)[model.ProductOllama]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}

	resp, _ := doRawJSON(t, client, http.MethodGet, "/api/generate", nil, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "POST" {
		t.Fatalf("GET on POST-only route = %d allow=%q", resp.StatusCode, resp.Header.Get("Allow"))
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("security headers missing: %#v", resp.Header)
	}
	if cookies := resp.Cookies(); len(cookies) != 0 {
		t.Fatalf("public Ollama endpoint must not set a session cookie: %#v", cookies)
	}

	tooLarge := strings.Repeat("x", 1<<20+1)
	resp = client.doWithHeaders(t, http.MethodPost, "/api/generate", strings.NewReader(tooLarge), "application/json", nil)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d", resp.StatusCode)
	}

	headers := make(map[string]string, 101)
	for i := 0; i < 101; i++ {
		headers[fmt.Sprintf("X-Test-%d", i)] = "x"
	}
	resp, _ = doRawJSON(t, client, http.MethodGet, "/api/tags", nil, headers)
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized header set status = %d", resp.StatusCode)
	}
}

func TestAdminRejectsCrossOriginMutationAndEnforcesSetupPolicy(t *testing.T) {
	a, cfg, _ := newTestApp(t, false)
	client := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	base := cfg.AdminPath
	resp, _ := doRawJSON(t, client, http.MethodPost, base+"setup/create-owner", map[string]string{"username": "owner", "password": "short8!!"}, map[string]string{"Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin setup status = %d", resp.StatusCode)
	}
	resp, _ = doRawJSON(t, client, http.MethodPost, base+"setup/create-owner", map[string]string{"username": "owner", "password": "short7"}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("short password status = %d", resp.StatusCode)
	}
	resp, _ = doRawJSON(t, client, http.MethodPost, base+"setup/create-owner", map[string]string{"username": "owner", "password": "short8!!"}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner setup status = %d", resp.StatusCode)
	}
	resp, _ = doRawJSON(t, client, http.MethodPost, base+"setup/create-owner", map[string]string{"username": "other", "password": "another8"}, nil)
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("second owner setup status = %d", resp.StatusCode)
	}
}

func TestSGLangAndLocalAIProfilesRemainSynthetic(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	cfg.Scenario[model.ProductSGLang] = "no-key"
	sglang := profiles.Build(cfg)[model.ProductSGLang]
	client := &inProcessClient{handler: a.publicHandler(sglang), cookies: map[string]string{}}
	resp, info := doJSON(t, client, http.MethodGet, "/server_info", nil)
	if resp.StatusCode != http.StatusOK || info["api_key"] == nil {
		t.Fatalf("SGLang server_info failed: %d %#v", resp.StatusCode, info)
	}
	key := info["api_key"].(string)
	resp, result := doJSON(t, client, http.MethodPost, "/load_lora_adapter_from_tensors", map[string]string{"tensors": "pickle __reduce__"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SGLang missing key status = %d", resp.StatusCode)
	}
	resp, result = doJSONWithHeaders(t, client, http.MethodPost, "/load_lora_adapter_from_tensors", map[string]string{"tensors": "pickle __reduce__"}, map[string]string{"Authorization": "Bearer " + key})
	if resp.StatusCode != http.StatusOK || result["status"] != "accepted" || result["weight_id"] == nil {
		t.Fatalf("SGLang honey key action failed: %d %#v", resp.StatusCode, result)
	}
	localAI := profiles.Build(cfg)[model.ProductLocalAI]
	localClient := &inProcessClient{handler: a.publicHandler(localAI), cookies: map[string]string{}}
	resp, result = doJSON(t, localClient, http.MethodPost, "/models/apply", map[string]string{"url": "http://127.0.0.1/model.tar"})
	if resp.StatusCode != http.StatusOK || result["status"] != "ready" || result["id"] == nil {
		t.Fatalf("LocalAI model apply failed: %d %#v", resp.StatusCode, result)
	}
}

func TestPublicPersonasHaveSeparateCleanModelSurfaces(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	profilesByName := profiles.Build(cfg)
	ollama := &inProcessClient{handler: a.publicHandler(profilesByName[model.ProductOllama]), cookies: map[string]string{}}
	vllm := &inProcessClient{handler: a.publicHandler(profilesByName[model.ProductVLLM]), cookies: map[string]string{}}

	ollamaResp, ollamaBody := doRawJSON(t, ollama, http.MethodGet, "/api/tags", nil, nil)
	assertPublicResponseClean(t, ollamaResp, ollamaBody)
	var tags struct {
		Models []profiles.OllamaModel `json:"models"`
	}
	if err := json.Unmarshal(ollamaBody, &tags); err != nil || len(tags.Models) != 3 {
		t.Fatalf("invalid Ollama tags response: %s: %#v", err, tags)
	}
	if tags.Models[0].Details.Family == "" || len(tags.Models[0].Details.Families) == 0 {
		t.Fatalf("Ollama details are incomplete: %#v", tags.Models[0])
	}
	seenSizes := map[int64]bool{}
	seenModified := map[string]bool{}
	for _, item := range tags.Models {
		if item.Size <= 0 || seenSizes[item.Size] || seenModified[item.ModifiedAt] {
			t.Fatalf("Ollama metadata is not distinct: %#v", tags.Models)
		}
		seenSizes[item.Size] = true
		seenModified[item.ModifiedAt] = true
		if len(item.Digest) != len("sha256:")+64 || !strings.HasPrefix(item.Digest, "sha256:") {
			t.Fatalf("invalid Ollama digest: %#v", item)
		}
		if len(item.Details.Families) != 1 || item.Details.Families[0] != item.Details.Family {
			t.Fatalf("Ollama family metadata is inconsistent: %#v", item)
		}
	}
	_, ollamaBodyAgain := doRawJSON(t, ollama, http.MethodGet, "/api/tags", nil, nil)
	if !reflect.DeepEqual(ollamaBody, ollamaBodyAgain) {
		t.Fatal("Ollama model metadata changed during one instance lifetime")
	}

	vllmResp, vllmBody := doRawJSON(t, vllm, http.MethodGet, "/v1/models", nil, nil)
	assertPublicResponseClean(t, vllmResp, vllmBody)
	var cards struct {
		Object string                   `json:"object"`
		Data   []profiles.VLLMModelCard `json:"data"`
	}
	if err := json.Unmarshal(vllmBody, &cards); err != nil || cards.Object != "list" || len(cards.Data) != 3 {
		t.Fatalf("invalid vLLM model list: %s: %#v", err, cards)
	}
	for _, card := range cards.Data {
		if card.Object != "model" || card.OwnedBy != "vllm" || card.Root != card.ID || len(card.Permission) != 1 {
			t.Fatalf("invalid vLLM ModelCard: %#v", card)
		}
	}
	if reflect.DeepEqual(ollamaBody, vllmBody) || strings.Contains(string(vllmBody), "display_name") || strings.Contains(string(vllmBody), "capabilities") {
		t.Fatal("Ollama and vLLM model surfaces were not separated")
	}
}

func TestVLLMMetricsAndHeadersStayConsistent(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	client := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductVLLM]), cookies: map[string]string{}}
	for _, endpoint := range []string{"/", "/health", "/version", "/v1/models", "/metrics", "/docs", "/openapi.json", "/unknown"} {
		resp, body := doRawJSON(t, client, http.MethodGet, endpoint, nil, nil)
		assertPublicResponseClean(t, resp, body)
		if resp.Header.Get("Server") != "uvicorn" {
			t.Fatalf("vLLM %s missing consistent Server header: %#v", endpoint, resp.Header)
		}
	}
	resp, metricsBefore := doRawJSON(t, client, http.MethodGet, "/metrics", nil, nil)
	if resp.Header.Get("Content-Type") != "text/plain; version=0.0.4" {
		t.Fatalf("unexpected metrics content type: %q", resp.Header.Get("Content-Type"))
	}
	for _, name := range []string{"vllm:num_requests_running", "vllm:num_requests_waiting", "vllm:kv_cache_usage_perc", "vllm:prompt_tokens_total", "vllm:generation_tokens_total", "vllm:request_success_total"} {
		if !strings.Contains(string(metricsBefore), name) {
			t.Fatalf("metrics missing %s: %s", name, metricsBefore)
		}
	}
	if strings.Contains(strings.ToLower(string(metricsBefore)), "synthetic") || strings.Contains(string(metricsBefore), "decoy=") {
		t.Fatal("vLLM metrics leaked internal marker")
	}
	resp, _ = doJSON(t, client, http.MethodPost, "/invocations", map[string]any{"model": "Qwen/Qwen3.6-35B-A3B", "prompt": "reply with ok"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("vLLM invocation status = %d", resp.StatusCode)
	}
	_, metricsAfter := doRawJSON(t, client, http.MethodGet, "/metrics", nil, nil)
	if !strings.Contains(string(metricsAfter), "vllm:prompt_tokens_total{model_name=\"Qwen/Qwen3.6-35B-A3B\"} 1") || !strings.Contains(string(metricsAfter), "vllm:request_success_total{finished_reason=\"stop\",model_name=\"Qwen/Qwen3.6-35B-A3B\"} 1") {
		t.Fatalf("vLLM metrics did not track accepted request: %s", metricsAfter)
	}
}

func TestPersonaErrorShapesAndNoPublicSessionCookie(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	ollama := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductOllama]), cookies: map[string]string{}}
	vllm := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductVLLM]), cookies: map[string]string{}}
	resp, body := doRawJSON(t, ollama, http.MethodGet, "/unknown", nil, nil)
	assertPublicResponseClean(t, resp, body)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), `"error"`) || strings.Contains(string(body), `"detail"`) {
		t.Fatalf("unexpected Ollama error shape: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, vllm, http.MethodGet, "/unknown", nil, nil)
	assertPublicResponseClean(t, resp, body)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), `"detail"`) || strings.Contains(string(body), `"error"`) {
		t.Fatalf("unexpected vLLM error shape: %d %s", resp.StatusCode, body)
	}
	resp, body = doRawJSON(t, ollama, http.MethodGet, "/api/generate", nil, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed || !strings.Contains(string(body), `"error"`) || len(resp.Cookies()) != 0 {
		t.Fatalf("Ollama method/cookie contract failed: %d %s cookies=%#v", resp.StatusCode, body, resp.Cookies())
	}
	resp, body = doRawJSON(t, vllm, http.MethodGet, "/v1/chat/completions", nil, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed || !strings.Contains(string(body), `"detail"`) || len(resp.Cookies()) != 0 {
		t.Fatalf("vLLM method/cookie contract failed: %d %s cookies=%#v", resp.StatusCode, body, resp.Cookies())
	}
}

func TestAllPublicPersonasAvoidInternalMarkers(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	checks := []struct {
		product string
		method  string
		path    string
		value   any
	}{
		{model.ProductNewAPI, http.MethodGet, "/", nil},
		{model.ProductSGLang, http.MethodGet, "/server_info", nil},
		{model.ProductLocalAI, http.MethodGet, "/models/available", nil},
	}
	for _, check := range checks {
		profile := profiles.Build(cfg)[check.product]
		client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
		resp, body := doRawJSON(t, client, check.method, check.path, check.value, nil)
		assertPublicResponseClean(t, resp, body)
	}
}

func assertPublicResponseClean(t *testing.T, resp *http.Response, body []byte) {
	t.Helper()
	text := strings.ToLower(string(body))
	for _, values := range resp.Header {
		text += "\n" + strings.ToLower(strings.Join(values, "\n"))
	}
	for _, marker := range []string{"synthetic", "decoy", "honeypot", "fake", "mock", "emulated", "hp_session", "hp_"} {
		if strings.Contains(text, marker) {
			t.Fatalf("public response leaked %q: headers=%#v body=%s", marker, resp.Header, body)
		}
	}
}

func doJSONWithHeaders(t *testing.T, client *inProcessClient, method, endpoint string, value any, headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	resp := client.doWithHeaders(t, method, endpoint, strings.NewReader(string(encoded)), "application/json", headers)
	defer resp.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	return resp, decoded
}
