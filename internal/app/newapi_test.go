package app

import (
	"net/http"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
)

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
