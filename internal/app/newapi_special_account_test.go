package app

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
)

func TestNewAPISpecialRootAccountLifecycleAndMonitoring(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	cfg.ProfilePorts[model.ProductNewAPI] = 3000
	profile := profiles.Build(cfg)[model.ProductNewAPI]

	rootFP := security.Fingerprint(cfg.InstanceKey, newAPIRootUsername)
	root, ok := st.FindHoneyUser(rootFP)
	if !ok || !a.isNewAPIRootUser(root) || root.VirtualQuota != newAPIRootDefaultQuota || len(st.ListTokens(root.ID)) != 0 {
		t.Fatalf("special root account was not initialized correctly: %#v tokens=%#v", root, st.ListTokens(root.ID))
	}
	if root.PasswordFP != security.Fingerprint(cfg.InstanceKey, newAPIRootPassword) || root.PasswordFP == newAPIRootPassword || !root.ResetAt.After(time.Now().UTC().Add(23*time.Hour)) {
		t.Fatalf("special root credential/reset state is unsafe or incomplete: %#v", root)
	}

	rootClient := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	if resp, _ := doJSON(t, rootClient, http.MethodPost, "/api/user/login", map[string]string{"username": newAPIRootUsername, "password": "wrong-password"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("root rejected-password status = %d", resp.StatusCode)
	}
	if resp, login := doJSON(t, rootClient, http.MethodPost, "/api/user/login", map[string]string{"username": newAPIRootUsername, "password": newAPIRootPassword}); resp.StatusCode != http.StatusOK || login["success"] != true {
		t.Fatalf("root login failed: %d %#v", resp.StatusCode, login)
	} else {
		user := login["data"].(map[string]any)["user"].(map[string]any)
		if user["role"] != float64(1) || user["quota"] != float64(newAPIRootDefaultQuota) || user["permissions"].(map[string]any)["sidebar_settings"] != false {
			t.Fatalf("root did not receive ordinary user page/permissions: %#v", user)
		}
	}

	registeredClient := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	if resp, registration := doJSON(t, registeredClient, http.MethodPost, "/api/user/register", map[string]string{"username": "quota-ten-user", "password": "Password123!"}); resp.StatusCode != http.StatusOK || registration["data"].(map[string]any)["quota"] != float64(newAPIRegisteredUserQuota) {
		t.Fatalf("registered account quota = %d %#v", resp.StatusCode, registration)
	}
	registered, ok := st.FindHoneyUser(security.Fingerprint(cfg.InstanceKey, "quota-ten-user"))
	if !ok || registered.VirtualQuota != newAPIRegisteredUserQuota {
		t.Fatalf("registered account did not receive quota %d: %#v", newAPIRegisteredUserQuota, registered)
	}
	if resp, body := doRawJSON(t, registeredClient, http.MethodGet, "/api/status", nil, nil); resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"quota_display_type":"USD"`) || !strings.Contains(string(body), `"display_in_currency":true`) {
		t.Fatalf("New API USD quota status = %d %s", resp.StatusCode, body)
	}

	resp, tokenResponse := doJSON(t, rootClient, http.MethodPost, "/api/token", map[string]any{"name": "root-monitor-key"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("root key creation failed: %d %#v", resp.StatusCode, tokenResponse)
	}
	rawKey := tokenResponse["data"].(map[string]any)["key"].(string)
	if rawKey == "" {
		t.Fatal("root key creation did not return a one-time key")
	}
	request := map[string]any{"model": "gpt-5.6-sol", "messages": []any{map[string]string{"role": "user", "content": "root-monitoring-marker"}}}
	if resp, _ := doRawJSON(t, rootClient, http.MethodPost, "/v1/chat/completions", request, map[string]string{"Authorization": "Bearer " + rawKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("root key LLM invocation failed: %d", resp.StatusCode)
	}

	events, err := st.Events(-1, model.ProductNewAPI, "")
	if err != nil {
		t.Fatal(err)
	}
	var rejected, loggedIn, keyCreated, keyInvoked *model.Event
	for index := range events {
		event := &events[index]
		if event.Metadata["special_account"] != newAPIRootUsername {
			continue
		}
		switch event.Metadata["root_monitoring_phase"] {
		case "password_attempt_rejected":
			rejected = event
		case "login_success":
			loggedIn = event
		case "key_created":
			keyCreated = event
		case "key_llm_invocation":
			keyInvoked = event
		}
	}
	if rejected == nil || rejected.Score != newAPIRootPasswordScore || loggedIn == nil || loggedIn.Score != newAPIRootLoginScore || keyCreated == nil || keyInvoked == nil || keyInvoked.Score != newAPIRootLLMScore {
		t.Fatalf("root monitoring scores/events incomplete: rejected=%+v login=%+v created=%+v invoked=%+v", rejected, loggedIn, keyCreated, keyInvoked)
	}

	if err := st.TouchHoneyUser(root.ID, func(user *model.HoneyUser) {
		user.VirtualQuota = 1
		user.ResetAt = time.Now().UTC().Add(-time.Minute)
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddToken(model.HoneyToken{ID: "root-reset-token", HoneyUserID: root.ID, Hash: "root-reset-token-hash", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if resp, _ := doRawJSON(t, rootClient, http.MethodGet, "/api/status", nil, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("root reset trigger status = %d", resp.StatusCode)
	}
	resetRoot, ok := st.GetHoneyUser(root.ID)
	if !ok || resetRoot.VirtualQuota != newAPIRootDefaultQuota || resetRoot.PasswordFP != security.Fingerprint(cfg.InstanceKey, newAPIRootPassword) || len(st.ListTokens(root.ID)) != 0 || !resetRoot.ResetAt.After(time.Now().UTC().Add(23*time.Hour)) {
		t.Fatalf("root account was not reset after 24-hour interval: %#v tokens=%#v", resetRoot, st.ListTokens(root.ID))
	}
	if resp, _ := doRawJSON(t, rootClient, http.MethodGet, "/api/user/self", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("root session survived account reset: %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, rootClient, http.MethodPost, "/api/user/login", map[string]string{"username": newAPIRootUsername, "password": newAPIRootPassword}); resp.StatusCode != http.StatusOK {
		t.Fatalf("root could not log in after reset: %d", resp.StatusCode)
	}
}
