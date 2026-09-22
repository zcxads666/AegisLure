package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestIPListAPISettingsAuthenticationAndFilters(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()

	now := time.Now().UTC()
	for _, event := range []model.Event{
		{EventID: "ip-api-low", Product: model.ProductOllama, SourceIP: "192.0.2.10", ObservedAt: now.Add(-2 * time.Hour), Score: 10},
		{EventID: "ip-api-medium", Product: model.ProductVLLM, SourceIP: "192.0.2.11", ObservedAt: now.Add(-72 * time.Hour), Score: 45},
		{EventID: "ip-api-high-recent", Product: model.ProductOllama, SourceIP: "192.0.2.12", ObservedAt: now.Add(-24 * time.Hour), Score: 80},
		{EventID: "ip-api-high-old", Product: model.ProductVLLM, SourceIP: "192.0.2.13", ObservedAt: now.Add(-8 * 24 * time.Hour), Score: 90},
	} {
		if err := st.AppendEvent(event); err != nil {
			t.Fatal(err)
		}
	}

	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	resp, settings := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/ip-list-api", nil)
	if resp.StatusCode != http.StatusOK || settings["enabled"] != false || settings["key_configured"] != false || settings["endpoint"] != "https://admin.test/test-admin-entry/api" {
		t.Fatalf("initial IP list API settings = %d %#v", resp.StatusCode, settings)
	}

	api := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doRawJSON(t, api, http.MethodGet, cfg.AdminPath+"api", nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled IP list API status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}

	resp, enabled := doJSON(t, admin, http.MethodPut, cfg.AdminPath+"admin/api/v1/ip-list-api", map[string]any{"enabled": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enable IP list API status = %d %#v", resp.StatusCode, enabled)
	}
	key, ok := enabled["api_key"].(string)
	if !ok || !strings.HasPrefix(key, ipListAPIKeyPrefix) || enabled["key_configured"] != true {
		t.Fatalf("enable response did not issue a key = %#v", enabled)
	}
	if settingsBody := mustJSONBody(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/ip-list-api", nil); settingsBody["api_key"] != nil {
		t.Fatalf("settings GET exposed the complete key: %#v", settingsBody)
	}

	if resp, _ := doRawJSON(t, api, http.MethodGet, cfg.AdminPath+"api", nil, map[string]string{"X-API-Key": "invalid"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid API key status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	resp, all := ipListAPITestJSON(t, api, cfg.AdminPath+"api", map[string]string{"Authorization": "Bearer " + key})
	if resp.StatusCode != http.StatusOK || all["count"] != float64(4) {
		t.Fatalf("full IP list = %d %#v", resp.StatusCode, all)
	}
	if items, ok := all["items"].([]any); !ok || len(items) != 4 {
		t.Fatalf("full IP list items = %#v", all["items"])
	}

	resp, highRecent := ipListAPITestJSON(t, api, cfg.AdminPath+"api?days=7&risk=high", map[string]string{"X-API-Key": key})
	if resp.StatusCode != http.StatusOK || highRecent["count"] != float64(1) {
		t.Fatalf("recent high-risk IP list = %d %#v", resp.StatusCode, highRecent)
	}
	highItems := highRecent["items"].([]any)
	if highItems[0].(map[string]any)["ip"] != "192.0.2.12" || highItems[0].(map[string]any)["risk_level"] != "high" {
		t.Fatalf("recent high-risk item = %#v", highItems[0])
	}

	resp, medium := ipListAPITestJSON(t, api, cfg.AdminPath+"api?month="+now.In(dashboardShanghaiLocation).Format("2006-01")+"&risk_level=medium", map[string]string{"X-API-Key": key})
	if resp.StatusCode != http.StatusOK || medium["count"] != float64(1) {
		t.Fatalf("monthly medium-risk IP list = %d %#v", resp.StatusCode, medium)
	}
	if filters := medium["filters"].(map[string]any); filters["month"] != now.In(dashboardShanghaiLocation).Format("2006-01") || filters["risk"] != "medium" {
		t.Fatalf("monthly filter metadata = %#v", filters)
	}

	for _, query := range []string{
		"?days=0",
		"?days=7&month=2026-09",
		"?risk=critical",
		"?month=2026-13",
	} {
		resp, body := ipListAPITestJSON(t, api, cfg.AdminPath+"api"+query, map[string]string{"X-API-Key": key})
		if resp.StatusCode != http.StatusBadRequest || body["error"] == nil {
			t.Fatalf("invalid IP list API query %q = %d %#v", query, resp.StatusCode, body)
		}
	}

	resp, rotated := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/ip-list-api/key:rotate", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate IP list API key status = %d %#v", resp.StatusCode, rotated)
	}
	newKey, ok := rotated["api_key"].(string)
	if !ok || newKey == key || rotated["key_configured"] != true {
		t.Fatalf("rotate response = %#v", rotated)
	}
	if resp, _ := doRawJSON(t, api, http.MethodGet, cfg.AdminPath+"api", nil, map[string]string{"X-API-Key": key}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old rotated key status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if resp, _ := doRawJSON(t, api, http.MethodGet, cfg.AdminPath+"api", nil, map[string]string{"X-API-Key": newKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("new rotated key status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if persisted := st.IPListAPIConfig(); !persisted.Enabled || persisted.KeyHash == "" || persisted.KeyPrefix == "" {
		t.Fatalf("persisted IP list API settings = %#v", persisted)
	}
}

func ipListAPITestJSON(t *testing.T, client *inProcessClient, endpoint string, headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	resp, raw := doRawJSON(t, client, http.MethodGet, endpoint, nil, headers)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode IP list API response: %v; raw=%s", err, raw)
	}
	return resp, body
}

func mustJSONBody(t *testing.T, client *inProcessClient, method, endpoint string, value any) map[string]any {
	t.Helper()
	_, body := doJSON(t, client, method, endpoint, value)
	return body
}
