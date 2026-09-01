package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestIPInfoClientUsesLiteResponseAndCachesPublicLookup(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/lite/8.8.8.8" || r.URL.Query().Get("token") != "test-token" {
			t.Fatalf("unexpected IPinfo request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ip":"8.8.8.8","asn":"AS15169","as_name":"Google LLC","as_domain":"google.com","country_code":"US","country":"United States","continent_code":"NA","continent":"North America"}`)
	}))
	defer server.Close()

	client := newIPInfoClient("test-token")
	client.endpoint = server.URL + "/lite/"
	first := client.resolve("8.8.8.8")
	second := client.resolve("8.8.8.8")
	if first.Country != "United States" || first.CountryCode != "US" || first.Source != "ipinfo_lite" || first.Status != "ok" {
		t.Fatalf("unexpected IPinfo result: %#v", first)
	}
	if second != first || requests.Load() != 1 {
		t.Fatalf("IPinfo cache not used: second=%#v requests=%d", second, requests.Load())
	}

	local := client.resolve("127.0.0.1")
	if local.Country != "本地/保留" || local.Source != "offline" || requests.Load() != 1 {
		t.Fatalf("local address should not call IPinfo: %#v requests=%d", local, requests.Load())
	}
}

func TestIPInfoClientFallsBackForMissingTokenAndProviderFailure(t *testing.T) {
	noToken := newIPInfoClient("")
	result := noToken.resolve("8.8.8.8")
	if result.Country != "未知" || result.Status != "fallback_unconfigured" || result.Source != "offline" {
		t.Fatalf("missing-token fallback = %#v", result)
	}
	invalid := noToken.resolve("not-an-ip")
	if invalid.Status != "fallback_invalid" || invalid.Country != "未知" {
		t.Fatalf("invalid-address fallback = %#v", invalid)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	failing := newIPInfoClient("test-token")
	failing.endpoint = server.URL + "/lite/"
	first := failing.resolve("1.1.1.1")
	second := failing.resolve("1.1.1.1")
	if first.Status != "fallback_error" || second.Status != "fallback_error" || requests.Load() != 1 {
		t.Fatalf("provider failure fallback/cache = first=%#v second=%#v requests=%d", first, second, requests.Load())
	}
}

func TestDashboardSourceCountryUsesIPInfoAndKeepsFallbackMetadata(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lite/8.8.8.8" {
			t.Fatalf("unexpected dashboard lookup path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country_code":"US","country":"United States","continent":"North America"}`)
	}))
	defer server.Close()
	a.ipInfo.endpoint = server.URL + "/lite/"
	a.ipInfo.setToken("test-token")

	analytics := a.buildDashboardAnalytics(nil, []model.Indicator{{IP: "8.8.8.8", Score: 55}}, time.Now().UTC())
	countries := analytics["source_countries"].([]map[string]any)
	if len(countries) != 1 || countries[0]["name"] != "United States" || countries[0]["country_code"] != "US" || countries[0]["geo_source"] != "ipinfo_lite" {
		t.Fatalf("dashboard IPinfo country aggregation = %#v", countries)
	}
}

func TestAdminIPInfoSettingsPersistsAndDoesNotReturnRawToken(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, a.cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}

	resp, body := doRawJSON(t, admin, http.MethodGet, a.cfg.AdminPath+"admin/api/v1/ipinfo-lite", nil, nil)
	if resp.StatusCode != http.StatusOK || bytes.Contains(body, []byte("test-ipinfo-secret")) {
		t.Fatalf("initial IPinfo settings response = %d %s", resp.StatusCode, body)
	}
	var initial map[string]any
	if err := json.Unmarshal(body, &initial); err != nil || initial["configured"] != false || initial["masked_token"] != "" {
		t.Fatalf("initial IPinfo settings = %s", body)
	}

	const token = "test-ipinfo-secret"
	resp, body = doRawJSON(t, admin, http.MethodPut, a.cfg.AdminPath+"admin/api/v1/ipinfo-lite", map[string]string{"token": token}, nil)
	if resp.StatusCode != http.StatusOK || bytes.Contains(body, []byte(token)) {
		t.Fatalf("saved IPinfo settings response = %d %s", resp.StatusCode, body)
	}
	var saved map[string]any
	if err := json.Unmarshal(body, &saved); err != nil || saved["configured"] != true || saved["masked_token"] != "********cret" {
		t.Fatalf("saved IPinfo settings = %s", body)
	}
	configPath := os.Getenv("HP_CONFIG")
	configBytes, err := os.ReadFile(configPath)
	if err != nil || !bytes.Contains(configBytes, []byte(token)) {
		t.Fatalf("IPinfo token was not persisted to config: err=%v contents=%s", err, configBytes)
	}
	info, err := os.Stat(configPath)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %v, err=%v", info.Mode().Perm(), err)
	}

	resp, body = doRawJSON(t, admin, http.MethodPut, a.cfg.AdminPath+"admin/api/v1/ipinfo-lite", map[string]string{"token": ""}, nil)
	if resp.StatusCode != http.StatusOK || bytes.Contains(body, []byte(token)) {
		t.Fatalf("cleared IPinfo settings response = %d %s", resp.StatusCode, body)
	}
	var cleared map[string]any
	if err := json.Unmarshal(body, &cleared); err != nil || cleared["configured"] != false || cleared["masked_token"] != "" {
		t.Fatalf("cleared IPinfo settings = %s", body)
	}
}
