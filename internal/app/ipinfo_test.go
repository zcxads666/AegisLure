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

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/model"
)

func TestIPInfoClientUsesAPIResponseAndCachesPublicLookup(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/8.8.8.8" || r.URL.Query().Get("token") != "test-token" {
			t.Fatalf("unexpected IPinfo request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ip":"8.8.8.8","city":"Mountain View","region":"California","country":"US","country_name":"United States","loc":"38.0088,-122.1175","org":"AS15169 Google LLC","postal":"94043","timezone":"America/Los_Angeles"}`)
	}))
	defer server.Close()

	client := newIPInfoClient("test-token")
	client.endpoint = server.URL + "/"
	first := client.resolve("8.8.8.8")
	second := client.resolve("8.8.8.8")
	if first.Country != "United States" || first.CountryCode != "US" || first.Source != config.GeoIPProviderIPInfoAPI || first.Status != "ok" {
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

func TestIPInfoClientUsesFullAPIResponseForCityAndASN(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/8.8.8.8" || r.URL.Query().Get("token") != "test-token" || r.Header.Get("Accept") != "application/json" {
			t.Errorf("unexpected full IPinfo request: %s?%s accept=%s", r.URL.Path, r.URL.RawQuery, r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ip":"8.8.8.8","city":"Mountain View","region":"California","country":"US","loc":"38.0088,-122.1175","org":"AS15169 Google LLC","postal":"94043","timezone":"America/Los_Angeles"}`)
	}))
	defer server.Close()
	client := newGeoIPClient(&config.Config{DataDir: t.TempDir(), GeoIPProvider: config.GeoIPProviderIPInfoAPI, IPInfoToken: "test-token"})
	defer client.close()
	if client.endpoint != defaultIPInfoAPIEndpoint {
		t.Fatalf("full IPinfo provider endpoint = %q", client.endpoint)
	}
	client.endpoint = server.URL + "/"
	result := client.resolve("8.8.8.8")
	if result.Status != "ok" || result.Source != config.GeoIPProviderIPInfoAPI || result.City != "Mountain View" || result.CountryCode != "US" || result.Country != "US" || result.ASN != "AS15169" || result.ASName != "Google LLC" || result.PostalCode != "94043" || result.Latitude != 38.0088 || result.Longitude != -122.1175 || requests.Load() != 1 {
		t.Fatalf("full IPinfo result = %#v requests=%d", result, requests.Load())
	}
}

func TestIPInfoLiveProvidersWithConfiguredToken(t *testing.T) {
	token := os.Getenv("AEGISLURE_IPINFO_LIVE_TOKEN")
	if token == "" {
		t.Skip("set AEGISLURE_IPINFO_LIVE_TOKEN to run the live IPinfo API check")
	}
	client := newGeoIPClient(&config.Config{DataDir: t.TempDir(), GeoIPProvider: config.GeoIPProviderIPInfoAPI, IPInfoToken: token})
	defer client.close()
	result := client.resolve("8.8.8.8")
	if result.Status != "ok" || result.Source != config.GeoIPProviderIPInfoAPI || result.CountryCode == "" || result.ASN == "" || result.City == "" {
		t.Fatalf("live IPinfo API result = %#v", result)
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
	failing.endpoint = server.URL + "/"
	first := failing.resolve("1.1.1.1")
	second := failing.resolve("1.1.1.1")
	if first.Status != "fallback_error" || second.Status != "fallback_error" || requests.Load() != 1 {
		t.Fatalf("provider failure fallback/cache = first=%#v second=%#v requests=%d", first, second, requests.Load())
	}
}

func TestIPInfoTokenSwitchClearsCachedUnknownAndQueriesAutomatically(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir(), GeoIPProvider: config.GeoIPProviderIPInfoAPI}
	client := newGeoIPClient(cfg)
	defer client.close()

	first := client.resolve("8.8.8.8")
	if first.Status != "fallback_unconfigured" || first.Country != "未知" {
		t.Fatalf("initial unavailable provider result = %#v", first)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/8.8.8.8" || r.URL.Query().Get("token") != "new-token" {
			t.Errorf("unexpected switched API request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country":"US","country_name":"United States","continent_code":"NA","continent":"North America"}`)
	}))
	defer server.Close()
	client.endpoint = server.URL + "/"
	client.setToken("new-token")

	second := client.resolve("8.8.8.8")
	if second.Status != "ok" || second.Country != "United States" || second.Source != config.GeoIPProviderIPInfoAPI || requests.Load() != 1 {
		t.Fatalf("token switch did not re-query cached unknown: result=%#v requests=%d", second, requests.Load())
	}
}

func TestIPInfoTokenRotationClearsCachedFailure(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("token") == "old-token" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country_code":"AU","country":"Australia","continent_code":"OC","continent":"Oceania"}`)
	}))
	defer server.Close()
	client := newIPInfoClient("old-token")
	defer client.close()
	client.endpoint = server.URL + "/"
	if result := client.resolve("1.1.1.1"); result.Status != "fallback_error" {
		t.Fatalf("initial API failure = %#v", result)
	}
	client.setToken("new-token")
	result := client.resolve("1.1.1.1")
	if result.Status != "ok" || result.CountryCode != "AU" || requests.Load() != 2 {
		t.Fatalf("token rotation did not re-query cached failure: result=%#v requests=%d", result, requests.Load())
	}
}

func TestIPInfoFailureCacheRetriesAfterExpiry(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country_code":"JP","country":"Japan","continent_code":"AS","continent":"Asia"}`)
	}))
	defer server.Close()
	client := newIPInfoClient("test-token")
	defer client.close()
	client.endpoint = server.URL + "/"
	if result := client.resolve("9.9.9.9"); result.Status != "fallback_error" {
		t.Fatalf("initial failure = %#v", result)
	}
	client.mu.Lock()
	entry := client.cache["9.9.9.9"]
	entry.ExpiresAt = time.Now().Add(-time.Second)
	client.cache["9.9.9.9"] = entry
	client.mu.Unlock()
	result := client.resolve("9.9.9.9")
	if result.Status != "ok" || result.Country != "Japan" || requests.Load() != 2 {
		t.Fatalf("expired failure was not retried: result=%#v requests=%d", result, requests.Load())
	}
}

func TestIPInfoClientSkipsNonPublicAddresses(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country_code":"US","country":"United States"}`)
	}))
	defer server.Close()
	client := newIPInfoClient("test-token")
	defer client.close()
	client.endpoint = server.URL + "/"
	for _, rawIP := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1", "2001:db8::1"} {
		result := client.resolve(rawIP)
		if result.Source != "offline" || requests.Load() != 0 {
			t.Fatalf("non-public address reached API: ip=%s result=%#v requests=%d", rawIP, result, requests.Load())
		}
	}
}

func TestDashboardSourceCountryUsesIPInfoAndKeepsFallbackMetadata(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/8.8.8.8" {
			t.Fatalf("unexpected dashboard lookup path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country_code":"US","country":"United States","continent":"North America"}`)
	}))
	defer server.Close()
	a.ipInfo.setProvider(config.GeoIPProviderIPInfoAPI)
	a.ipInfo.endpoint = server.URL + "/"
	a.ipInfo.setToken("test-token")

	analytics := a.buildDashboardAnalytics(nil, []model.Indicator{{IP: "8.8.8.8", Score: 55}}, time.Now().UTC())
	countries := analytics["source_countries"].([]map[string]any)
	if len(countries) != 1 || countries[0]["name"] != "美国" || countries[0]["country_code"] != "US" || countries[0]["geo_source"] != config.GeoIPProviderIPInfoAPI {
		t.Fatalf("dashboard IPinfo country aggregation = %#v", countries)
	}
}

func TestAdminIPInfoSwitchRequeriesDashboardAfterUnknown(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/8.8.8.8" {
			t.Errorf("unexpected dashboard re-query path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country_code":"US","country":"United States","continent_code":"NA","continent":"North America"}`)
	}))
	defer server.Close()
	a.ipInfo.endpoint = server.URL + "/"
	if result := a.resolveIPInfo("8.8.8.8"); result.Status != "fallback_unconfigured" {
		t.Fatalf("initial dashboard unknown = %#v", result)
	}
	a.ipInfo.endpoint = server.URL + "/"

	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, a.cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	resp, body := doRawJSON(t, admin, http.MethodPut, a.cfg.AdminPath+"admin/api/v1/ipinfo", map[string]string{"provider": config.GeoIPProviderIPInfoAPI, "token": "new-token"}, nil)
	if resp.StatusCode != http.StatusOK || bytes.Contains(body, []byte("new-token")) {
		t.Fatalf("admin provider switch = %d %s", resp.StatusCode, body)
	}
	analytics := a.buildDashboardAnalytics(nil, []model.Indicator{{IP: "8.8.8.8", Score: 55}}, time.Now().UTC())
	countries := analytics["source_countries"].([]map[string]any)
	if len(countries) != 1 || countries[0]["name"] != "美国" || countries[0]["geo_source"] != config.GeoIPProviderIPInfoAPI || requests.Load() != 2 {
		t.Fatalf("dashboard did not auto-query after provider switch: countries=%#v requests=%d", countries, requests.Load())
	}
}

func TestAdminIndicatorsRequeriesHistoricalIPsAndReturnsGeoFields(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	now := time.Now().UTC()
	for _, ip := range []string{"8.8.8.8", "1.1.1.1"} {
		if err := st.AppendEvent(model.Event{EventID: "historical-" + ip, Product: model.ProductOllama, SourceIP: ip, ObservedAt: now, Score: 80}); err != nil {
			t.Fatalf("append historical indicator %s: %v", ip, err)
		}
	}
	if result := a.resolveIPInfo("8.8.8.8"); result.Status != "fallback_unconfigured" {
		t.Fatalf("historical IP should initially be unknown: %#v", result)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("token") != "test-token" {
			t.Errorf("historical lookup did not use configured token: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/8.8.8.8":
			_, _ = io.WriteString(w, `{"city":"Mountain View","region":"California","country":"US","loc":"38.0088,-122.1175","org":"AS15169 Google LLC"}`)
		case "/1.1.1.1":
			_, _ = io.WriteString(w, `{"city":"Sydney","region":"New South Wales","country":"AU","loc":"-33.86785,151.20732","org":"AS13335 Cloudflare, Inc."}`)
		default:
			t.Errorf("unexpected historical lookup path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	a.ipInfo.setProvider(config.GeoIPProviderIPInfoAPI)
	a.ipInfo.endpoint = server.URL + "/"
	a.ipInfo.setToken("test-token")

	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	resp, body := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("historical indicator list status = %d %#v", resp.StatusCode, body)
	}
	items, ok := body["items"].([]any)
	if !ok || len(items) != 2 || requests.Load() != 2 {
		t.Fatalf("historical indicator list did not query every IP: items=%#v requests=%d", body["items"], requests.Load())
	}
	byIP := make(map[string]map[string]any, len(items))
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("indicator item type = %#v", raw)
		}
		byIP[item["ip"].(string)] = item
	}
	for ip, expected := range map[string]map[string]string{
		"8.8.8.8": {"country": "US", "country_code": "US", "city": "Mountain View", "asn": "AS15169"},
		"1.1.1.1": {"country": "AU", "country_code": "AU", "city": "Sydney", "asn": "AS13335"},
	} {
		item, ok := byIP[ip]
		if !ok {
			t.Fatalf("missing historical indicator %s: %#v", ip, byIP)
		}
		for field, value := range expected {
			if item[field] != value {
				t.Fatalf("historical indicator %s field %s = %#v, want %q; item=%#v", ip, field, item[field], value, item)
			}
		}
		if item["geo_source"] != config.GeoIPProviderIPInfoAPI || item["geo_status"] != "ok" {
			t.Fatalf("historical indicator %s geo metadata = %#v", ip, item)
		}
	}
}

func TestAdminIPInfoSettingsPersistsAndDoesNotReturnRawToken(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, a.cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	const token = "test-ipinfo-secret"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/8.8.8.8" || r.URL.Query().Get("token") != token {
			t.Errorf("unexpected key verification request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country":"US","country_name":"United States","city":"Mountain View"}`)
	}))
	defer server.Close()
	a.ipInfo.endpoint = server.URL + "/"

	resp, body := doRawJSON(t, admin, http.MethodGet, a.cfg.AdminPath+"admin/api/v1/ipinfo", nil, nil)
	if resp.StatusCode != http.StatusOK || bytes.Contains(body, []byte(token)) {
		t.Fatalf("initial IPinfo settings response = %d %s", resp.StatusCode, body)
	}
	var initial map[string]any
	if err := json.Unmarshal(body, &initial); err != nil || initial["provider"] != config.GeoIPProviderIPInfoAPI || initial["configured"] != false || initial["masked_token"] != "" {
		t.Fatalf("initial IPinfo settings = %s", body)
	}
	available, ok := initial["available_providers"].([]any)
	if !ok || len(available) != 1 {
		t.Fatalf("unexpected available providers: %#v", initial["available_providers"])
	}
	providerOption, ok := available[0].(map[string]any)
	if !ok || providerOption["id"] != config.GeoIPProviderIPInfoAPI {
		t.Fatalf("unexpected available provider option: %#v", available[0])
	}
	if _, ok := initial["maxmind"]; ok {
		t.Fatal("settings should not expose MaxMind configuration")
	}
	if _, ok := initial["ipinfo_mmdb"]; ok {
		t.Fatal("settings should not expose IPinfo MMDB configuration")
	}

	resp, body = doRawJSON(t, admin, http.MethodPut, a.cfg.AdminPath+"admin/api/v1/ipinfo", map[string]string{"provider": config.GeoIPProviderIPInfoAPI, "token": token}, nil)
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

	resp, body = doRawJSON(t, admin, http.MethodPut, a.cfg.AdminPath+"admin/api/v1/ipinfo", map[string]string{"token": ""}, nil)
	if resp.StatusCode != http.StatusOK || bytes.Contains(body, []byte(token)) {
		t.Fatalf("cleared IPinfo settings response = %d %s", resp.StatusCode, body)
	}
	var cleared map[string]any
	if err := json.Unmarshal(body, &cleared); err != nil || cleared["configured"] != false || cleared["masked_token"] != "" {
		t.Fatalf("cleared IPinfo settings = %s", body)
	}

	if requests.Load() != 1 {
		t.Fatalf("saving a key should verify 8.8.8.8 exactly once: requests=%d", requests.Load())
	}
	for _, unsupported := range []string{"unsupported", "maxmind", "ipinfo_lite", "ipinfo_mmdb"} {
		resp, body = doRawJSON(t, admin, http.MethodPut, a.cfg.AdminPath+"admin/api/v1/ipinfo", map[string]string{"provider": unsupported}, nil)
		if resp.StatusCode != http.StatusBadRequest || !bytes.Contains(body, []byte("provider must be ipinfo_api")) {
			t.Fatalf("unsupported provider %q response = %d %s", unsupported, resp.StatusCode, body)
		}
	}
}

func TestAdminIPInfoKeyVerificationRejectsFailureWithoutOverwritingConfig(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	configPath := os.Getenv("HP_CONFIG")
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	const token = "bad-ipinfo-secret"
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/8.8.8.8" {
			t.Errorf("unexpected key verification path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	a.ipInfo.endpoint = server.URL + "/"

	resp, body := doRawJSON(t, admin, http.MethodPut, cfg.AdminPath+"admin/api/v1/ipinfo", map[string]string{"provider": config.GeoIPProviderIPInfoAPI, "token": token}, nil)
	if resp.StatusCode != http.StatusBadGateway || !bytes.Contains(body, []byte("8.8.8.8")) || bytes.Contains(body, []byte(token)) {
		t.Fatalf("failed key verification response = %d %s", resp.StatusCode, body)
	}
	if requests.Load() != 1 || a.ipInfo.token != "" {
		t.Fatalf("failed verification changed runtime state: requests=%d token=%q", requests.Load(), a.ipInfo.token)
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(configBytes, []byte(token)) {
		t.Fatalf("failed key was persisted: %s", configBytes)
	}
}
