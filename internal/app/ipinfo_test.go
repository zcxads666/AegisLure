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
	client := newGeoIPClient(&config.Config{DataDir: t.TempDir(), GeoIPProvider: config.GeoIPProviderIPInfoAPI, IPInfoLiteToken: "test-token"})
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
	for _, provider := range []string{config.GeoIPProviderIPInfoAPI, config.GeoIPProviderIPInfoLite} {
		provider := provider
		t.Run(provider, func(t *testing.T) {
			client := newGeoIPClient(&config.Config{DataDir: t.TempDir(), GeoIPProvider: provider, IPInfoLiteToken: token})
			defer client.close()
			result := client.resolve("8.8.8.8")
			if result.Status != "ok" || result.Source != provider || result.CountryCode == "" || result.ASN == "" {
				t.Fatalf("live IPinfo %s result = %#v", provider, result)
			}
			if provider == config.GeoIPProviderIPInfoAPI && result.City == "" {
				t.Fatalf("live full IPinfo API did not return city: %#v", result)
			}
		})
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

func TestIPInfoSwitchClearsCachedUnknownAndQueriesAutomatically(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir(), GeoIPProvider: config.GeoIPProviderMaxMind}
	client := newGeoIPClient(cfg)
	defer client.close()

	first := client.resolve("8.8.8.8")
	if first.Status != "fallback_maxmind_unavailable" || first.Country != "未知" {
		t.Fatalf("initial unavailable provider result = %#v", first)
	}
	client.setProvider(config.GeoIPProviderIPInfoAPI)
	if client.endpoint != defaultIPInfoAPIEndpoint {
		t.Fatalf("provider switch did not select full IPinfo endpoint: %q", client.endpoint)
	}

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/lite/8.8.8.8" || r.URL.Query().Get("token") != "new-token" {
			t.Errorf("unexpected switched provider request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country_code":"US","country":"United States","continent_code":"NA","continent":"North America"}`)
	}))
	defer server.Close()
	client.endpoint = server.URL + "/lite/"
	client.setProvider(config.GeoIPProviderIPInfoLite)
	client.setToken("new-token")

	second := client.resolve("8.8.8.8")
	if second.Status != "ok" || second.Country != "United States" || second.Source != config.GeoIPProviderIPInfoLite || requests.Load() != 1 {
		t.Fatalf("provider switch did not re-query cached unknown: result=%#v requests=%d", second, requests.Load())
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
	client.endpoint = server.URL + "/lite/"
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
	client.endpoint = server.URL + "/lite/"
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
	client.endpoint = server.URL + "/lite/"
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
		if r.URL.Path != "/lite/8.8.8.8" {
			t.Fatalf("unexpected dashboard lookup path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country_code":"US","country":"United States","continent":"North America"}`)
	}))
	defer server.Close()
	a.ipInfo.setProvider(config.GeoIPProviderIPInfoLite)
	a.ipInfo.endpoint = server.URL + "/lite/"
	a.ipInfo.setToken("test-token")

	analytics := a.buildDashboardAnalytics(nil, []model.Indicator{{IP: "8.8.8.8", Score: 55}}, time.Now().UTC())
	countries := analytics["source_countries"].([]map[string]any)
	if len(countries) != 1 || countries[0]["name"] != "United States" || countries[0]["country_code"] != "US" || countries[0]["geo_source"] != "ipinfo_lite" {
		t.Fatalf("dashboard IPinfo country aggregation = %#v", countries)
	}
}

func TestMaxMindClientDefaultsToLocalAndFallsBackWhenDatabasesAreMissing(t *testing.T) {
	cfg := &config.Config{DataDir: t.TempDir(), GeoIPProvider: config.GeoIPProviderMaxMind}
	client := newGeoIPClient(cfg)
	defer client.close()
	result := client.resolve("8.8.8.8")
	if result.Source != "offline" || result.Status != "fallback_maxmind_unavailable" || result.Country != "未知" {
		t.Fatalf("missing MaxMind databases should use fallback: %#v", result)
	}
	view := client.settingsView()
	if view["provider"] != config.GeoIPProviderMaxMind || view["configured"] != false {
		t.Fatalf("unexpected default MaxMind settings: %#v", view)
	}
}

func TestIPInfoMMDBClientReadsOfficialSampleWhenPathsProvided(t *testing.T) {
	locationPath := os.Getenv("AEGISLURE_IPINFO_LOCATION_MMDB")
	asnPath := os.Getenv("AEGISLURE_IPINFO_ASN_MMDB")
	if locationPath == "" || asnPath == "" {
		t.Skip("set AEGISLURE_IPINFO_LOCATION_MMDB and AEGISLURE_IPINFO_ASN_MMDB to run the official IPinfo MMDB integration check")
	}
	client := newGeoIPClient(&config.Config{
		DataDir:              t.TempDir(),
		GeoIPProvider:        config.GeoIPProviderIPInfoMMDB,
		IPInfoLocationDBPath: locationPath,
		IPInfoASNDBPath:      asnPath,
	})
	defer client.close()
	result := client.resolve("1.0.0.1")
	if result.Status != "ok" || result.Source != "ipinfo_mmdb" || result.City != "Sydney" || result.CountryCode != "AU" || result.ASN != "AS13335" || result.ASName != "Cloudflare, Inc." {
		t.Fatalf("IPinfo MMDB sample lookup = %#v", result)
	}
	view := client.settingsView()
	if view["provider"] != config.GeoIPProviderIPInfoMMDB || view["configured"] != true {
		t.Fatalf("IPinfo MMDB settings = %#v", view)
	}
}

func TestIPInfoMMDBClientFallsBackWhenDatabasesAreMissing(t *testing.T) {
	client := newGeoIPClient(&config.Config{DataDir: t.TempDir(), GeoIPProvider: config.GeoIPProviderIPInfoMMDB})
	defer client.close()
	result := client.resolve("8.8.8.8")
	if result.Source != "offline" || result.Status != "fallback_ipinfo_mmdb_unavailable" || result.Country != "未知" {
		t.Fatalf("missing IPinfo MMDB fallback = %#v", result)
	}
	view := client.settingsView()
	if view["provider"] != config.GeoIPProviderIPInfoMMDB || view["configured"] != false {
		t.Fatalf("missing IPinfo MMDB settings = %#v", view)
	}
}

func TestAdminIPInfoSwitchRequeriesDashboardAfterUnknown(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/lite/8.8.8.8" {
			t.Errorf("unexpected dashboard re-query path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"country_code":"US","country":"United States","continent_code":"NA","continent":"North America"}`)
	}))
	defer server.Close()
	a.ipInfo.endpoint = server.URL + "/lite/"
	if result := a.resolveIPInfo("8.8.8.8"); result.Status != "fallback_maxmind_unavailable" {
		t.Fatalf("initial dashboard unknown = %#v", result)
	}

	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, a.cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	resp, body := doRawJSON(t, admin, http.MethodPut, a.cfg.AdminPath+"admin/api/v1/ipinfo-lite", map[string]string{"provider": config.GeoIPProviderIPInfoLite, "token": "new-token"}, nil)
	if resp.StatusCode != http.StatusOK || bytes.Contains(body, []byte("new-token")) {
		t.Fatalf("admin provider switch = %d %s", resp.StatusCode, body)
	}
	analytics := a.buildDashboardAnalytics(nil, []model.Indicator{{IP: "8.8.8.8", Score: 55}}, time.Now().UTC())
	countries := analytics["source_countries"].([]map[string]any)
	if len(countries) != 1 || countries[0]["name"] != "United States" || countries[0]["geo_source"] != config.GeoIPProviderIPInfoLite || requests.Load() != 1 {
		t.Fatalf("dashboard did not auto-query after provider switch: countries=%#v requests=%d", countries, requests.Load())
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
	if err := json.Unmarshal(body, &initial); err != nil || initial["provider"] != config.GeoIPProviderMaxMind || initial["configured"] != false || initial["masked_token"] != "" {
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

	resp, body = doRawJSON(t, admin, http.MethodPut, a.cfg.AdminPath+"admin/api/v1/ipinfo-lite", map[string]string{"provider": config.GeoIPProviderMaxMind}, nil)
	if resp.StatusCode != http.StatusOK || bytes.Contains(body, []byte(token)) {
		t.Fatalf("switched MaxMind settings response = %d %s", resp.StatusCode, body)
	}
	var switched map[string]any
	if err := json.Unmarshal(body, &switched); err != nil || switched["provider"] != config.GeoIPProviderMaxMind || switched["configured"] != false {
		t.Fatalf("switched MaxMind settings = %s", body)
	}
}
