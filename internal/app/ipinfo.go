package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	geoip2 "github.com/oschwald/geoip2-golang/v2"
	"github.com/zcxads666/AegisLure/internal/config"
)

const (
	defaultIPInfoLiteEndpoint = "https://api.ipinfo.io/lite/"
	maxMindSource             = "maxmind_geolite2"
	ipInfoLookupTimeout       = 2 * time.Second
	ipInfoDashboardTimeout    = 4 * time.Second
	ipInfoCacheTTL            = 24 * time.Hour
	ipInfoFailureCacheTTL     = 5 * time.Minute
	ipInfoMaxTokenLength      = 256
	ipInfoMaxDashboardIPs     = 128
	ipInfoWorkers             = 6
)

type ipInfoResult struct {
	IP            string `json:"ip"`
	ASN           string `json:"asn,omitempty"`
	ASName        string `json:"as_name,omitempty"`
	ASDomain      string `json:"as_domain,omitempty"`
	CountryCode   string `json:"country_code,omitempty"`
	Country       string `json:"country,omitempty"`
	ContinentCode string `json:"continent_code,omitempty"`
	Continent     string `json:"continent,omitempty"`
	Source        string `json:"source"`
	Status        string `json:"status"`
}

type ipInfoLiteResponse struct {
	IP            string `json:"ip"`
	ASN           string `json:"asn"`
	ASName        string `json:"as_name"`
	ASDomain      string `json:"as_domain"`
	CountryCode   string `json:"country_code"`
	Country       string `json:"country"`
	ContinentCode string `json:"continent_code"`
	Continent     string `json:"continent"`
}

type ipInfoCacheEntry struct {
	Result    ipInfoResult
	ExpiresAt time.Time
}

type ipInfoClient struct {
	mu         sync.Mutex
	provider   string
	token      string
	generation uint64
	cache      map[string]ipInfoCacheEntry
	httpClient *http.Client
	endpoint   string
	cityDB     *geoip2.Reader
	asnDB      *geoip2.Reader
	cityDBPath string
	asnDBPath  string
}

// newIPInfoClient is kept for tests and compatibility with the previous
// client constructor. Production App instances use newGeoIPClient so the
// default provider is local MaxMind GeoLite2.
func newIPInfoClient(token string) *ipInfoClient {
	return newGeoIPClient(&config.Config{
		GeoIPProvider:   config.GeoIPProviderIPInfoLite,
		IPInfoLiteToken: token,
	})
}

func newGeoIPClient(cfg *config.Config) *ipInfoClient {
	provider := config.GeoIPProviderMaxMind
	token := ""
	cityPath, asnPath := "", ""
	if cfg != nil {
		if normalized, ok := normalizeGeoIPProvider(cfg.GeoIPProvider); ok {
			provider = normalized
		}
		token = strings.TrimSpace(cfg.IPInfoLiteToken)
		cityPath, asnPath = cfg.GeoIPDatabasePaths()
	}
	cityDB := openMaxMindReader(cityPath)
	asnDB := openMaxMindReader(asnPath)
	return &ipInfoClient{
		provider:   provider,
		token:      token,
		cache:      make(map[string]ipInfoCacheEntry),
		httpClient: newIPInfoHTTPClient(),
		endpoint:   defaultIPInfoLiteEndpoint,
		cityDB:     cityDB,
		asnDB:      asnDB,
		cityDBPath: cityPath,
		asnDBPath:  asnPath,
	}
}

func newIPInfoHTTPClient() *http.Client {
	return &http.Client{
		Timeout: ipInfoLookupTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func normalizeGeoIPProvider(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", config.GeoIPProviderMaxMind:
		return config.GeoIPProviderMaxMind, true
	case config.GeoIPProviderIPInfoLite, "ipinfo", "ipinfo-lite":
		return config.GeoIPProviderIPInfoLite, true
	default:
		return "", false
	}
}

func openMaxMindReader(path string) *geoip2.Reader {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() == 0 || info.Size() > 1<<30 {
		return nil
	}
	reader, err := geoip2.Open(path)
	if err != nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil
	}
	return reader
}

func (c *ipInfoClient) setProvider(provider string) {
	if c == nil {
		return
	}
	normalized, ok := normalizeGeoIPProvider(provider)
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider == normalized {
		return
	}
	c.provider = normalized
	c.generation++
	c.cache = make(map[string]ipInfoCacheEntry)
}

func (c *ipInfoClient) setToken(token string) {
	if c == nil {
		return
	}
	token = strings.TrimSpace(token)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == token {
		return
	}
	c.token = token
	c.generation++
	// A response obtained with the previous token must never be served after
	// the administrator changes the provider credential.
	c.cache = make(map[string]ipInfoCacheEntry)
}

func (c *ipInfoClient) settingsView() map[string]any {
	provider := config.GeoIPProviderMaxMind
	token := ""
	endpoint := defaultIPInfoLiteEndpoint
	cityDBAvailable := false
	asnDBAvailable := false
	cityDBPath, asnDBPath := "", ""
	if c != nil {
		c.mu.Lock()
		provider = c.provider
		token = c.token
		endpoint = c.endpoint
		cityDBAvailable = c.cityDB != nil
		asnDBAvailable = c.asnDB != nil
		cityDBPath = c.cityDBPath
		asnDBPath = c.asnDBPath
		c.mu.Unlock()
	}
	maxMindReady := cityDBAvailable && asnDBAvailable
	configured := (provider == config.GeoIPProviderMaxMind && maxMindReady) || (provider == config.GeoIPProviderIPInfoLite && token != "")
	return map[string]any{
		"provider":                  provider,
		"provider_label":            geoIPProviderLabel(provider),
		"available_providers":       geoIPProviderOptions(),
		"configured":                configured,
		"enabled":                   configured,
		"masked_token":              maskIPInfoToken(token),
		"ipinfo_configured":         token != "",
		"endpoint":                  endpoint,
		"timeout_seconds":           int(ipInfoLookupTimeout / time.Second),
		"cache_ttl_seconds":         int(ipInfoCacheTTL / time.Second),
		"failure_cache_ttl_seconds": int(ipInfoFailureCacheTTL / time.Second),
		"dashboard_lookup_limit":    ipInfoMaxDashboardIPs,
		"fallback":                  "本地/保留地址离线识别；当前查询不可用时显示未知",
		"maxmind": map[string]any{
			"ready":          maxMindReady,
			"city_available": cityDBAvailable,
			"asn_available":  asnDBAvailable,
			"city_file":      databaseFileName(cityDBPath),
			"asn_file":       databaseFileName(asnDBPath),
		},
	}
}

func geoIPProviderLabel(provider string) string {
	if provider == config.GeoIPProviderIPInfoLite {
		return "IPinfo Lite API"
	}
	return "MaxMind GeoLite2 City + ASN"
}

func geoIPProviderOptions() []map[string]any {
	return []map[string]any{
		{"id": config.GeoIPProviderMaxMind, "label": geoIPProviderLabel(config.GeoIPProviderMaxMind)},
		{"id": config.GeoIPProviderIPInfoLite, "label": geoIPProviderLabel(config.GeoIPProviderIPInfoLite)},
	}
}

func databaseFileName(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	name := filepath.Base(path)
	if name == "." || name == string(filepath.Separator) {
		return ""
	}
	return name
}

func maskIPInfoToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 4 {
		return "********"
	}
	return "********" + token[len(token)-4:]
}

func (c *ipInfoClient) resolve(rawIP string) ipInfoResult {
	ctx, cancel := context.WithTimeout(context.Background(), ipInfoLookupTimeout)
	defer cancel()
	return c.resolveContext(ctx, rawIP)
}

func (c *ipInfoClient) resolveContext(ctx context.Context, rawIP string) ipInfoResult {
	trimmed := strings.TrimSpace(rawIP)
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return fallbackIPInfo(trimmed, "fallback_invalid")
	}
	canonical := ip.String()
	if sourceCountryLabel(canonical) != "未知" {
		return fallbackIPInfo(canonical, "offline")
	}
	if c == nil {
		return fallbackIPInfo(canonical, "fallback_unconfigured")
	}

	now := time.Now()
	c.mu.Lock()
	if cached, ok := c.cache[canonical]; ok && now.Before(cached.ExpiresAt) {
		c.mu.Unlock()
		return cached.Result
	}
	provider := c.provider
	token := c.token
	generation := c.generation
	endpoint := c.endpoint
	client := c.httpClient
	cityDB := c.cityDB
	asnDB := c.asnDB
	c.mu.Unlock()

	if provider == config.GeoIPProviderMaxMind {
		addr, err := netip.ParseAddr(canonical)
		if err != nil {
			return fallbackIPInfo(canonical, "fallback_invalid")
		}
		return c.resolveMaxMind(canonical, addr, generation, cityDB, asnDB)
	}
	return c.resolveIPInfo(ctx, canonical, token, generation, endpoint, client)
}

func (c *ipInfoClient) resolveMaxMind(canonical string, addr netip.Addr, generation uint64, cityDB, asnDB *geoip2.Reader) ipInfoResult {
	if cityDB == nil && asnDB == nil {
		return c.cacheFailure(canonical, "fallback_maxmind_unavailable", generation)
	}
	result := ipInfoResult{IP: canonical, Source: maxMindSource, Status: "partial"}
	cityFound, asnFound := false, false
	if cityDB != nil {
		if record, err := cityDB.City(addr); err == nil && record != nil && record.HasData() {
			result.CountryCode = strings.TrimSpace(record.Country.ISOCode)
			result.Country = strings.TrimSpace(record.Country.Names.English)
			result.ContinentCode = strings.TrimSpace(record.Continent.Code)
			result.Continent = strings.TrimSpace(record.Continent.Names.English)
			cityFound = result.CountryCode != "" || result.Country != "" || result.ContinentCode != "" || result.Continent != ""
		}
	}
	if asnDB != nil {
		if record, err := asnDB.ASN(addr); err == nil && record != nil && record.HasData() {
			if record.AutonomousSystemNumber != 0 {
				result.ASN = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
			}
			result.ASName = strings.TrimSpace(record.AutonomousSystemOrganization)
			asnFound = result.ASN != "" || result.ASName != ""
		}
	}
	if !cityFound && !asnFound {
		return c.cacheFailure(canonical, "fallback_maxmind_not_found", generation)
	}
	if cityFound && asnFound {
		result.Status = "ok"
	}
	c.cacheResult(canonical, result, ipInfoCacheTTL, generation)
	return result
}

func (c *ipInfoClient) resolveIPInfo(ctx context.Context, canonical, token string, generation uint64, endpoint string, client *http.Client) ipInfoResult {
	if token == "" {
		result := fallbackIPInfo(canonical, "fallback_unconfigured")
		c.cacheResult(canonical, result, ipInfoFailureCacheTTL, generation)
		return result
	}
	if endpoint == "" {
		endpoint = defaultIPInfoLiteEndpoint
	}
	if client == nil {
		client = http.DefaultClient
	}

	requestURL := strings.TrimRight(endpoint, "/") + "/" + url.PathEscape(canonical)
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return c.cacheFailure(canonical, "fallback_error", generation)
	}
	query := parsedURL.Query()
	query.Set("token", token)
	parsedURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return c.cacheFailure(canonical, "fallback_error", generation)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "AegisLure-IPinfo-Lite/1.0")
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return fallbackIPInfo(canonical, "fallback_timeout")
		}
		return c.cacheFailure(canonical, "fallback_error", generation)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if ctx.Err() != nil {
			return fallbackIPInfo(canonical, "fallback_timeout")
		}
		return c.cacheFailure(canonical, "fallback_error", generation)
	}
	var payload ipInfoLiteResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16*1024))
	if err := decoder.Decode(&payload); err != nil || strings.TrimSpace(payload.Country) == "" && strings.TrimSpace(payload.CountryCode) == "" && strings.TrimSpace(payload.Continent) == "" && strings.TrimSpace(payload.ContinentCode) == "" {
		if ctx.Err() != nil {
			return fallbackIPInfo(canonical, "fallback_timeout")
		}
		return c.cacheFailure(canonical, "fallback_error", generation)
	}
	result := ipInfoResult{
		IP:            canonical,
		ASN:           strings.TrimSpace(payload.ASN),
		ASName:        strings.TrimSpace(payload.ASName),
		ASDomain:      strings.TrimSpace(payload.ASDomain),
		CountryCode:   strings.TrimSpace(payload.CountryCode),
		Country:       strings.TrimSpace(payload.Country),
		ContinentCode: strings.TrimSpace(payload.ContinentCode),
		Continent:     strings.TrimSpace(payload.Continent),
		Source:        config.GeoIPProviderIPInfoLite,
		Status:        "ok",
	}
	c.cacheResult(canonical, result, ipInfoCacheTTL, generation)
	return result
}

func (c *ipInfoClient) cacheFailure(canonical, status string, generation uint64) ipInfoResult {
	result := fallbackIPInfo(canonical, status)
	c.cacheResult(canonical, result, ipInfoFailureCacheTTL, generation)
	return result
}

func (c *ipInfoClient) cacheResult(canonical string, result ipInfoResult, ttl time.Duration, generation uint64) {
	if c == nil || ttl <= 0 {
		return
	}
	c.mu.Lock()
	if generation != c.generation {
		c.mu.Unlock()
		return
	}
	c.cache[canonical] = ipInfoCacheEntry{Result: result, ExpiresAt: time.Now().Add(ttl)}
	c.mu.Unlock()
}

func (c *ipInfoClient) lookupMany(rawIPs []string) map[string]ipInfoResult {
	results := make(map[string]ipInfoResult, len(rawIPs))
	if c == nil {
		for _, rawIP := range rawIPs {
			results[rawIP] = fallbackIPInfo(rawIP, "fallback_unconfigured")
		}
		return results
	}
	unique := make([]string, 0, len(rawIPs))
	seen := make(map[string]bool, len(rawIPs))
	for _, rawIP := range rawIPs {
		key := strings.TrimSpace(rawIP)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, key)
	}
	if len(unique) > ipInfoMaxDashboardIPs {
		for _, key := range unique[ipInfoMaxDashboardIPs:] {
			results[key] = fallbackIPInfo(key, "fallback_limit")
		}
		unique = unique[:ipInfoMaxDashboardIPs]
	}
	ctx, cancel := context.WithTimeout(context.Background(), ipInfoDashboardTimeout)
	defer cancel()
	jobs := make(chan string, len(unique))
	for _, key := range unique {
		jobs <- key
	}
	close(jobs)
	var resultsMu sync.Mutex
	var workers sync.WaitGroup
	workerCount := len(unique)
	if workerCount > ipInfoWorkers {
		workerCount = ipInfoWorkers
	}
	for i := 0; i < workerCount; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for key := range jobs {
				result := c.resolveContext(ctx, key)
				resultsMu.Lock()
				results[key] = result
				resultsMu.Unlock()
			}
		}()
	}
	workers.Wait()
	for _, rawIP := range rawIPs {
		key := strings.TrimSpace(rawIP)
		if result, ok := results[key]; ok {
			results[rawIP] = result
		}
	}
	return results
}

func (c *ipInfoClient) close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	cityDB, asnDB := c.cityDB, c.asnDB
	c.cityDB, c.asnDB = nil, nil
	c.mu.Unlock()
	var first error
	if cityDB != nil {
		if err := cityDB.Close(); err != nil {
			first = err
		}
	}
	if asnDB != nil {
		if err := asnDB.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func fallbackIPInfo(rawIP, status string) ipInfoResult {
	trimmed := strings.TrimSpace(rawIP)
	if ip := net.ParseIP(trimmed); ip != nil {
		trimmed = ip.String()
	}
	return ipInfoResult{IP: trimmed, Country: sourceCountryLabel(trimmed), Source: "offline", Status: status}
}

func (a *App) resolveIPInfo(rawIP string) ipInfoResult {
	if a == nil || a.ipInfo == nil {
		return fallbackIPInfo(rawIP, "fallback_unconfigured")
	}
	return a.ipInfo.resolve(rawIP)
}

func (a *App) lookupIPInfo(ips []string) map[string]ipInfoResult {
	if a == nil || a.ipInfo == nil {
		results := make(map[string]ipInfoResult, len(ips))
		for _, ip := range ips {
			results[ip] = fallbackIPInfo(ip, "fallback_unconfigured")
		}
		return results
	}
	return a.ipInfo.lookupMany(ips)
}

func (a *App) adminIPInfoSettings(w http.ResponseWriter, r *http.Request) {
	if a.ipInfo == nil {
		a.ipInfo = newGeoIPClient(a.cfg)
	}
	if r.Method == http.MethodGet {
		a.writeJSON(w, http.StatusOK, a.ipInfo.settingsView())
		return
	}
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-ipinfo-settings:"+requestSourceIP(r), 20, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 8*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider or token must be provided as JSON"})
		return
	}

	provider := config.GeoIPProviderMaxMind
	a.ipInfo.mu.Lock()
	provider = a.ipInfo.provider
	a.ipInfo.mu.Unlock()
	rawProvider, providerProvided := value["provider"]
	if providerProvided {
		providerValue, ok := rawProvider.(string)
		if !ok {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider must be a string"})
			return
		}
		var valid bool
		provider, valid = normalizeGeoIPProvider(providerValue)
		if !valid {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider must be maxmind or ipinfo_lite"})
			return
		}
	}
	rawToken, tokenProvided := value["token"]
	if !tokenProvided {
		rawToken, tokenProvided = value["key"]
	}
	if !tokenProvided {
		rawToken, tokenProvided = value["apikey"]
	}
	token := a.cfg.IPInfoLiteToken
	if tokenProvided {
		var tokenOK bool
		token, tokenOK = rawToken.(string)
		if !tokenOK {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token must be a string"})
			return
		}
		token = strings.TrimSpace(token)
		if len(token) > ipInfoMaxTokenLength {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("token must be at most %d characters", ipInfoMaxTokenLength)})
			return
		}
	}
	if !providerProvided && tokenProvided {
		// Preserve the old PUT contract: sending only token/key selected the
		// IPinfo provider. New clients should send provider explicitly.
		provider = config.GeoIPProviderIPInfoLite
	}
	if !providerProvided && !tokenProvided {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider or token field is required"})
		return
	}

	previousProvider, previousToken := a.cfg.GeoIPProvider, a.cfg.IPInfoLiteToken
	a.cfg.GeoIPProvider = provider
	if tokenProvided {
		a.cfg.IPInfoLiteToken = token
	}
	if err := config.Save(configPathForApp(), a.cfg); err != nil {
		a.cfg.GeoIPProvider, a.cfg.IPInfoLiteToken = previousProvider, previousToken
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "geolocation setting could not be saved"})
		return
	}
	a.ipInfo.setProvider(provider)
	if tokenProvided {
		a.ipInfo.setToken(token)
	}
	view := a.ipInfo.settingsView()
	configured, _ := view["configured"].(bool)
	a.recordAudit(r, "admin.geoip.update", "geoip", "success", map[string]string{
		"provider":   provider,
		"configured": strconv.FormatBool(configured),
	})
	view["success"] = true
	a.writeJSON(w, http.StatusOK, view)
}
