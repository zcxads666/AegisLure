package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zcxads666/AegisLure/internal/config"
)

const (
	defaultIPInfoAPIEndpoint = "https://ipinfo.io/"
	ipInfoProbeIP            = "8.8.8.8"
	ipInfoLookupTimeout      = 2 * time.Second
	ipInfoDashboardTimeout   = 4 * time.Second
	ipInfoCacheTTL           = 24 * time.Hour
	ipInfoFailureCacheTTL    = 5 * time.Minute
	ipInfoMaxTokenLength     = 256
	ipInfoMaxDashboardIPs    = 128
	ipInfoRiskListTimeout    = 8 * time.Second
	ipInfoWorkers            = 6
)

type ipInfoResult struct {
	IP            string  `json:"ip"`
	City          string  `json:"city,omitempty"`
	Region        string  `json:"region,omitempty"`
	RegionCode    string  `json:"region_code,omitempty"`
	PostalCode    string  `json:"postal_code,omitempty"`
	Latitude      float64 `json:"latitude,omitempty"`
	Longitude     float64 `json:"longitude,omitempty"`
	Timezone      string  `json:"timezone,omitempty"`
	ASN           string  `json:"asn,omitempty"`
	ASName        string  `json:"as_name,omitempty"`
	ASDomain      string  `json:"as_domain,omitempty"`
	CountryCode   string  `json:"country_code,omitempty"`
	Country       string  `json:"country,omitempty"`
	ContinentCode string  `json:"continent_code,omitempty"`
	Continent     string  `json:"continent,omitempty"`
	Source        string  `json:"source"`
	Status        string  `json:"status"`
}

type ipInfoAPIResponse struct {
	IP            string  `json:"ip"`
	City          string  `json:"city"`
	Region        string  `json:"region"`
	RegionCode    string  `json:"region_code"`
	PostalCode    string  `json:"postal_code"`
	Postal        string  `json:"postal"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	Timezone      string  `json:"timezone"`
	ASN           string  `json:"asn"`
	ASName        string  `json:"as_name"`
	ASDomain      string  `json:"as_domain"`
	CountryCode   string  `json:"country_code"`
	Country       string  `json:"country"`
	CountryName   string  `json:"country_name"`
	ContinentCode string  `json:"continent_code"`
	Continent     string  `json:"continent"`
	Loc           string  `json:"loc"`
	Org           string  `json:"org"`
	Domain        string  `json:"domain"`
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
}

// newIPInfoClient is kept for tests and compatibility with the previous
// client constructor. IPinfo API is the only supported provider.
func newIPInfoClient(token string) *ipInfoClient {
	return newGeoIPClient(&config.Config{
		GeoIPProvider: config.GeoIPProviderIPInfoAPI,
		IPInfoToken:   token,
	})
}

func newGeoIPClient(cfg *config.Config) *ipInfoClient {
	provider := config.GeoIPProviderIPInfoAPI
	token := ""
	if cfg != nil {
		if normalized, ok := normalizeGeoIPProvider(cfg.GeoIPProvider); ok {
			provider = normalized
		}
		token = strings.TrimSpace(cfg.IPInfoToken)
	}
	return &ipInfoClient{
		provider:   provider,
		token:      token,
		cache:      make(map[string]ipInfoCacheEntry),
		httpClient: newIPInfoHTTPClient(),
		endpoint:   defaultIPInfoAPIEndpoint,
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
	case "", config.GeoIPProviderIPInfoAPI, "ipinfo-api", "ipinfo-full":
		return config.GeoIPProviderIPInfoAPI, true
	default:
		return "", false
	}
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
	if c.endpoint == "" || c.endpoint == defaultIPInfoAPIEndpoint {
		c.endpoint = defaultIPInfoAPIEndpoint
	}
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
	provider := config.GeoIPProviderIPInfoAPI
	token := ""
	endpoint := defaultIPInfoAPIEndpoint
	if c != nil {
		c.mu.Lock()
		provider = c.provider
		token = c.token
		endpoint = c.endpoint
		c.mu.Unlock()
	}
	configured := provider == config.GeoIPProviderIPInfoAPI && token != ""
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
		"fallback":                  "本地/保留地址本地识别；公网 API 查询不可用时显示未知",
	}
}

func geoIPProviderLabel(provider string) string {
	_ = provider
	return "IPinfo API（City + ASN）"
}

func geoIPProviderOptions() []map[string]any {
	return []map[string]any{
		{"id": config.GeoIPProviderIPInfoAPI, "label": geoIPProviderLabel(config.GeoIPProviderIPInfoAPI)},
	}
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
	token := c.token
	generation := c.generation
	endpoint := c.endpoint
	client := c.httpClient
	c.mu.Unlock()
	return c.resolveIPInfo(ctx, canonical, token, generation, endpoint, client)
}

func normalizeASN(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(value), "AS") {
		return "AS" + strings.TrimSpace(value[2:])
	}
	return "AS" + value
}

func (c *ipInfoClient) resolveIPInfo(ctx context.Context, canonical, token string, generation uint64, endpoint string, client *http.Client) ipInfoResult {
	if token == "" {
		result := fallbackIPInfo(canonical, "fallback_unconfigured")
		c.cacheResult(canonical, result, ipInfoFailureCacheTTL, generation)
		return result
	}
	result, err := c.fetchIPInfo(ctx, canonical, token, endpoint, client)
	if err != nil {
		if ctx.Err() != nil {
			return fallbackIPInfo(canonical, "fallback_timeout")
		}
		return c.cacheFailure(canonical, "fallback_error", generation)
	}
	c.cacheResult(canonical, result, ipInfoCacheTTL, generation)
	return result
}

func (c *ipInfoClient) fetchIPInfo(ctx context.Context, canonical, token, endpoint string, client *http.Client) (ipInfoResult, error) {
	if strings.TrimSpace(token) == "" {
		return ipInfoResult{}, fmt.Errorf("IPinfo API key is empty")
	}
	if endpoint == "" {
		endpoint = defaultIPInfoAPIEndpoint
	}
	if client == nil {
		client = http.DefaultClient
	}
	requestURL := strings.TrimRight(endpoint, "/") + "/" + url.PathEscape(canonical)
	parsedURL, err := url.Parse(requestURL)
	if err != nil {
		return ipInfoResult{}, fmt.Errorf("invalid IPinfo API endpoint")
	}
	query := parsedURL.Query()
	query.Set("token", token)
	parsedURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return ipInfoResult{}, fmt.Errorf("could not create IPinfo API request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "AegisLure-IPinfo/1.0")
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ipInfoResult{}, fmt.Errorf("IPinfo API request timed out")
		}
		return ipInfoResult{}, fmt.Errorf("IPinfo API request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return ipInfoResult{}, fmt.Errorf("IPinfo API returned HTTP %d", response.StatusCode)
	}
	var payload ipInfoAPIResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16*1024))
	if err := decoder.Decode(&payload); err != nil {
		return ipInfoResult{}, fmt.Errorf("IPinfo API returned invalid JSON")
	}
	if strings.TrimSpace(payload.Country) == "" && strings.TrimSpace(payload.CountryCode) == "" && strings.TrimSpace(payload.Continent) == "" && strings.TrimSpace(payload.ContinentCode) == "" {
		return ipInfoResult{}, fmt.Errorf("IPinfo API returned no location data")
	}
	return parseIPInfoResponse(canonical, payload), nil
}

func (c *ipInfoClient) verifyToken(token string) error {
	if c == nil {
		return fmt.Errorf("IPinfo API client is unavailable")
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("IPinfo API key is empty")
	}
	c.mu.Lock()
	endpoint := c.endpoint
	client := c.httpClient
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), ipInfoLookupTimeout)
	defer cancel()
	if _, err := c.fetchIPInfo(ctx, ipInfoProbeIP, token, endpoint, client); err != nil {
		return fmt.Errorf("IPinfo API 获取 %s 失败：%s", ipInfoProbeIP, err)
	}
	return nil
}

func parseIPInfoResponse(canonical string, payload ipInfoAPIResponse) ipInfoResult {
	countryCode := strings.ToUpper(strings.TrimSpace(payload.CountryCode))
	country := strings.TrimSpace(payload.Country)
	if countryCode == "" {
		countryCode = strings.ToUpper(country)
	}
	country = firstNonEmpty(payload.CountryName, payload.Country, countryCode)
	asn := normalizeASN(payload.ASN)
	asName := strings.TrimSpace(payload.ASName)
	if asn == "" || asName == "" {
		orgASN, orgName := parseIPInfoOrganization(payload.Org)
		if asn == "" {
			asn = orgASN
		}
		if asName == "" {
			asName = orgName
		}
	}
	latitude, longitude := payload.Latitude, payload.Longitude
	if latitude == 0 && longitude == 0 {
		latitude, longitude = parseIPInfoLocation(payload.Loc)
	}
	return ipInfoResult{
		IP:            canonical,
		City:          strings.TrimSpace(payload.City),
		Region:        strings.TrimSpace(payload.Region),
		RegionCode:    strings.TrimSpace(payload.RegionCode),
		PostalCode:    firstNonEmpty(payload.PostalCode, payload.Postal),
		Latitude:      latitude,
		Longitude:     longitude,
		Timezone:      strings.TrimSpace(payload.Timezone),
		ASN:           asn,
		ASName:        asName,
		ASDomain:      firstNonEmpty(payload.ASDomain, payload.Domain),
		CountryCode:   countryCode,
		Country:       country,
		ContinentCode: strings.ToUpper(strings.TrimSpace(payload.ContinentCode)),
		Continent:     strings.TrimSpace(payload.Continent),
		Source:        config.GeoIPProviderIPInfoAPI,
		Status:        "ok",
	}
}

func parseIPInfoOrganization(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	parts := strings.Fields(value)
	if len(parts) == 0 || !strings.HasPrefix(strings.ToUpper(parts[0]), "AS") {
		return "", value
	}
	return normalizeASN(parts[0]), strings.TrimSpace(strings.TrimPrefix(value, parts[0]))
}

func parseIPInfoLocation(value string) (float64, float64) {
	parts := strings.Split(value, ",")
	if len(parts) != 2 {
		return 0, 0
	}
	latitude, latitudeErr := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	longitude, longitudeErr := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if latitudeErr != nil || longitudeErr != nil {
		return 0, 0
	}
	return latitude, longitude
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
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
	return c.lookupManyWithOptions(rawIPs, ipInfoMaxDashboardIPs, ipInfoDashboardTimeout)
}

func (c *ipInfoClient) lookupManyForRiskList(rawIPs []string) map[string]ipInfoResult {
	return c.lookupManyWithOptions(rawIPs, 0, ipInfoRiskListTimeout)
}

func (c *ipInfoClient) lookupManyWithOptions(rawIPs []string, maxIPs int, timeout time.Duration) map[string]ipInfoResult {
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
	if maxIPs > 0 && len(unique) > maxIPs {
		for _, key := range unique[maxIPs:] {
			results[key] = fallbackIPInfo(key, "fallback_limit")
		}
		unique = unique[:maxIPs]
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
	return nil
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

func (a *App) lookupIPInfoForRiskList(ips []string) map[string]ipInfoResult {
	if a == nil || a.ipInfo == nil {
		results := make(map[string]ipInfoResult, len(ips))
		for _, ip := range ips {
			results[ip] = fallbackIPInfo(ip, "fallback_unconfigured")
		}
		return results
	}
	return a.ipInfo.lookupManyForRiskList(ips)
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

	provider := config.GeoIPProviderIPInfoAPI
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
		if strings.TrimSpace(providerValue) != config.GeoIPProviderIPInfoAPI {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider must be ipinfo_api"})
			return
		}
		provider = config.GeoIPProviderIPInfoAPI
	}
	rawToken, tokenProvided := value["token"]
	if !tokenProvided {
		rawToken, tokenProvided = value["key"]
	}
	if !tokenProvided {
		rawToken, tokenProvided = value["apikey"]
	}
	token := a.cfg.IPInfoToken
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
		// Preserve the old PUT contract: sending only token/key selects the
		// sole supported IPinfo API provider.
		provider = config.GeoIPProviderIPInfoAPI
	}
	if !providerProvided && !tokenProvided {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider or token field is required"})
		return
	}

	if tokenProvided && token != "" {
		if err := a.ipInfo.verifyToken(token); err != nil {
			a.writeJSON(w, http.StatusBadGateway, map[string]string{"error": "IPinfo API key 验证失败：" + err.Error()})
			return
		}
	}

	previousProvider, previousToken := a.cfg.GeoIPProvider, a.cfg.IPInfoToken
	a.cfg.GeoIPProvider = provider
	if tokenProvided {
		a.cfg.IPInfoToken = token
	}
	if err := config.Save(configPathForApp(), a.cfg); err != nil {
		a.cfg.GeoIPProvider, a.cfg.IPInfoToken = previousProvider, previousToken
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
