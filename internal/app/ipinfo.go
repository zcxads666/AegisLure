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
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/zcxads666/AegisLure/internal/config"
)

const (
	defaultIPInfoLiteEndpoint = "https://api.ipinfo.io/lite/"
	defaultIPInfoAPIEndpoint  = "https://ipinfo.io/"
	maxMindSource             = "maxmind_geolite2"
	ipInfoMMDBSource          = "ipinfo_mmdb"
	ipInfoLookupTimeout       = 2 * time.Second
	ipInfoDashboardTimeout    = 4 * time.Second
	ipInfoCacheTTL            = 24 * time.Hour
	ipInfoFailureCacheTTL     = 5 * time.Minute
	ipInfoMaxTokenLength      = 256
	ipInfoMaxDashboardIPs     = 128
	ipInfoRiskListTimeout     = 8 * time.Second
	ipInfoWorkers             = 6
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

type ipInfoLiteResponse struct {
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
	mu                   sync.Mutex
	provider             string
	token                string
	generation           uint64
	cache                map[string]ipInfoCacheEntry
	httpClient           *http.Client
	endpoint             string
	cityDB               *geoip2.Reader
	asnDB                *geoip2.Reader
	cityDBPath           string
	asnDBPath            string
	ipInfoLocationDB     *maxminddb.Reader
	ipInfoASNDB          *maxminddb.Reader
	ipInfoLocationDBPath string
	ipInfoASNDBPath      string
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
	ipInfoLocationPath, ipInfoASNPath := "", ""
	if cfg != nil {
		if normalized, ok := normalizeGeoIPProvider(cfg.GeoIPProvider); ok {
			provider = normalized
		}
		token = strings.TrimSpace(cfg.IPInfoLiteToken)
		cityPath, asnPath = cfg.GeoIPDatabasePaths()
		ipInfoLocationPath, ipInfoASNPath = cfg.IPInfoDatabasePaths()
	}
	cityDB := openMaxMindReader(cityPath)
	asnDB := openMaxMindReader(asnPath)
	ipInfoLocationDB := openIPInfoReader(ipInfoLocationPath)
	ipInfoASNDB := openIPInfoReader(ipInfoASNPath)
	return &ipInfoClient{
		provider:             provider,
		token:                token,
		cache:                make(map[string]ipInfoCacheEntry),
		httpClient:           newIPInfoHTTPClient(),
		endpoint:             defaultIPInfoEndpoint(provider),
		cityDB:               cityDB,
		asnDB:                asnDB,
		cityDBPath:           cityPath,
		asnDBPath:            asnPath,
		ipInfoLocationDB:     ipInfoLocationDB,
		ipInfoASNDB:          ipInfoASNDB,
		ipInfoLocationDBPath: ipInfoLocationPath,
		ipInfoASNDBPath:      ipInfoASNPath,
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
	case config.GeoIPProviderIPInfoAPI, "ipinfo-api", "ipinfo-full":
		return config.GeoIPProviderIPInfoAPI, true
	case config.GeoIPProviderIPInfoLite, "ipinfo", "ipinfo-lite":
		return config.GeoIPProviderIPInfoLite, true
	case config.GeoIPProviderIPInfoMMDB, "ipinfo-mmdb", "ipinfo-database", "ipinfo-db":
		return config.GeoIPProviderIPInfoMMDB, true
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

// openIPInfoReader uses the generic MMDB reader because IPinfo databases use
// a flat record schema and an IPinfo-specific database_type. geoip2.Reader
// intentionally rejects that metadata before a lookup can happen.
func openIPInfoReader(path string) *maxminddb.Reader {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() == 0 || info.Size() > 4<<30 {
		return nil
	}
	reader, err := maxminddb.Open(path)
	if err != nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(reader.Metadata.DatabaseType)), "ipinfo") {
		_ = reader.Close()
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
	if c.endpoint == "" || c.endpoint == defaultIPInfoLiteEndpoint || c.endpoint == defaultIPInfoAPIEndpoint {
		c.endpoint = defaultIPInfoEndpoint(normalized)
	}
	c.generation++
	c.cache = make(map[string]ipInfoCacheEntry)
}

func defaultIPInfoEndpoint(provider string) string {
	if provider == config.GeoIPProviderIPInfoAPI {
		return defaultIPInfoAPIEndpoint
	}
	return defaultIPInfoLiteEndpoint
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
	ipInfoLocationAvailable := false
	ipInfoASNAvailable := false
	ipInfoLocationPath, ipInfoASNPath := "", ""
	if c != nil {
		c.mu.Lock()
		provider = c.provider
		token = c.token
		endpoint = c.endpoint
		cityDBAvailable = c.cityDB != nil
		asnDBAvailable = c.asnDB != nil
		cityDBPath = c.cityDBPath
		asnDBPath = c.asnDBPath
		ipInfoLocationAvailable = c.ipInfoLocationDB != nil
		ipInfoASNAvailable = c.ipInfoASNDB != nil
		ipInfoLocationPath = c.ipInfoLocationDBPath
		ipInfoASNPath = c.ipInfoASNDBPath
		c.mu.Unlock()
	}
	maxMindReady := cityDBAvailable && asnDBAvailable
	ipInfoMMDBReady := ipInfoLocationAvailable && ipInfoASNAvailable
	configured := (provider == config.GeoIPProviderMaxMind && maxMindReady) ||
		((provider == config.GeoIPProviderIPInfoAPI || provider == config.GeoIPProviderIPInfoLite) && token != "") ||
		(provider == config.GeoIPProviderIPInfoMMDB && ipInfoMMDBReady)
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
		"ipinfo_mmdb": map[string]any{
			"ready":              ipInfoMMDBReady,
			"location_available": ipInfoLocationAvailable,
			"asn_available":      ipInfoASNAvailable,
			"location_file":      databaseFileName(ipInfoLocationPath),
			"asn_file":           databaseFileName(ipInfoASNPath),
		},
	}
}

func geoIPProviderLabel(provider string) string {
	if provider == config.GeoIPProviderIPInfoAPI {
		return "IPinfo API（City + ASN）"
	}
	if provider == config.GeoIPProviderIPInfoLite {
		return "IPinfo Lite API"
	}
	if provider == config.GeoIPProviderIPInfoMMDB {
		return "IPinfo Location + ASN MMDB"
	}
	return "MaxMind GeoLite2 City + ASN"
}

func geoIPProviderOptions() []map[string]any {
	return []map[string]any{
		{"id": config.GeoIPProviderMaxMind, "label": geoIPProviderLabel(config.GeoIPProviderMaxMind)},
		{"id": config.GeoIPProviderIPInfoAPI, "label": geoIPProviderLabel(config.GeoIPProviderIPInfoAPI)},
		{"id": config.GeoIPProviderIPInfoLite, "label": geoIPProviderLabel(config.GeoIPProviderIPInfoLite)},
		{"id": config.GeoIPProviderIPInfoMMDB, "label": geoIPProviderLabel(config.GeoIPProviderIPInfoMMDB)},
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
	ipInfoLocationDB := c.ipInfoLocationDB
	ipInfoASNDB := c.ipInfoASNDB
	c.mu.Unlock()

	if provider == config.GeoIPProviderMaxMind {
		addr, err := netip.ParseAddr(canonical)
		if err != nil {
			return fallbackIPInfo(canonical, "fallback_invalid")
		}
		return c.resolveMaxMind(canonical, addr, generation, cityDB, asnDB)
	}
	if provider == config.GeoIPProviderIPInfoMMDB {
		addr, err := netip.ParseAddr(canonical)
		if err != nil {
			return fallbackIPInfo(canonical, "fallback_invalid")
		}
		return c.resolveIPInfoMMDB(canonical, addr, generation, ipInfoLocationDB, ipInfoASNDB)
	}
	return c.resolveIPInfo(ctx, canonical, token, generation, endpoint, client, provider)
}

func (c *ipInfoClient) resolveMaxMind(canonical string, addr netip.Addr, generation uint64, cityDB, asnDB *geoip2.Reader) ipInfoResult {
	if cityDB == nil && asnDB == nil {
		return c.cacheFailure(canonical, "fallback_maxmind_unavailable", generation)
	}
	result := ipInfoResult{IP: canonical, Source: maxMindSource, Status: "partial"}
	cityFound, asnFound := false, false
	if cityDB != nil {
		if record, err := cityDB.City(addr); err == nil && record != nil && record.HasData() {
			result.City = strings.TrimSpace(record.City.Names.English)
			if len(record.Subdivisions) > 0 {
				result.Region = strings.TrimSpace(record.Subdivisions[0].Names.English)
				result.RegionCode = strings.TrimSpace(record.Subdivisions[0].ISOCode)
			}
			result.PostalCode = strings.TrimSpace(record.Postal.Code)
			if record.Location.Latitude != nil {
				result.Latitude = *record.Location.Latitude
			}
			if record.Location.Longitude != nil {
				result.Longitude = *record.Location.Longitude
			}
			result.Timezone = strings.TrimSpace(record.Location.TimeZone)
			result.CountryCode = strings.TrimSpace(record.Country.ISOCode)
			result.Country = strings.TrimSpace(record.Country.Names.English)
			result.ContinentCode = strings.TrimSpace(record.Continent.Code)
			result.Continent = strings.TrimSpace(record.Continent.Names.English)
			cityFound = result.City != "" || result.Region != "" || result.CountryCode != "" || result.Country != "" || result.ContinentCode != "" || result.Continent != "" || result.PostalCode != "" || result.Latitude != 0 || result.Longitude != 0
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

func (c *ipInfoClient) resolveIPInfoMMDB(canonical string, addr netip.Addr, generation uint64, locationDB, asnDB *maxminddb.Reader) ipInfoResult {
	if locationDB == nil && asnDB == nil {
		return c.cacheFailure(canonical, "fallback_ipinfo_mmdb_unavailable", generation)
	}
	result := ipInfoResult{IP: canonical, Source: ipInfoMMDBSource, Status: "partial"}
	locationFound, asnFound := false, false
	if locationDB != nil {
		var record map[string]any
		lookup := locationDB.Lookup(addr)
		if lookup.Found() {
			if err := lookup.Decode(&record); err == nil {
				result.City = ipInfoDatabaseString(record, "city")
				result.Region = ipInfoDatabaseString(record, "region")
				result.RegionCode = ipInfoDatabaseString(record, "region_code")
				result.PostalCode = ipInfoDatabaseString(record, "postal_code")
				result.Country = ipInfoDatabaseString(record, "country")
				result.CountryCode = strings.ToUpper(ipInfoDatabaseString(record, "country_code"))
				result.Continent = ipInfoDatabaseString(record, "continent")
				result.ContinentCode = strings.ToUpper(ipInfoDatabaseString(record, "continent_code"))
				result.Latitude = ipInfoDatabaseFloat(record, "latitude")
				result.Longitude = ipInfoDatabaseFloat(record, "longitude")
				result.Timezone = ipInfoDatabaseString(record, "timezone")
				locationFound = result.City != "" || result.Region != "" || result.Country != "" || result.CountryCode != "" || result.Continent != "" || result.ContinentCode != "" || result.PostalCode != "" || result.Latitude != 0 || result.Longitude != 0
			}
		}
	}
	if asnDB != nil {
		var record map[string]any
		lookup := asnDB.Lookup(addr)
		if lookup.Found() {
			if err := lookup.Decode(&record); err == nil {
				result.ASN = normalizeASN(ipInfoDatabaseString(record, "asn"))
				result.ASName = ipInfoDatabaseString(record, "name", "as_name")
				result.ASDomain = ipInfoDatabaseString(record, "domain", "as_domain")
				asnFound = result.ASN != "" || result.ASName != "" || result.ASDomain != ""
			}
		}
	}
	if !locationFound && !asnFound {
		return c.cacheFailure(canonical, "fallback_ipinfo_mmdb_not_found", generation)
	}
	if locationFound && asnFound {
		result.Status = "ok"
	}
	c.cacheResult(canonical, result, ipInfoCacheTTL, generation)
	return result
}

func ipInfoDatabaseString(record map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := record[key]
		if !ok || value == nil {
			continue
		}
		switch value := value.(type) {
		case string:
			if value = strings.TrimSpace(value); value != "" {
				return value
			}
		case []byte:
			if text := strings.TrimSpace(string(value)); text != "" {
				return text
			}
		default:
			if text := strings.TrimSpace(fmt.Sprint(value)); text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}

func ipInfoDatabaseFloat(record map[string]any, key string) float64 {
	value, ok := record[key]
	if !ok || value == nil {
		return 0
	}
	switch value := value.(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case uint64:
		return float64(value)
	default:
		return 0
	}
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

func (c *ipInfoClient) resolveIPInfo(ctx context.Context, canonical, token string, generation uint64, endpoint string, client *http.Client, provider string) ipInfoResult {
	if token == "" {
		result := fallbackIPInfo(canonical, "fallback_unconfigured")
		c.cacheResult(canonical, result, ipInfoFailureCacheTTL, generation)
		return result
	}
	if endpoint == "" {
		endpoint = defaultIPInfoEndpoint(provider)
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
	request.Header.Set("User-Agent", "AegisLure-IPinfo/1.0")
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
	result := parseIPInfoResponse(canonical, payload, provider)
	c.cacheResult(canonical, result, ipInfoCacheTTL, generation)
	return result
}

func parseIPInfoResponse(canonical string, payload ipInfoLiteResponse, provider string) ipInfoResult {
	countryCode := strings.ToUpper(strings.TrimSpace(payload.CountryCode))
	country := strings.TrimSpace(payload.Country)
	if provider == config.GeoIPProviderIPInfoAPI {
		if countryCode == "" {
			countryCode = strings.ToUpper(country)
		}
		country = strings.TrimSpace(payload.CountryName)
		if country == "" {
			country = countryCode
		}
	}
	asn := normalizeASN(payload.ASN)
	asName := strings.TrimSpace(payload.ASName)
	if provider == config.GeoIPProviderIPInfoAPI && (asn == "" || asName == "") {
		orgASN, orgName := parseIPInfoOrganization(payload.Org)
		if asn == "" {
			asn = orgASN
		}
		if asName == "" {
			asName = orgName
		}
	}
	latitude, longitude := payload.Latitude, payload.Longitude
	if provider == config.GeoIPProviderIPInfoAPI && (latitude == 0 && longitude == 0) {
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
		Source:        provider,
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
	if c == nil {
		return nil
	}
	c.mu.Lock()
	cityDB, asnDB := c.cityDB, c.asnDB
	ipInfoLocationDB, ipInfoASNDB := c.ipInfoLocationDB, c.ipInfoASNDB
	c.cityDB, c.asnDB = nil, nil
	c.ipInfoLocationDB, c.ipInfoASNDB = nil, nil
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
	if ipInfoLocationDB != nil {
		if err := ipInfoLocationDB.Close(); err != nil && first == nil {
			first = err
		}
	}
	if ipInfoASNDB != nil {
		if err := ipInfoASNDB.Close(); err != nil && first == nil {
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
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider must be maxmind, ipinfo_mmdb, ipinfo_api, or ipinfo_lite"})
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
