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
	defaultIPInfoLiteEndpoint = "https://api.ipinfo.io/lite/"
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
	token      string
	tokenEpoch uint64
	cache      map[string]ipInfoCacheEntry
	httpClient *http.Client
	endpoint   string
}

func newIPInfoClient(token string) *ipInfoClient {
	return &ipInfoClient{
		token: strings.TrimSpace(token),
		cache: make(map[string]ipInfoCacheEntry),
		httpClient: &http.Client{
			Timeout: ipInfoLookupTimeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		endpoint: defaultIPInfoLiteEndpoint,
	}
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
	c.tokenEpoch++
	// A response obtained with the previous token must never be served after
	// the administrator changes the provider credential.
	c.cache = make(map[string]ipInfoCacheEntry)
}

func (c *ipInfoClient) settingsView() map[string]any {
	token := ""
	endpoint := defaultIPInfoLiteEndpoint
	if c != nil {
		c.mu.Lock()
		token = c.token
		endpoint = c.endpoint
		c.mu.Unlock()
	}
	return map[string]any{
		"provider":                  "IPinfo Lite",
		"configured":                token != "",
		"enabled":                   token != "",
		"masked_token":              maskIPInfoToken(token),
		"endpoint":                  endpoint,
		"timeout_seconds":           int(ipInfoLookupTimeout / time.Second),
		"cache_ttl_seconds":         int(ipInfoCacheTTL / time.Second),
		"failure_cache_ttl_seconds": int(ipInfoFailureCacheTTL / time.Second),
		"dashboard_lookup_limit":    ipInfoMaxDashboardIPs,
		"fallback":                  "本地/保留地址离线识别；公网地址无 key、超时或失败时显示未知",
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
	tokenEpoch := c.tokenEpoch
	endpoint := c.endpoint
	client := c.httpClient
	c.mu.Unlock()
	if token == "" {
		result := fallbackIPInfo(canonical, "fallback_unconfigured")
		c.cacheResult(canonical, result, ipInfoFailureCacheTTL, tokenEpoch)
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
		return c.cacheFailure(canonical, "fallback_error", tokenEpoch)
	}
	query := parsedURL.Query()
	query.Set("token", token)
	parsedURL.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return c.cacheFailure(canonical, "fallback_error", tokenEpoch)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "AegisLure-IPinfo-Lite/1.0")
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return fallbackIPInfo(canonical, "fallback_timeout")
		}
		return c.cacheFailure(canonical, "fallback_error", tokenEpoch)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if ctx.Err() != nil {
			return fallbackIPInfo(canonical, "fallback_timeout")
		}
		return c.cacheFailure(canonical, "fallback_error", tokenEpoch)
	}
	var payload ipInfoLiteResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16*1024))
	if err := decoder.Decode(&payload); err != nil || strings.TrimSpace(payload.Country) == "" && strings.TrimSpace(payload.CountryCode) == "" && strings.TrimSpace(payload.Continent) == "" && strings.TrimSpace(payload.ContinentCode) == "" {
		if ctx.Err() != nil {
			return fallbackIPInfo(canonical, "fallback_timeout")
		}
		return c.cacheFailure(canonical, "fallback_error", tokenEpoch)
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
		Source:        "ipinfo_lite",
		Status:        "ok",
	}
	c.cacheResult(canonical, result, ipInfoCacheTTL, tokenEpoch)
	return result
}

func (c *ipInfoClient) cacheFailure(canonical, status string, tokenEpoch uint64) ipInfoResult {
	result := fallbackIPInfo(canonical, status)
	c.cacheResult(canonical, result, ipInfoFailureCacheTTL, tokenEpoch)
	return result
}

func (c *ipInfoClient) cacheResult(canonical string, result ipInfoResult, ttl time.Duration, tokenEpoch uint64) {
	if c == nil || ttl <= 0 {
		return
	}
	c.mu.Lock()
	if tokenEpoch != c.tokenEpoch {
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
		a.ipInfo = newIPInfoClient(a.cfg.IPInfoLiteToken)
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
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token must be provided as JSON"})
		return
	}
	rawToken, exists := value["token"]
	if !exists {
		rawToken, exists = value["key"]
	}
	if !exists {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token field is required"})
		return
	}
	token, ok := rawToken.(string)
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token must be a string"})
		return
	}
	token = strings.TrimSpace(token)
	if len(token) > ipInfoMaxTokenLength {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("token must be at most %d characters", ipInfoMaxTokenLength)})
		return
	}
	previous := a.cfg.IPInfoLiteToken
	a.cfg.IPInfoLiteToken = token
	if err := config.Save(configPathForApp(), a.cfg); err != nil {
		a.cfg.IPInfoLiteToken = previous
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "IPinfo Lite setting could not be saved"})
		return
	}
	a.ipInfo.setToken(token)
	a.recordAudit(r, "admin.ipinfo_lite.update", "ipinfo-lite", "success", map[string]string{"configured": strconv.FormatBool(token != "")})
	view := a.ipInfo.settingsView()
	view["success"] = true
	a.writeJSON(w, http.StatusOK, view)
}
