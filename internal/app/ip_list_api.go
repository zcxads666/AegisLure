package app

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/security"
	"github.com/zcxads666/AegisLure/internal/store"
)

const (
	ipListAPIPath       = "api"
	ipListAPIKeyPrefix  = "ak_"
	ipListAPIMaxDays    = 3650
	ipListAPIRateLimit  = 60
	ipListAPIKeyMaxSize = 256
)

type ipListAPIFilter struct {
	Days    int
	Month   string
	Risk    string
	StartAt time.Time
	EndAt   time.Time
}

// ipListAPISettingsView is intentionally metadata-only. The full API key is
// added by the mutation handlers only when a new key was just generated.
func (a *App) ipListAPISettingsView(r *http.Request, settings model.IPListAPIConfig) map[string]any {
	endpointPath := strings.TrimRight(a.cfg.AdminPath, "/") + "/" + ipListAPIPath
	endpoint := endpointPath
	if r != nil {
		endpoint = (&url.URL{Scheme: requestScheme(r), Host: r.Host, Path: endpointPath}).String()
	}
	view := map[string]any{
		"enabled":          settings.Enabled,
		"endpoint":         endpoint,
		"endpoint_path":    endpointPath,
		"method":           http.MethodGet,
		"key_configured":   strings.TrimSpace(settings.KeyHash) != "",
		"key_masked":       ipListAPIKeyMask(settings.KeyPrefix),
		"key_rotated_at":   nil,
		"authorization":    "Authorization: Bearer <API key>",
		"alternate_header": "X-API-Key: <API key>",
		"query_parameters": map[string]string{
			"days":  "最近 N 天，例如 days=7；与 month 互斥",
			"month": "自然月 YYYY-MM，例如 month=2026-09；与 days 互斥",
			"risk":  "all、low、medium、high；默认 all",
		},
		"risk_levels": map[string]map[string]int{
			"low":    {"min_score": 0, "max_score": 29},
			"medium": {"min_score": 30, "max_score": 59},
			"high":   {"min_score": 60, "max_score": 100},
		},
		"timezone": model.InteractionChainTimezone,
	}
	if !settings.RotatedAt.IsZero() {
		view["key_rotated_at"] = settings.RotatedAt
	}
	return view
}

func ipListAPIKeyMask(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return ""
	}
	return prefix + "••••••••"
}

func (a *App) adminIPListAPISettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.writeJSON(w, http.StatusOK, a.ipListAPISettingsView(r, a.store.IPListAPIConfig()))
		return
	}
	if !sameOriginAdminUIRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin page request required"})
		return
	}
	if !a.allowRate("admin-ip-list-api-settings:"+requestSourceIP(r), 20, time.Minute) {
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
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enabled must be provided as JSON"})
		return
	}
	enabled, ok := value["enabled"].(bool)
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "enabled must be a boolean"})
		return
	}

	settings := a.store.IPListAPIConfig()
	generatedKey := ""
	if enabled && strings.TrimSpace(settings.KeyHash) == "" {
		var err error
		generatedKey, err = newIPListAPIKey()
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "API key generation failed"})
			return
		}
	}
	if err := a.store.UpdateIPListAPIConfig(func(current *model.IPListAPIConfig) {
		current.Enabled = enabled
		if generatedKey != "" {
			current.KeyHash = security.Fingerprint(a.cfg.InstanceKey, generatedKey)
			current.KeyPrefix = ipListAPIKeyDisplayPrefix(generatedKey)
			current.RotatedAt = time.Now().UTC()
		}
	}); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "IP list API setting could not be saved"})
		return
	}
	a.recordAudit(r, "admin.ip_list_api.update", "ip_list_api", "success", map[string]string{
		"enabled":       strconv.FormatBool(enabled),
		"key_generated": strconv.FormatBool(generatedKey != ""),
	})
	view := a.ipListAPISettingsView(r, a.store.IPListAPIConfig())
	view["success"] = true
	if generatedKey != "" {
		view["api_key"] = generatedKey
		view["api_key_notice"] = "完整 key 只返回本次，请立即复制；丢失后需要再次轮换。"
	}
	a.writeJSON(w, http.StatusOK, view)
}

func (a *App) rotateIPListAPIKey(w http.ResponseWriter, r *http.Request) {
	if !sameOriginAdminUIRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin page request required"})
		return
	}
	if !a.allowRate("admin-ip-list-api-key-rotate:"+requestSourceIP(r), 10, time.Minute) {
		rateLimited(w)
		return
	}
	key, err := newIPListAPIKey()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "API key generation failed"})
		return
	}
	if err := a.store.UpdateIPListAPIConfig(func(settings *model.IPListAPIConfig) {
		settings.KeyHash = security.Fingerprint(a.cfg.InstanceKey, key)
		settings.KeyPrefix = ipListAPIKeyDisplayPrefix(key)
		settings.RotatedAt = time.Now().UTC()
	}); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "API key could not be saved"})
		return
	}
	a.recordAudit(r, "admin.ip_list_api.key.rotate", "ip_list_api", "success", nil)
	view := a.ipListAPISettingsView(r, a.store.IPListAPIConfig())
	view["success"] = true
	view["api_key"] = key
	view["api_key_notice"] = "完整 key 只返回本次，请立即复制；旧 key 已失效。"
	a.writeJSON(w, http.StatusOK, view)
}

func newIPListAPIKey() (string, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	return ipListAPIKeyPrefix + token, nil
}

func ipListAPIKeyDisplayPrefix(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:12]
}

func (a *App) ipListAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Authorization, X-API-Key")
	settings := a.store.IPListAPIConfig()
	if !settings.Enabled {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "IP list API is disabled"})
		return
	}
	key := ipListAPIRequestKey(r)
	if len(key) == 0 || len(key) > ipListAPIKeyMaxSize || strings.TrimSpace(settings.KeyHash) == "" || subtle.ConstantTimeCompare([]byte(security.Fingerprint(a.cfg.InstanceKey, key)), []byte(settings.KeyHash)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ip-list-api"`)
		a.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "valid API key required"})
		return
	}
	if !a.allowRate("ip-list-api:"+requestSourceIP(r), ipListAPIRateLimit, time.Minute) {
		rateLimited(w)
		return
	}
	filter, err := parseIPListAPIFilter(r)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	events, err := a.store.EventSummariesContext(r.Context(), -1, "", "")
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "IP list query failed"})
		return
	}
	filteredEvents := filterIPListEvents(events, filter, r.Context())
	items := make([]map[string]any, 0)
	for _, indicator := range store.IndicatorsFromEvents(filteredEvents) {
		if !indicatorMatchesRiskLevel(indicator.Score, filter.Risk) {
			continue
		}
		items = append(items, ipListAPIView(indicator, a.cfg.InstanceKey))
	}
	response := map[string]any{
		"schema_version": 1,
		"success":        true,
		"generated_at":   time.Now().UTC(),
		"timezone":       model.InteractionChainTimezone,
		"filters":        ipListAPIFilterView(filter),
		"count":          len(items),
		"items":          items,
	}
	a.writeJSON(w, http.StatusOK, response)
}

func ipListAPIRequestKey(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-API-Key")); value != "" {
		return value
	}
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authorization) >= len("Bearer ") && strings.EqualFold(authorization[:len("Bearer ")], "Bearer ") {
		return strings.TrimSpace(authorization[len("Bearer "):])
	}
	return ""
}

func parseIPListAPIFilter(r *http.Request) (ipListAPIFilter, error) {
	risk, err := indicatorRiskLevelQuery(r)
	if err != nil {
		return ipListAPIFilter{}, err
	}
	daysValue := strings.TrimSpace(r.URL.Query().Get("days"))
	month := strings.TrimSpace(r.URL.Query().Get("month"))
	if daysValue != "" && month != "" {
		return ipListAPIFilter{}, fmt.Errorf("days and month cannot be used together")
	}
	filter := ipListAPIFilter{Risk: risk}
	if daysValue != "" {
		days, parseErr := strconv.Atoi(daysValue)
		if parseErr != nil || days < 1 || days > ipListAPIMaxDays {
			return ipListAPIFilter{}, fmt.Errorf("days must be between 1 and %d", ipListAPIMaxDays)
		}
		now := time.Now().In(dashboardShanghaiLocation)
		filter.Days = days
		filter.StartAt = now.AddDate(0, 0, -days).UTC()
		filter.EndAt = now.UTC()
		return filter, nil
	}
	if month != "" {
		if len(month) != len("2006-01") {
			return ipListAPIFilter{}, fmt.Errorf("month must use YYYY-MM format")
		}
		start, parseErr := time.ParseInLocation("2006-01", month, dashboardShanghaiLocation)
		if parseErr != nil || start.Format("2006-01") != month {
			return ipListAPIFilter{}, fmt.Errorf("month must use YYYY-MM format")
		}
		filter.Month = month
		filter.StartAt = start.UTC()
		filter.EndAt = start.AddDate(0, 1, 0).UTC()
	}
	return filter, nil
}

func filterIPListEvents(events []model.Event, filter ipListAPIFilter, ctx context.Context) []model.Event {
	if filter.StartAt.IsZero() && filter.EndAt.IsZero() {
		return events
	}
	filtered := make([]model.Event, 0, len(events))
	for _, event := range events {
		if ctx != nil && ctx.Err() != nil {
			return filtered
		}
		if !filter.StartAt.IsZero() && event.ObservedAt.Before(filter.StartAt) {
			continue
		}
		if !filter.EndAt.IsZero() && !event.ObservedAt.Before(filter.EndAt) {
			continue
		}
		filtered = append(filtered, event)
	}
	return filtered
}

func ipListAPIFilterView(filter ipListAPIFilter) map[string]any {
	view := map[string]any{"risk": filter.Risk}
	if filter.Days > 0 {
		view["days"] = filter.Days
	}
	if filter.Month != "" {
		view["month"] = filter.Month
	}
	if !filter.StartAt.IsZero() {
		view["start_at"] = filter.StartAt
	}
	if !filter.EndAt.IsZero() {
		view["end_at"] = filter.EndAt
	}
	return view
}

func ipListAPIView(item model.Indicator, key string) map[string]any {
	return map[string]any{
		"id":                  indicatorID(key, item.IP),
		"ip":                  item.IP,
		"score":               item.Score,
		"risk_level":          indicatorRiskLevel(item.Score),
		"confidence":          item.Confidence,
		"first_seen":          item.FirstSeen,
		"last_seen":           item.LastSeen,
		"expires_at":          item.ExpiresAt,
		"reason_codes":        item.ReasonCodes,
		"products":            item.Products,
		"sensor_count":        item.SensorCount,
		"site_count":          item.SiteCount,
		"recommended_action":  item.RecommendedAction,
		"evidence_count":      item.EvidenceCount,
		"associated":          item.Associated,
		"associated_ips":      item.AssociatedIPs,
		"association_reasons": item.AssociationReasons,
	}
}
