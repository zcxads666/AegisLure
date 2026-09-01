package app

import (
	"crypto/sha256"
	"encoding/binary"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
)

// New API uses numeric public identifiers. AegisLure keeps its honey records
// keyed by opaque internal IDs, so the public number is a deterministic,
// non-reversible projection rather than a second persisted identity. Keep the
// projection within JavaScript's safe integer range because the upstream web
// client serializes token IDs as regular numbers before putting them in URLs.
func newAPIPublicID(value string) int64 {
	digest := sha256.Sum256([]byte("new-api-public-id\x00" + value))
	result := int64(binary.BigEndian.Uint64(digest[:8]) % uint64(1<<53-1))
	if result == 0 {
		return 1
	}
	return result
}

func newAPIPublicTokenID(token model.HoneyToken) int64 {
	return newAPIPublicID(token.ID)
}

func newAPIUserView(user model.HoneyUser) map[string]any {
	created := user.CreatedAt.Unix()
	if created < 0 {
		created = 0
	}
	return map[string]any{
		"id":                newAPIPublicID(user.ID),
		"username":          user.UsernameHint,
		"display_name":      user.UsernameHint,
		"role":              1,
		"status":            1,
		"group":             "default",
		"quota":             user.VirtualQuota,
		"used_quota":        0,
		"request_count":     0,
		"aff_count":         0,
		"aff_quota":         0,
		"aff_history_quota": 0,
		"created_time":      created,
		"setting":           "{}",
		"permissions": map[string]any{
			"sidebar_settings": false,
		},
	}
}

func newAPISessionView(session Session) map[string]any {
	created := session.CreatedAt.Unix()
	lastActive := session.LastSeen.Unix()
	if created < 0 {
		created = 0
	}
	if lastActive < 0 {
		lastActive = created
	}
	ip := session.SourceIP
	if ip == "" {
		ip = "127.0.0.1"
	}
	userAgent := session.UserAgent
	if userAgent == "" {
		userAgent = "New API session"
	}
	return map[string]any{
		"sid":            session.ID,
		"current":        true,
		"login_method":   "password",
		"ip":             ip,
		"user_agent":     userAgent,
		"created_at":     created,
		"last_active_at": lastActive,
		"expires_at":     lastActive + int64((30 * time.Minute).Seconds()),
	}
}

func newAPIAuthBundle(user model.HoneyUser, session Session) map[string]any {
	return map[string]any{
		"access_token":      security.MustRandomToken(32),
		"token_type":        "Bearer",
		"access_expires_at": time.Now().UTC().Add(time.Hour).Unix(),
		"user":              newAPIUserView(user),
		"session":           newAPISessionView(session),
	}
}

func newAPIPublicTokenView(token model.HoneyToken) map[string]any {
	status := 1
	if !token.DisabledAt.IsZero() {
		status = 2
	} else if !token.ExpiredAt.IsZero() && !token.ExpiredAt.After(time.Now().UTC()) {
		status = 3
	} else if !token.UnlimitedQuota && token.RemainQuota <= 0 {
		status = 4
	}
	expired := int64(-1)
	if !token.ExpiredAt.IsZero() {
		expired = token.ExpiredAt.Unix()
	}
	accessed := int64(0)
	if !token.LastUsedAt.IsZero() {
		accessed = token.LastUsedAt.Unix()
	}
	masked := strings.TrimPrefix(token.PrefixHint, "sk-")
	if masked == "" {
		masked = "proj-..."
	} else if !strings.HasSuffix(masked, "...") {
		masked += "..."
	}
	groups := append([]string(nil), token.AutoGroups...)
	if groups == nil {
		groups = []string{}
	}
	group := token.Group
	if group == "" {
		group = "default"
	}
	return map[string]any{
		"id":                   newAPIPublicTokenID(token),
		"name":                 token.Name,
		"key":                  masked,
		"status":               status,
		"remain_quota":         token.RemainQuota,
		"used_quota":           0,
		"unlimited_quota":      token.UnlimitedQuota,
		"expired_time":         expired,
		"created_time":         token.CreatedAt.Unix(),
		"accessed_time":        accessed,
		"group":                group,
		"auto_groups":          groups,
		"cross_group_retry":    token.CrossGroupRetry,
		"model_limits_enabled": len(token.ModelAllowlist) > 0,
		"model_limits":         strings.Join(token.ModelAllowlist, ","),
		"allow_ips":            token.AllowIPs,
	}
}

func newAPIKeySuffix(raw string) string {
	return strings.TrimPrefix(raw, "sk-")
}

func newAPIPublicTokenIDString(token model.HoneyToken) string {
	return strconv.FormatInt(newAPIPublicTokenID(token), 10)
}

// Raw honey keys are intentionally process-local. The durable store only
// contains a keyed fingerprint; a restart therefore invalidates the optional
// "reveal key" convenience without creating a recoverable secret at rest.
func (a *App) rememberNewAPIRawKey(tokenID, raw string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.newAPIRawKeys == nil {
		a.newAPIRawKeys = make(map[string]string)
	}
	a.newAPIRawKeys[tokenID] = raw
}

func (a *App) newAPIRawKey(tokenID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.newAPIRawKeys[tokenID]
}

func (a *App) forgetNewAPIRawKey(tokenID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.newAPIRawKeys, tokenID)
}

func newAPITokenIDForUser(tokens []model.HoneyToken, value string) (string, bool) {
	value, err := url.PathUnescape(strings.TrimSpace(value))
	if err != nil {
		return "", false
	}
	value = strings.TrimSuffix(value, "/")
	if value == "" || strings.ContainsAny(value, "/\\\r\n") {
		return "", false
	}
	if strings.HasPrefix(value, "ht_") {
		if _, ok := findHoneyToken(tokens, value); ok {
			return value, true
		}
		return "", false
	}
	publicID, err := strconv.ParseInt(value, 10, 64)
	if err != nil || publicID <= 0 {
		return "", false
	}
	for _, token := range tokens {
		if newAPIPublicTokenID(token) == publicID {
			return token.ID, true
		}
	}
	return "", false
}

func newAPITokenKeyIDForUser(tokens []model.HoneyToken, path string) (string, bool) {
	if !strings.HasPrefix(path, "/api/token/") || !strings.HasSuffix(path, "/key") {
		return "", false
	}
	value := strings.TrimSuffix(strings.TrimPrefix(path, "/api/token/"), "/key")
	return newAPITokenIDForUser(tokens, value)
}

func newAPIProfileModelIDs(catalog []profiles.CatalogEntry) []string {
	result := make([]string, 0, len(catalog))
	for _, entry := range catalog {
		if entry.ID != "" {
			result = append(result, entry.ID)
		}
	}
	return result
}

func newAPIVendorIcon(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "openai":
		return "OpenAI.Color"
	case "anthropic":
		return "Claude.Color"
	case "google", "gemini":
		return "Gemini.Color"
	default:
		return ""
	}
}

func newAPIPricingView(catalog []profiles.CatalogEntry) map[string]any {
	data := make([]map[string]any, 0, len(catalog))
	vendors := make([]map[string]any, 0)
	seenVendors := make(map[string]bool)
	for index, entry := range catalog {
		provider := entry.Provider
		if provider == "" {
			provider = "local"
		}
		vendorID := 0
		for i, vendor := range vendors {
			if vendor["name"] == provider {
				vendorID = i + 1
				break
			}
		}
		if vendorID == 0 {
			vendor := map[string]any{"id": len(vendors) + 1, "name": provider, "description": "Model catalog"}
			if icon := newAPIVendorIcon(provider); icon != "" {
				vendor["icon"] = icon
			}
			vendors = append(vendors, vendor)
			vendorID = len(vendors)
		}
		if !seenVendors[provider] {
			seenVendors[provider] = true
		}
		data = append(data, map[string]any{
			"id":                       index + 1,
			"model_name":               entry.ID,
			"description":              entry.DisplayName,
			"vendor_id":                vendorID,
			"vendor_name":              provider,
			"quota_type":               0,
			"model_ratio":              1,
			"completion_ratio":         1,
			"enable_groups":            []string{"default"},
			"supported_endpoint_types": []string{"openai", "anthropic", "gemini"},
			"capabilities":             append([]string(nil), entry.Capabilities...),
			"context_length":           entry.VirtualContextTokens,
			"model_price":              0,
			"group_ratio":              map[string]any{"default": 1},
		})
	}
	return map[string]any{
		"success":            true,
		"message":            "",
		"data":               data,
		"vendors":            vendors,
		"group_ratio":        map[string]any{"default": 1},
		"usable_group":       map[string]any{"default": map[string]any{"desc": "Default group", "ratio": 1}},
		"supported_endpoint": map[string]string{"openai": "OpenAI-compatible", "anthropic": "Anthropic Messages", "gemini": "Gemini"},
		"auto_groups":        []string{},
	}
}

func newAPIRankingsView() map[string]any {
	emptyHistory := map[string]any{"points": []any{}, "models": []any{}, "vendors": []any{}, "buckets": 0}
	return map[string]any{
		"success": true,
		"message": "",
		"data": map[string]any{
			"models":               []any{},
			"vendors":              []any{},
			"top_movers":           []any{},
			"top_droppers":         []any{},
			"models_history":       emptyHistory,
			"vendor_share_history": emptyHistory,
		},
	}
}

func newAPIUsageLog(event model.Event, user model.HoneyUser) map[string]any {
	created := event.ObservedAt.Unix()
	if created < 0 {
		created = 0
	}
	return map[string]any{
		"id":                  newAPIPublicID(event.EventID),
		"user_id":             newAPIPublicID(user.ID),
		"created_at":          created,
		"type":                2,
		"content":             "API request completed.",
		"username":            user.UsernameHint,
		"token_name":          "API key",
		"model_name":          event.ModelID,
		"quota":               event.SimulatedCost,
		"prompt_tokens":       event.SimulatedInputTokens,
		"completion_tokens":   event.SimulatedOutputTokens,
		"use_time":            event.DurationMS,
		"is_stream":           strings.Contains(event.RouteTemplate, "stream") || event.Metadata["stream"] == "true",
		"channel":             0,
		"channel_name":        "",
		"token_id":            0,
		"group":               "default",
		"other":               "{}",
		"request_id":          event.InvocationID,
		"upstream_request_id": "",
	}
}
