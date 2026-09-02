package app

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/oauth"
	"github.com/zcxads666/AegisLure/internal/packs"
	"github.com/zcxads666/AegisLure/internal/security"
)

func adminProfileName(value string) string {
	return strings.TrimPrefix(strings.TrimSpace(value), "inst_")
}

type importSourceRequest struct {
	ID            string `json:"id"`
	SourceType    string `json:"source_type"`
	RootPathAlias string `json:"root_path_alias"`
	Product       string `json:"product"`
	SchemaVersion string `json:"schema_version"`
}

const (
	importSourceDraft    = "Draft"
	importSourceValid    = "Validated"
	importSourceDryRun   = "DryRun"
	importSourceEnabled  = "Enabled"
	importSourceDisabled = "Disabled"
)

func (a *App) adminImportSourceRoute(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 && parts[0] == "import-sources" {
		switch r.Method {
		case http.MethodGet:
			a.adminImportSources(w)
		case http.MethodPost:
			a.adminImportSourceCreate(w, r)
		default:
			a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		}
		return
	}
	if len(parts) != 2 || parts[0] != "import-sources" || r.Method != http.MethodPost {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "import source route not found"})
		return
	}
	separator := strings.LastIndex(parts[1], ":")
	if separator <= 0 || separator == len(parts[1])-1 {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "import source action not found"})
		return
	}
	a.adminImportSourceAction(w, r, parts[1][:separator], parts[1][separator+1:])
}

func (a *App) adminImportSources(w http.ResponseWriter) {
	sources := a.store.ListImportSources()
	items := make([]map[string]any, 0, len(sources))
	for _, source := range sources {
		items = append(items, importSourceView(source))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"sources": items, "count": len(items), "filesystem_access": false, "online_fetch": false})
}

func (a *App) adminImportSourceCreate(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-import-source-create:"+requestSourceIP(r), 30, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 16*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "import source declaration too large"})
		return
	}
	var request importSourceRequest
	if err := decodeStrictValue(body, &request); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid import source declaration"})
		return
	}
	if strings.TrimSpace(request.ID) == "" {
		request.ID = "src_" + security.Fingerprint(a.cfg.InstanceKey, request.SourceType+"\x00"+request.RootPathAlias+"\x00"+request.Product+"\x00"+request.SchemaVersion)[:20]
	}
	if err := validateImportSourceDeclaration(request); err != nil {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	source := model.ImportSource{ID: strings.TrimSpace(request.ID), SourceType: strings.TrimSpace(request.SourceType), RootPathAlias: strings.TrimSpace(request.RootPathAlias), Product: strings.TrimSpace(request.Product), SchemaVersion: strings.TrimSpace(request.SchemaVersion), Lifecycle: importSourceDraft, ReadOnly: true}
	if err := a.store.CreateImportSource(source); err != nil {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	a.recordAudit(r, "import_source.create", source.ID, "success", map[string]string{"source_type": source.SourceType, "product": source.Product})
	a.writeJSON(w, http.StatusCreated, map[string]any{"source": importSourceView(source), "filesystem_access": false, "online_fetch": false})
}

func (a *App) adminImportSourceAction(w http.ResponseWriter, r *http.Request, id, action string) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-import-source-action:"+requestSourceIP(r), 60, time.Minute) {
		rateLimited(w)
		return
	}
	source, ok := a.store.GetImportSource(id)
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "import source not found"})
		return
	}
	now := time.Now().UTC()
	var update func(*model.ImportSource)
	var result map[string]any
	switch action {
	case "validate":
		update = func(value *model.ImportSource) { value.LastValidatedAt = now; value.Lifecycle = importSourceValid }
		result = map[string]any{"valid": true, "schema_allowlisted": true, "filesystem_access": false, "online_fetch": false}
	case "dry-run":
		update = func(value *model.ImportSource) { value.LastDryRunAt = now; value.Lifecycle = importSourceDryRun }
		result = map[string]any{"read": 0, "imported": 0, "duplicates": 0, "rejected": 0, "body_preview": "redacted_and_bounded", "provenance": true, "filesystem_access": false, "online_fetch": false}
	case "enable":
		update = func(value *model.ImportSource) { value.Enabled = true; value.Lifecycle = importSourceEnabled }
		result = map[string]any{"enabled": true}
	case "disable":
		update = func(value *model.ImportSource) { value.Enabled = false; value.Lifecycle = importSourceDisabled }
		result = map[string]any{"enabled": false}
	default:
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported import source action"})
		return
	}
	if err := a.store.UpdateImportSource(id, update); err != nil {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}
	source, _ = a.store.GetImportSource(id)
	a.recordAudit(r, "import_source."+action, id, "success", nil)
	result["source"] = importSourceView(source)
	a.writeJSON(w, http.StatusOK, result)
}

func validateImportSourceDeclaration(request importSourceRequest) error {
	if !safeControlIdentifier(request.ID, 64) {
		return errors.New("id must be 1-64 ASCII identifier characters")
	}
	if request.SourceType != "promptpot-jsonl" && request.SourceType != "tpot-jsonl" {
		return errors.New("source_type must be promptpot-jsonl or tpot-jsonl")
	}
	if !safeControlIdentifier(request.RootPathAlias, 128) || strings.HasPrefix(request.RootPathAlias, ".") {
		return errors.New("root_path_alias must be a non-path installation alias")
	}
	switch request.Product {
	case model.ProductNewAPI, model.ProductVLLM, model.ProductOllama, model.ProductSGLang, model.ProductLocalAI:
	default:
		return errors.New("product is not allowlisted")
	}
	if !safeControlIdentifier(request.SchemaVersion, 128) {
		return errors.New("schema_version must be a bounded identifier")
	}
	return nil
}

func safeControlIdentifier(value string, limit int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > limit {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' && char != '_' && char != '.' {
			return false
		}
	}
	return true
}

func importSourceView(source model.ImportSource) map[string]any {
	return map[string]any{"id": source.ID, "source_type": source.SourceType, "root_path_alias": source.RootPathAlias, "product": source.Product, "schema_version": source.SchemaVersion, "lifecycle": source.Lifecycle, "enabled": source.Enabled, "read_only": true, "read_count": source.ReadCount, "imported_count": source.ImportedCount, "duplicate_count": source.DuplicateCount, "rejected_count": source.RejectedCount, "last_validated_at": source.LastValidatedAt, "last_dry_run_at": source.LastDryRunAt, "last_imported_at": source.LastImportedAt, "created_at": source.CreatedAt, "updated_at": source.UpdatedAt, "filesystem_access": false, "online_fetch": false}
}

type indicatorQueryError struct {
	message string
}

func (e *indicatorQueryError) Error() string {
	return e.message
}

func invalidIndicatorQuery(message string) error {
	return &indicatorQueryError{message: message}
}

func indicatorQueryInt(r *http.Request, name string, fallback int) (int, error) {
	value := strings.TrimSpace(r.URL.Query().Get(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, invalidIndicatorQuery(name + " must be an integer")
	}
	return parsed, nil
}

func (a *App) filteredIndicators(r *http.Request) ([]model.Indicator, map[string]model.IndicatorDecision, error) {
	items, err := a.store.Indicators()
	if err != nil {
		return nil, nil, err
	}
	statusFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	if statusFilter == "" {
		statusFilter = "all"
	}
	if statusFilter != "all" && statusFilter != "pending" && statusFilter != "approved" && statusFilter != "ignored" && statusFilter != "revoked" && statusFilter != "expired" {
		return nil, nil, invalidIndicatorQuery(fmt.Sprintf("unsupported indicator status %q", statusFilter))
	}
	confidenceFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("confidence")))
	if confidenceFilter != "" && confidenceFilter != "low" && confidenceFilter != "medium" && confidenceFilter != "high" {
		return nil, nil, invalidIndicatorQuery(fmt.Sprintf("unsupported indicator confidence %q", confidenceFilter))
	}
	minScore, err := indicatorQueryInt(r, "min_score", 0)
	if err != nil {
		return nil, nil, err
	}
	if minScore < 0 || minScore > 100 {
		return nil, nil, invalidIndicatorQuery("min_score must be between 0 and 100")
	}
	minSensors, err := indicatorQueryInt(r, "min_sensor_count", 0)
	if err != nil {
		return nil, nil, err
	}
	if minSensors < 0 {
		return nil, nil, invalidIndicatorQuery("min_sensor_count must not be negative")
	}
	if siteID := strings.TrimSpace(r.URL.Query().Get("site_id")); siteID != "" && siteID != "all" && siteID != "local" {
		return nil, nil, invalidIndicatorQuery("standalone only supports site_id=all or local")
	}
	var seenSince time.Time
	if value := strings.TrimSpace(r.URL.Query().Get("seen_since")); value != "" {
		parsed, parseErr := time.Parse(time.RFC3339Nano, value)
		if parseErr != nil {
			return nil, nil, invalidIndicatorQuery("seen_since must be RFC3339")
		}
		seenSince = parsed.UTC()
	}
	decisions := make(map[string]model.IndicatorDecision)
	for _, decision := range a.store.ListIndicatorDecisions() {
		decisions[decision.IP] = decision
	}
	now := time.Now().UTC()
	filtered := make([]model.Indicator, 0, len(items))
	for _, item := range items {
		if item.Score < minScore || item.SensorCount < minSensors || (confidenceFilter != "" && item.Confidence != confidenceFilter) || (!seenSince.IsZero() && item.LastSeen.Before(seenSince)) {
			continue
		}
		if statusFilter != "all" && indicatorDecisionStatus(decisions[item.IP], now) != statusFilter {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered, decisions, nil
}

func indicatorDecisionStatus(decision model.IndicatorDecision, now time.Time) string {
	if decision.Status == "" {
		return "pending"
	}
	if (decision.Status == "approved" || decision.Status == "ignored" || decision.Status == "challenge") && !decision.ExpiresAt.IsZero() && !decision.ExpiresAt.After(now) {
		return "expired"
	}
	return decision.Status
}

func indicatorID(key, ip string) string {
	return "ind_" + security.Fingerprint(key, "indicator\x00"+ip)[:24]
}

func indicatorView(item model.Indicator, decision model.IndicatorDecision, key string) map[string]any {
	status := indicatorDecisionStatus(decision, time.Now().UTC())
	return map[string]any{
		"id": indicatorID(key, item.IP), "ip": item.IP, "score": item.Score, "confidence": item.Confidence,
		"first_seen": item.FirstSeen, "last_seen": item.LastSeen, "expires_at": item.ExpiresAt,
		"reason_codes": item.ReasonCodes, "products": item.Products, "sensor_count": item.SensorCount, "site_count": item.SiteCount,
		"recommended_action": item.RecommendedAction, "evidence_count": item.EvidenceCount, "status": status,
		"decision_reviewer": decision.Reviewer, "decision_reason": decision.Reason, "decision_expires_at": decision.ExpiresAt,
	}
}

func addIndicatorGeoView(view map[string]any, location ipInfoResult) {
	country := firstNonEmpty(location.Country, sourceCountryLabel(location.IP))
	view["country"] = country
	view["country_code"] = location.CountryCode
	view["city"] = location.City
	view["region"] = location.Region
	view["region_code"] = location.RegionCode
	view["postal_code"] = location.PostalCode
	view["latitude"] = location.Latitude
	view["longitude"] = location.Longitude
	view["timezone"] = location.Timezone
	view["asn"] = location.ASN
	view["as_name"] = location.ASName
	view["as_domain"] = location.ASDomain
	view["continent"] = location.Continent
	view["continent_code"] = location.ContinentCode
	view["geo_source"] = location.Source
	view["geo_status"] = location.Status
}

func renderIndicatorExport(items []model.Indicator, decisions map[string]model.IndicatorDecision, format, key string) (string, string, error) {
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "json", "":
		views := make([]map[string]any, 0, len(items))
		for _, item := range items {
			views = append(views, indicatorView(item, decisions[item.IP], key))
		}
		data, err := json.MarshalIndent(views, "", "  ")
		return string(data), "application/json; charset=utf-8", err
	case "plain", "txt":
		var builder strings.Builder
		for _, item := range items {
			builder.WriteString(item.IP)
			builder.WriteByte('\n')
		}
		return builder.String(), "text/plain; charset=utf-8", nil
	case "csv":
		var buffer bytes.Buffer
		writer := csv.NewWriter(&buffer)
		if err := writer.Write([]string{"id", "ip", "score", "confidence", "status", "first_seen", "last_seen", "expires_at", "reason_codes"}); err != nil {
			return "", "", err
		}
		for _, item := range items {
			decision := decisions[item.IP]
			values := []string{indicatorID(key, item.IP), item.IP, fmt.Sprintf("%d", item.Score), item.Confidence, indicatorDecisionStatus(decision, time.Now().UTC()), item.FirstSeen.Format(time.RFC3339), item.LastSeen.Format(time.RFC3339), item.ExpiresAt.Format(time.RFC3339), strings.Join(item.ReasonCodes, "|")}
			for i, value := range values {
				if strings.HasPrefix(value, "=") || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "@") {
					values[i] = "'" + value
				}
			}
			if err := writer.Write(values); err != nil {
				return "", "", err
			}
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return "", "", err
		}
		return buffer.String(), "text/csv; charset=utf-8", nil
	case "stix2":
		objects := make([]map[string]any, 0, len(items))
		for _, item := range items {
			ip := net.ParseIP(item.IP)
			if ip == nil {
				continue
			}
			objectType := "ipv4-addr"
			if ip.To4() == nil {
				objectType = "ipv6-addr"
			}
			hash := security.Fingerprint(key, "stix-indicator\x00"+item.IP)
			objectID := "indicator--" + hash[:8] + "-" + hash[8:12] + "-" + hash[12:16] + "-" + hash[16:20] + "-" + hash[20:32]
			decision := decisions[item.IP]
			objects = append(objects, map[string]any{"type": "indicator", "spec_version": "2.1", "id": objectID, "created": item.FirstSeen.UTC(), "modified": item.LastSeen.UTC(), "name": "AegisLure local IP indicator", "pattern": "[" + objectType + ":value = '" + item.IP + "']", "pattern_type": "stix", "valid_from": item.FirstSeen.UTC(), "valid_until": item.ExpiresAt.UTC(), "labels": []string{"aegislure:" + indicatorDecisionStatus(decision, time.Now().UTC())}, "confidence": item.Score, "x_aegislure_reason_codes": item.ReasonCodes})
		}
		bundleParts := make([]string, 0, len(objects))
		for _, item := range items {
			bundleParts = append(bundleParts, item.IP+"\x00"+indicatorDecisionStatus(decisions[item.IP], time.Now().UTC()))
		}
		sort.Strings(bundleParts)
		bundleHash := security.Fingerprint(key, "stix-bundle\x00"+strings.Join(bundleParts, "\x00"))
		bundleID := "bundle--" + bundleHash[:8] + "-" + bundleHash[8:12] + "-" + bundleHash[12:16] + "-" + bundleHash[16:20] + "-" + bundleHash[20:32]
		data, err := json.MarshalIndent(map[string]any{"type": "bundle", "id": bundleID, "objects": objects}, "", "  ")
		return string(data), "application/stix+json; charset=utf-8", err
	case "nftables":
		ipv4, ipv6 := make([]string, 0), make([]string, 0)
		for _, item := range items {
			if indicatorDecisionStatus(decisions[item.IP], time.Now().UTC()) != "approved" {
				continue
			}
			ip := net.ParseIP(item.IP)
			if ip == nil {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				ipv4 = append(ipv4, ip4.String())
			} else {
				ipv6 = append(ipv6, ip.String())
			}
		}
		var builder strings.Builder
		builder.WriteString("# AegisLure standalone approved indicators; every decision has an expiry.\n")
		builder.WriteString("table inet aegislure {\n")
		if len(ipv4) > 0 {
			builder.WriteString("  set approved_ipv4 { type ipv4_addr; flags interval; elements = { ")
			builder.WriteString(strings.Join(ipv4, ", "))
			builder.WriteString(" } }\n")
		}
		if len(ipv6) > 0 {
			builder.WriteString("  set approved_ipv6 { type ipv6_addr; flags interval; elements = { ")
			builder.WriteString(strings.Join(ipv6, ", "))
			builder.WriteString(" } }\n")
		}
		builder.WriteString("}\n")
		return builder.String(), "text/plain; charset=utf-8", nil
	default:
		return "", "", fmt.Errorf("unsupported indicator export format %q", format)
	}
}

func indicatorExportExtension(format string) string {
	switch format {
	case "stix2", "json":
		return "json"
	case "nftables":
		return "nft"
	case "plain", "txt":
		return "txt"
	case "csv":
		return "csv"
	default:
		return format
	}
}

func (a *App) adminIndicatorAction(w http.ResponseWriter, r *http.Request, path string) {
	separator := strings.LastIndex(path, ":")
	if separator <= 0 || separator == len(path)-1 {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "indicator action not found"})
		return
	}
	identifier, action := path[:separator], path[separator+1:]
	items, err := a.store.Indicators()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "indicator query failed"})
		return
	}
	decisions := make(map[string]model.IndicatorDecision)
	for _, decision := range a.store.ListIndicatorDecisions() {
		decisions[decision.IP] = decision
	}
	var item model.Indicator
	found := false
	decoded, decodeErr := url.PathUnescape(identifier)
	if decodeErr == nil {
		if ip := net.ParseIP(decoded); ip != nil {
			decoded = ip.String()
			for _, candidate := range items {
				if candidate.IP == decoded {
					item, found = candidate, true
					break
				}
			}
		} else {
			for _, candidate := range items {
				if indicatorID(a.cfg.InstanceKey, candidate.IP) == decoded {
					item, found = candidate, true
					break
				}
			}
		}
	}
	if !found {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "indicator not found"})
		return
	}
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-indicator-action:"+requestSourceIP(r), 60, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 8*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "indicator decision too large"})
		return
	}
	var request struct {
		Reason     string `json:"reason"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := decodeStrictValue(body, &request); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid indicator decision"})
			return
		}
	}
	if len(request.Reason) > 256 || strings.ContainsAny(request.Reason, "\r\n") {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "reason is invalid"})
		return
	}
	now := time.Now().UTC()
	decision := decisions[item.IP]
	decision.IP = item.IP
	decision.Reviewer = a.auditActor(r)
	decision.Reason = strings.TrimSpace(request.Reason)
	switch action {
	case "approve", "ignore":
		if request.TTLSeconds == 0 {
			request.TTLSeconds = int(time.Until(item.ExpiresAt).Seconds())
			if request.TTLSeconds < 3600 {
				request.TTLSeconds = 3600
			}
		}
		if request.TTLSeconds < 60 || request.TTLSeconds > 7*24*60*60 {
			a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "ttl_seconds must be between 60 and 604800"})
			return
		}
		decision.Status = map[string]string{"approve": "approved", "ignore": "ignored"}[action]
		decision.ExpiresAt = now.Add(time.Duration(request.TTLSeconds) * time.Second)
	case "revoke":
		decision.Status = "revoked"
		decision.ExpiresAt = now
	default:
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported indicator action"})
		return
	}
	if err := a.store.SetIndicatorDecision(decision); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "indicator decision save failed"})
		return
	}
	a.recordAudit(r, "indicator."+action, item.IP, "success", map[string]string{"status": decision.Status, "expires_at": decision.ExpiresAt.Format(time.RFC3339)})
	a.writeJSON(w, http.StatusOK, map[string]any{"indicator": indicatorView(item, decision, a.cfg.InstanceKey), "decision": decision, "permanent_block": false})
}

func (a *App) adminIdentityIndicatorAction(w http.ResponseWriter, r *http.Request, path string) {
	separator := strings.LastIndex(path, ":")
	if separator <= 0 || separator == len(path)-1 {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity indicator action not found"})
		return
	}
	identityID, action := path[:separator], path[separator+1:]
	identityID, err := url.PathUnescape(identityID)
	if err != nil || identityID == "" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity indicator not found"})
		return
	}
	found := false
	for _, identity := range a.store.ListHoneyIdentities() {
		if identity.ID == identityID {
			found = true
			break
		}
	}
	if !found {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity indicator not found"})
		return
	}
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-identity-indicator-action:"+requestSourceIP(r), 60, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 8*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "identity decision too large"})
		return
	}
	var request struct {
		Reason     string `json:"reason"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := decodeStrictValue(body, &request); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid identity decision"})
			return
		}
	}
	if len(request.Reason) > 256 || strings.ContainsAny(request.Reason, "\r\n") {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "reason is invalid"})
		return
	}
	now := time.Now().UTC()
	decision := model.IdentityIndicatorDecision{IdentityID: identityID, Reviewer: a.auditActor(r), Reason: strings.TrimSpace(request.Reason)}
	switch action {
	case "approve", "challenge":
		if request.TTLSeconds == 0 {
			request.TTLSeconds = 24 * 60 * 60
		}
		if request.TTLSeconds < 60 || request.TTLSeconds > 7*24*60*60 {
			a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "ttl_seconds must be between 60 and 604800"})
			return
		}
		decision.Status = action
		decision.ExpiresAt = now.Add(time.Duration(request.TTLSeconds) * time.Second)
	case "revoke":
		decision.Status = "revoked"
		decision.ExpiresAt = now
		if err := a.store.RevokeHoneyIdentity(identityID); err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": "identity revoke failed"})
			return
		}
	default:
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported identity indicator action"})
		return
	}
	if err := a.store.SetIdentityIndicatorDecision(decision); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "identity decision save failed"})
		return
	}
	a.recordAudit(r, "identity_indicator."+action, identityID, "success", map[string]string{"status": decision.Status, "expires_at": decision.ExpiresAt.Format(time.RFC3339)})
	a.writeJSON(w, http.StatusOK, map[string]any{"identity_id": identityID, "decision": decision, "cross_site_feed": false, "permanent_block": false})
}

func (a *App) adminInstanceRoute(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance not found"})
		return
	}
	name := adminProfileName(parts[0])
	if _, ok := a.profiles[name]; !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance not found"})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		a.adminInstanceDetail(w, name)
		return
	}
	if len(parts) == 2 && parts[1] == "compatibility" && r.Method == http.MethodGet {
		a.adminInstanceCompatibility(w, name)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodPatch {
		a.adminInstancePatch(w, r, name)
		return
	}
	a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance route not found"})
}

func (a *App) adminInstanceCreate(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-instance-create:"+requestSourceIP(r), 30, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 16*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "instance declaration too large"})
		return
	}
	var request struct {
		Product  string  `json:"product"`
		Enabled  *bool   `json:"enabled"`
		Scenario *string `json:"scenario"`
		Port     *int    `json:"port"`
	}
	if err := decodeStrictValue(body, &request); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid instance declaration"})
		return
	}
	name := adminProfileName(request.Product)
	if _, ok := a.profiles[name]; !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "profile not found"})
		return
	}
	if request.Scenario != nil && (strings.TrimSpace(*request.Scenario) == "" || len(*request.Scenario) > 128 || strings.ContainsAny(*request.Scenario, "\r\n")) {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "scenario is invalid"})
		return
	}
	if request.Port != nil {
		if _, err := a.moveProfilePort(name, portMoveRequest{Port: *request.Port}, false); err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
	}
	if request.Scenario != nil {
		if a.cfg.Scenario == nil {
			a.cfg.Scenario = make(map[string]string)
		}
		a.cfg.Scenario[name] = strings.TrimSpace(*request.Scenario)
		profile := a.profiles[name]
		profile.Scenario = a.cfg.Scenario[name]
		a.profiles[name] = profile
		if err := config.Save(configPathForApp(), a.cfg); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "instance configuration save failed"})
			return
		}
	}
	if request.Enabled != nil {
		if *request.Enabled {
			if err := a.startProfile(name); err != nil {
				a.writeJSON(w, http.StatusConflict, map[string]string{"error": "instance start failed: " + err.Error()})
				return
			}
		} else if err := a.stopProfile(name); err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": "instance stop failed: " + err.Error()})
			return
		}
		if err := a.persistProfileSelection(name, *request.Enabled); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "instance configuration save failed"})
			return
		}
	}
	a.recordAudit(r, "instance.create", "inst_"+name, "success", map[string]string{"enabled": fmt.Sprintf("%t", request.Enabled != nil && *request.Enabled)})
	a.adminInstanceDetail(w, name)
}

func (a *App) adminInstanceDetail(w http.ResponseWriter, name string) {
	view, ok := a.instanceView(name)
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"instance": view})
}

func (a *App) instanceView(name string) (map[string]any, bool) {
	profile, ok := a.profiles[name]
	if !ok {
		return nil, false
	}
	profile = a.applyRuntimePacks(profile)
	a.serverMu.RLock()
	running := a.profileServers[name] != nil
	actualPort := a.actualProfilePortLocked(name)
	portRevision := a.portRevisionLocked(name, actualPort)
	a.serverMu.RUnlock()
	if actualPort == 0 {
		actualPort = profile.DefaultPort
	}
	bound := make(map[string]map[string]string)
	for _, kind := range []string{model.PackKindFingerprint, model.PackKindModel, model.PackKindScenario, model.PackKindDetector} {
		if pack, found := a.store.BoundPack(kind, "inst_"+name); found {
			bound[kind] = map[string]string{"id": pack.ID, "revision": pack.Revision, "lifecycle": pack.Lifecycle}
		}
	}
	return map[string]any{
		"id":                   "inst_" + name,
		"product":              name,
		"profile_id":           profile.ID,
		"display_version":      profile.DisplayVersion,
		"port":                 actualPort,
		"port_pool":            append([]int(nil), a.cfg.PortPools[name]...),
		"port_revision":        portRevision,
		"scenario":             profile.Scenario,
		"effect_scope":         profile.EffectScope,
		"effect_ttl_seconds":   int(profile.EffectTTL / time.Second),
		"state":                map[bool]string{true: "running", false: "stopped"}[running],
		"enabled":              containsString(a.cfg.EnabledProfiles, name),
		"endpoint":             fmt.Sprintf("%s:%d", a.cfg.PublicBind, actualPort),
		"synthetic_only":       true,
		"bound_pack_revisions": bound,
	}, true
}

func (a *App) adminInstancePatch(w http.ResponseWriter, r *http.Request, name string) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-instance-patch:"+name, 30, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 16*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "instance patch too large"})
		return
	}
	var request struct {
		Enabled          *bool   `json:"enabled"`
		Scenario         *string `json:"scenario"`
		Port             *int    `json:"port"`
		Protocol         string  `json:"protocol"`
		DrainSeconds     int     `json:"drain_seconds"`
		ExpectedRevision string  `json:"expected_revision"`
	}
	if err := decodeStrictValue(body, &request); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid instance patch"})
		return
	}
	if request.Enabled == nil && request.Scenario == nil && request.Port == nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "instance patch is empty"})
		return
	}
	if request.Scenario != nil && (strings.TrimSpace(*request.Scenario) == "" || len(*request.Scenario) > 128 || strings.ContainsAny(*request.Scenario, "\r\n")) {
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "scenario is invalid"})
		return
	}
	if request.Port != nil {
		result, err := a.moveProfilePort(name, portMoveRequest{Port: *request.Port, Protocol: request.Protocol, DrainSeconds: request.DrainSeconds, ExpectedRevision: request.ExpectedRevision}, false)
		if err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		if result.Applied {
			a.recordAudit(r, "instance.move_port", "inst_"+name, "success", map[string]string{"from_port": fmt.Sprintf("%d", result.CurrentPort), "to_port": fmt.Sprintf("%d", result.DesiredPort), "revision": result.DesiredRevision})
		}
	}
	if request.Scenario != nil {
		previous := a.profiles[name]
		previousScenario := a.cfg.Scenario[name]
		if a.cfg.Scenario == nil {
			a.cfg.Scenario = make(map[string]string)
		}
		a.cfg.Scenario[name] = strings.TrimSpace(*request.Scenario)
		updated := previous
		updated.Scenario = a.cfg.Scenario[name]
		a.profiles[name] = updated
		if err := config.Save(configPathForApp(), a.cfg); err != nil {
			a.cfg.Scenario[name] = previousScenario
			a.profiles[name] = previous
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "instance configuration save failed"})
			return
		}
		a.recordAudit(r, "instance.scenario.update", "inst_"+name, "success", map[string]string{"scenario": updated.Scenario})
	}
	if request.Enabled != nil {
		var err error
		if *request.Enabled {
			err = a.startProfile(name)
		} else {
			err = a.stopProfile(name)
		}
		if err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": "instance state change failed: " + err.Error()})
			return
		}
		if err := a.persistProfileSelection(name, *request.Enabled); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "instance configuration save failed"})
			return
		}
		a.recordAudit(r, "instance.enabled.update", "inst_"+name, "success", map[string]string{"enabled": fmt.Sprintf("%t", *request.Enabled)})
	}
	a.adminInstanceDetail(w, name)
}

func (a *App) adminInstanceCompatibility(w http.ResponseWriter, name string) {
	profile, ok := a.profiles[name]
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance not found"})
		return
	}
	profile = a.applyRuntimePacks(profile)
	manifest := map[string]any{"source": "built-in safe contract", "dangerous_parsers": false, "outbound_network": false}
	if pack, found := a.store.BoundPack(model.PackKindFingerprint, "inst_"+name); found {
		var document packs.FingerprintPackDocument
		if json.Unmarshal(pack.Definition, &document) == nil && document.CompatibilityManifest != nil {
			manifest = document.CompatibilityManifest
		}
	}
	modelRevision := "compiled-default"
	if pack, found := a.store.BoundPack(model.PackKindModel, "inst_"+name); found {
		modelRevision = pack.Revision
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"instance_id":            "inst_" + name,
		"product":                name,
		"profile_id":             profile.ID,
		"display_version":        profile.DisplayVersion,
		"routes":                 compatibilityRoutes(name),
		"fingerprint_manifest":   manifest,
		"model_catalog_revision": modelRevision,
		"scenario":               profile.Scenario,
		"synthetic_only":         true,
		"real_inference":         false,
		"outbound_network":       false,
	})
}

func compatibilityRoutes(product string) []string {
	routes := map[string][]string{
		model.ProductNewAPI:  {"/", "/login", "/sign-in", "/register", "/sign-up", "/forgot-password", "/forget-password", "/dashboard", "/models", "/pricing", "/docs", "/keys", "/token", "/usage", "/usage-logs", "/profile", "/api/status", "/api/user/login", "/api/user/register", "/api/user/logout", "/api/user/self", "/api/user/", "/api/user/forgot-password", "/api/user/forget-password", "/api/user/checkin", "/api/user/bind", "/api/user/logs", "/api/log", "/api/oauth/state", "/api/oauth/{provider}/start", "/api/oauth/{provider}/callback", "/api/token", "/api/token/{id}", "/api/video/{id}", "/api/stripe/webhook", "/v1/models", "/v1/models/{model}", "/v1/messages", "/v1/chat/completions", "/v1/completions", "/v1/responses", "/v1/embeddings", "/v1beta/models", "/v1beta/models/{model}:generateContent", "/v1beta/models/{model}:streamGenerateContent", "/v1beta/openai/models"},
		model.ProductVLLM:    {"/", "/health", "/version", "/metrics", "/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/responses", "/v1/embeddings", "/invocations", "/docs", "/openapi.json"},
		model.ProductOllama:  {"/", "/api/version", "/api/tags", "/api/ps", "/api/show", "/api/generate", "/api/chat", "/api/embeddings", "/v1/models", "/v1/chat/completions", "/v1/embeddings"},
		model.ProductSGLang:  {"/health", "/get_model_info", "/metrics", "/docs", "/redoc", "/openapi.json", "/server_info", "/dumper", "/generate", "/load_lora_adapter_from_tensors", "/update_weights_from_disk", "/flush_cache", "/get_weights_by_name", "/v1/models", "/v1/chat/completions"},
		model.ProductLocalAI: {"/", "/readyz", "/healthz", "/metrics", "/swagger", "/openapi.json", "/models/available", "/models/apply", "/models/installed", "/models/delete", "/models/jobs/{id}", "/v1/models", "/v1/chat/completions", "/v1/completions", "/v1/responses", "/v1/embeddings", "/v1/audio/transcriptions", "/v1/audio/speech", "/v1/images/generations"},
	}
	return append([]string(nil), routes[product]...)
}

func (a *App) adminEventDetail(w http.ResponseWriter, _ *http.Request, eventID string) {
	eventID, err := url.PathUnescape(strings.TrimSpace(eventID))
	if err != nil || eventID == "" || strings.Contains(eventID, "/") {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
		return
	}
	events, err := a.store.Events(-1, "", "")
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "event query failed"})
		return
	}
	for _, event := range events {
		if event.EventID == eventID {
			a.writeJSON(w, http.StatusOK, map[string]any{"event": event, "raw_payload_available": false, "payload_view": "bounded_redacted_preview_only"})
			return
		}
	}
	a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
}

type localSessionView struct {
	ID              string    `json:"id"`
	Product         string    `json:"product"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	EventCount      int       `json:"event_count"`
	InvocationCount int       `json:"invocation_count"`
	SourceIPs       []string  `json:"source_ips"`
}

func (a *App) sessionViews(events []model.Event) []localSessionView {
	byID := make(map[string]*localSessionView)
	for _, event := range events {
		if event.SessionID == "" {
			continue
		}
		view := byID[event.SessionID]
		if view == nil {
			view = &localSessionView{ID: event.SessionID, Product: event.Product, FirstSeen: event.ObservedAt, LastSeen: event.ObservedAt}
			byID[event.SessionID] = view
		}
		if event.ObservedAt.Before(view.FirstSeen) {
			view.FirstSeen = event.ObservedAt
		}
		if event.ObservedAt.After(view.LastSeen) {
			view.LastSeen = event.ObservedAt
		}
		view.EventCount++
		if event.InvocationID != "" {
			view.InvocationCount++
		}
		if !containsString(view.SourceIPs, event.SourceIP) && event.SourceIP != "" {
			view.SourceIPs = append(view.SourceIPs, event.SourceIP)
		}
	}
	a.mu.Lock()
	for _, session := range a.sessions {
		if _, exists := byID[session.ID]; exists {
			continue
		}
		byID[session.ID] = &localSessionView{ID: session.ID, Product: session.Product, FirstSeen: session.CreatedAt, LastSeen: session.LastSeen}
	}
	a.mu.Unlock()
	result := make([]localSessionView, 0, len(byID))
	for _, view := range byID {
		sort.Strings(view.SourceIPs)
		result = append(result, *view)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].LastSeen.After(result[j].LastSeen) })
	return result
}

func (a *App) adminSessionsList(w http.ResponseWriter, r *http.Request) {
	events, err := a.store.Events(-1, r.URL.Query().Get("product"), r.URL.Query().Get("ip"))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session query failed"})
		return
	}
	items := a.sessionViews(events)
	limit := queryInt(r, "limit", 100)
	if limit < 1 || limit > 1000 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 1000"})
		return
	}
	if len(items) > limit {
		items = items[:limit]
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"sessions": items, "count": len(items), "synthetic_only": true})
}

func (a *App) adminSessionDetail(w http.ResponseWriter, r *http.Request, sessionID string) {
	sessionID, err := url.PathUnescape(strings.TrimSpace(sessionID))
	if err != nil || sessionID == "" || strings.Contains(sessionID, "/") {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	events, err := a.store.Events(-1, "", "")
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session query failed"})
		return
	}
	filtered := make([]model.Event, 0)
	for _, event := range events {
		if event.SessionID == sessionID {
			filtered = append(filtered, event)
		}
	}
	views := a.sessionViews(filtered)
	if len(views) == 0 {
		a.mu.Lock()
		_, exists := a.sessions[sessionID]
		a.mu.Unlock()
		if !exists {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
			return
		}
		views = a.sessionViews(nil)
		for _, item := range views {
			if item.ID == sessionID {
				views = []localSessionView{item}
				break
			}
		}
	}
	var view localSessionView
	for _, item := range views {
		if item.ID == sessionID {
			view = item
			break
		}
	}
	if view.ID == "" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"session": view, "events": filtered, "raw_payload_available": false, "synthetic_only": true})
}

func (a *App) adminInvocationDetail(w http.ResponseWriter, r *http.Request, invocationID string) {
	invocationID, err := url.PathUnescape(strings.TrimSpace(invocationID))
	if err != nil || invocationID == "" || strings.Contains(invocationID, "/") {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "invocation not found"})
		return
	}
	events, err := a.store.Events(-1, r.URL.Query().Get("product"), "")
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invocation query failed"})
		return
	}
	matched := make([]model.Event, 0)
	for _, event := range events {
		if event.InvocationID == invocationID {
			matched = append(matched, event)
		}
	}
	if len(matched) == 0 {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "invocation not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"invocation_id": invocationID, "events": matched, "event_count": len(matched), "synthetic_only": true, "real_inference": false})
}

func (a *App) adminInteractionChainDetail(w http.ResponseWriter, _ *http.Request, chainID string) {
	chainID, err := url.PathUnescape(strings.TrimSpace(chainID))
	if err != nil || chainID == "" || strings.Contains(chainID, "/") {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "interaction chain not found"})
		return
	}
	events, err := a.store.Events(-1, "", "")
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "chain query failed"})
		return
	}
	views := a.buildInteractionChainViews(events, a.store.InteractionChainConfig())
	for _, view := range views {
		if view.ID == chainID {
			a.writeJSON(w, http.StatusOK, map[string]any{"chain": view, "synthetic_only": true})
			return
		}
	}
	a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "interaction chain not found"})
}

func buildInteractionChainView(id, sessionID string, events []model.Event) *interactionChainView {
	view := &interactionChainView{ID: id, SessionID: sessionID, FirstEventID: "", LastEventID: "", InvocationLevel: model.L0, Events: append([]model.Event(nil), events...)}
	sessions := make(map[string]bool)
	for _, event := range events {
		if view.FirstEventID == "" {
			view.FirstEventID = event.EventID
		}
		view.LastEventID = event.EventID
		view.Product = event.Product
		view.EventCount++
		if event.SessionID != "" {
			sessions[event.SessionID] = true
		}
		if event.ObservedAt.After(view.LatestObservedAt) {
			view.LatestObservedAt = event.ObservedAt
		}
		if event.Sequence > view.LatestSequence {
			view.LatestSequence = event.Sequence
		}
		if event.Score > view.Score {
			view.Score = event.Score
		}
		if invocationRank(event.InvocationLevel) > invocationRank(view.InvocationLevel) {
			view.InvocationLevel = event.InvocationLevel
		}
		if event.IntentClass != "" {
			view.IntentClass = event.IntentClass
		}
		view.MatchedRuleIDs = uniqueStrings(append(view.MatchedRuleIDs, event.MatchedRuleIDs...))
		view.ReasonCodes = uniqueStrings(append(view.ReasonCodes, event.ReasonCodes...))
	}
	view.SessionCount = len(sessions)
	switch view.InvocationLevel {
	case model.L4:
		view.Stage = "post_call_verified"
	case model.L3:
		view.Stage = "response_consumed"
	case model.L2:
		view.Stage = "synthetic_accepted"
	case model.L1:
		view.Stage = "rejected_attempt"
	default:
		view.Stage = "discovery"
	}
	return view
}

func (a *App) adminActorDetail(w http.ResponseWriter, _ *http.Request, rawIP string) {
	ip, err := url.PathUnescape(strings.TrimSpace(rawIP))
	if err != nil || net.ParseIP(ip) == nil {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "actor not found"})
		return
	}
	events, err := a.store.Events(-1, "", ip)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "actor query failed"})
		return
	}
	indicators, err := a.store.Indicators()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "actor query failed"})
		return
	}
	var indicator model.Indicator
	found := false
	for _, item := range indicators {
		if item.IP == ip {
			indicator, found = item, true
			break
		}
	}
	if !found && len(events) == 0 {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "actor not found"})
		return
	}
	location := a.resolveIPInfo(ip)
	a.writeJSON(w, http.StatusOK, map[string]any{
		"ip": ip, "country": location.Country, "country_code": location.CountryCode,
		"continent": location.Continent, "continent_code": location.ContinentCode,
		"asn": location.ASN, "as_name": location.ASName, "as_domain": location.ASDomain,
		"geo_source": location.Source, "geo_status": location.Status, "geo": location,
		"indicator": indicator, "events": events, "event_count": len(events), "synthetic_only": true,
	})
}

func (a *App) adminIdentityIndicators(w http.ResponseWriter, _ *http.Request) {
	identities := a.store.ListHoneyIdentities()
	items := make([]map[string]any, 0, len(identities))
	decisions := make(map[string]model.IdentityIndicatorDecision)
	for _, decision := range a.store.ListIdentityIndicatorDecisions() {
		decisions[decision.IdentityID] = decision
	}
	now := time.Now().UTC()
	for _, identity := range identities {
		status := "local_only"
		if !identity.RevokedAt.IsZero() {
			status = "revoked"
		}
		decision := decisions[identity.ID]
		if decision.Status != "" && (decision.Status == "approved" || decision.Status == "challenge") && !decision.ExpiresAt.IsZero() && !decision.ExpiresAt.After(now) {
			status = "expired"
		} else if decision.Status != "" {
			status = decision.Status
		}
		items = append(items, map[string]any{"id": identity.ID, "provider": identity.Provider, "subject_hmac": identity.SubjectHMAC, "status": status, "confidence": "observed_association", "risk_score": 0, "cross_site_feed": "blocked", "approval_required": true, "policy_mode": identity.PolicyMode, "decision_reviewer": decision.Reviewer, "decision_reason": decision.Reason, "decision_expires_at": decision.ExpiresAt})
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "cross_site_feed": false, "permanent_block": false})
}

func (a *App) adminIdentityPolicyAction(w http.ResponseWriter, r *http.Request, path string) {
	providerText := strings.TrimSuffix(strings.TrimSpace(path), ":validate")
	if providerText == "" || providerText == path {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity policy action not found"})
		return
	}
	provider, ok := oauth.ParseProvider(providerText)
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported identity provider"})
		return
	}
	mode := "local_only"
	if provider == oauth.Discord {
		mode = "blocked"
	} else if provider == oauth.LinuxDO {
		mode = "pending_approval"
	}
	a.recordAudit(r, "identity.policy.validate", "identity-policy/"+providerText, "success", map[string]string{"mode": mode})
	a.writeJSON(w, http.StatusOK, map[string]any{"provider": provider, "valid": true, "mode": mode, "cross_site_feed": false, "raw_provider_id": false, "email": false, "token": false})
}

func (a *App) adminIdentityPolicies(w http.ResponseWriter) {
	policies := a.store.ListOAuthChannelPolicies()
	items := make([]map[string]any, 0, len(policies))
	for _, policy := range policies {
		items = append(items, map[string]any{
			"provider":   policy.Provider,
			"enabled":    policy.Enabled,
			"mode":       policy.Mode,
			"cross_site": policy.CrossSite,
			"updated_at": policy.UpdatedAt,
		})
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"providers": items})
}

type identityPolicyUpdateRequest struct {
	Enabled *bool `json:"enabled"`
}

func (a *App) adminIdentityPolicyUpdate(w http.ResponseWriter, r *http.Request, path string) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	providerText := strings.TrimSpace(path)
	provider, ok := oauth.ParseProvider(providerText)
	if !ok || providerText != string(provider) {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported identity provider"})
		return
	}
	body, tooLarge := readBoundedBody(r, 4*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "identity policy update too large"})
		return
	}
	var request identityPolicyUpdateRequest
	if err := decodeStrictValue(body, &request); err != nil || request.Enabled == nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "identity policy enabled flag is required"})
		return
	}
	policy, ok := a.store.GetOAuthChannelPolicy(string(provider))
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity policy not found"})
		return
	}
	policy.Enabled = *request.Enabled
	if err := a.store.SetOAuthChannelPolicy(policy); err != nil {
		a.writeJSON(w, http.StatusConflict, map[string]string{"error": "identity policy update failed"})
		return
	}
	policy, _ = a.store.GetOAuthChannelPolicy(string(provider))
	a.recordAudit(r, "identity.policy.update", "identity-policy/"+string(provider), "success", map[string]string{"enabled": fmt.Sprintf("%t", policy.Enabled)})
	a.writeJSON(w, http.StatusOK, map[string]any{
		"provider":   policy.Provider,
		"enabled":    policy.Enabled,
		"mode":       policy.Mode,
		"cross_site": policy.CrossSite,
		"updated_at": policy.UpdatedAt,
	})
}
