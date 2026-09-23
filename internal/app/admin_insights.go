package app

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/security"
)

const (
	insightAccount  = "account"
	insightKey      = "key"
	insightIdentity = "identity"
	insightDetect   = "detection"
)

type informationInsight struct {
	ID                      string            `json:"id"`
	IdentityType            string            `json:"identity_type"`
	SubjectFingerprint      string            `json:"subject_fingerprint"`
	SubjectFingerprints     []string          `json:"subject_fingerprints,omitempty"`
	IdentityTypes           []string          `json:"identity_types,omitempty"`
	IdentityCount           int               `json:"identity_count,omitempty"`
	RelatedAccount          string            `json:"related_account,omitempty"`
	RelatedKey              string            `json:"related_key,omitempty"`
	RelatedAccounts         []string          `json:"related_accounts,omitempty"`
	RelatedKeys             []string          `json:"related_keys,omitempty"`
	Products                []string          `json:"products,omitempty"`
	CreationIPs             []string          `json:"creation_ips,omitempty"`
	UsageIPs                []string          `json:"usage_ips,omitempty"`
	SourceIPs               []string          `json:"source_ips,omitempty"`
	DifferentIPCount        int               `json:"different_ip_count"`
	FirstSeen               time.Time         `json:"first_seen"`
	LastSeen                time.Time         `json:"last_seen"`
	EventCount              int               `json:"event_count"`
	Score                   int               `json:"score"`
	Events                  []model.Event     `json:"events"`
	DetectionFindings       []map[string]any  `json:"detection_findings,omitempty"`
	RootAccountGroup        bool              `json:"root_account_group,omitempty"`
	CreationEvidenceMissing bool              `json:"creation_evidence_missing,omitempty"`
	EventIDs                []string          `json:"-"`
	EventSourceIPs          map[string]string `json:"-"`
}

type insightAccumulator struct {
	view               informationInsight
	creationIPs        map[string]bool
	usageIPs           map[string]bool
	sourceIPs          map[string]bool
	products           map[string]bool
	eventIDs           map[string]bool
	creationSeen       bool
	usageSeen          bool
	rootExcluded       bool
	persistentIdentity bool
	eventCount         int
}

func (a *App) adminInsights(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	page, pageSize, query, err := adminPageParams(r)
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	product := strings.TrimSpace(r.URL.Query().Get("product"))
	events, err := a.store.EventSummariesContext(r.Context(), -1, product, "")
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "insight query failed"})
		return
	}
	items := a.buildInformationInsights(events)
	if query != "" {
		needle := strings.ToLower(query)
		filtered := items[:0]
		for _, item := range items {
			encoded, _ := json.Marshal(item)
			if strings.Contains(strings.ToLower(string(encoded)), needle) {
				filtered = append(filtered, item)
			}
		}
		items = filtered
	}
	pageItems, pagination := paginateAdminValues(items, page, pageSize)
	response := adminPagePayload(pagination)
	response["insights"] = pageItems
	response["items"] = pageItems
	response["count"] = len(pageItems)
	response["synthetic_only"] = true
	response["aggregation"] = map[string]any{
		"account":                "creation event + authenticated use event with a different source IP",
		"key":                    "key creation event + key use event with a different source IP",
		"ip_pair":                "each unordered source IP pair is emitted once with all linked identities and evidence",
		"legacy_identity":        "durable identity with missing historical creation evidence + use from at least two source IPs",
		"root_accounts_excluded": true,
	}
	a.writeJSON(w, http.StatusOK, response)
}

func (a *App) buildInformationInsights(events []model.Event) []informationInsight {
	accounts := make(map[string]*insightAccumulator)
	keys := make(map[string]*insightAccumulator)
	detections := make(map[string]*insightAccumulator)
	for _, user := range a.store.ListHoneyUsers() {
		if user.ID == "" || a.isNewAPIRootUser(user) {
			continue
		}
		accountID := security.Fingerprint(a.cfg.InstanceKey, "account\x00"+user.ID)[:20]
		account := newInsightAccumulator(a.cfg.InstanceKey, insightAccount, accountID)
		account.persistentIdentity = true
		account.addPersistedCreation(user.CreationIP, user.CreatedAt)
		accounts[accountID] = account
	}
	for _, token := range a.store.ListTokens("") {
		keyID := strings.TrimSpace(token.Hash)
		if keyID == "" {
			continue
		}
		key := newInsightAccumulator(a.cfg.InstanceKey, insightKey, keyID)
		key.persistentIdentity = true
		key.addPersistedCreation(token.CreationIP, token.CreatedAt)
		keys[keyID] = key
	}
	for _, event := range events {
		accountID, accountOK := a.insightAccountID(event)
		keyID := insightKeyID(event)
		isAccountCreation := isInsightAccountCreation(event)
		isKeyCreation := isInsightKeyCreation(event)
		isDetection := event.EventType == "frontend.detection.mismatch" && event.Metadata["detection_mismatch"] == "true" || event.EventType == "frontend.detection.report" && event.Metadata["detection_reported"] == "true"

		if accountOK {
			account := accounts[accountID]
			if account == nil {
				account = newInsightAccumulator(a.cfg.InstanceKey, insightAccount, accountID)
				accounts[accountID] = account
			}
			if isAccountCreation {
				account.creationSeen = true
				account.addCreation(event)
			} else if isInsightAccountUse(event) {
				account.usageSeen = true
				account.addUsage(event)
			}
			account.addEvent(event)
		}

		if keyID != "" {
			key := keys[keyID]
			if key == nil {
				key = newInsightAccumulator(a.cfg.InstanceKey, insightKey, keyID)
				keys[keyID] = key
			}
			if isKeyCreation {
				key.creationSeen = true
				key.addCreation(event)
			} else if isInsightKeyUse(event) {
				key.usageSeen = true
				key.addUsage(event)
			}
			key.addEvent(event)
		}

		if isDetection {
			id := "detection_" + security.Fingerprint(a.cfg.InstanceKey, event.EventID)[:20]
			detection := detections[id]
			if detection == nil {
				detection = newInsightAccumulator(a.cfg.InstanceKey, insightDetect, event.EventID)
				detection.view.ID = id
				detection.view.RelatedAccount = accountID
				detection.view.RelatedKey = keyID
				detections[id] = detection
			}
			detection.addEvent(event)
			detection.view.DetectionFindings = append(detection.view.DetectionFindings, detectionFinding(event))
		}
	}

	identities := make([]informationInsight, 0, len(accounts)+len(keys))
	for _, item := range accounts {
		finished := item.finish()
		if item.rootExcluded || !item.usageSeen || finished.DifferentIPCount == 0 {
			continue
		}
		identities = append(identities, finished)
	}
	for _, item := range keys {
		finished := item.finish()
		if !item.usageSeen || finished.DifferentIPCount == 0 {
			continue
		}
		identities = append(identities, finished)
	}
	result := a.aggregateInformationInsightsByIPPair(identities)
	for _, item := range detections {
		result = append(result, item.finish())
	}
	sort.SliceStable(result, func(i, j int) bool {
		if !result[i].LastSeen.Equal(result[j].LastSeen) {
			return result[i].LastSeen.After(result[j].LastSeen)
		}
		if result[i].IdentityType != result[j].IdentityType {
			return result[i].IdentityType < result[j].IdentityType
		}
		return result[i].ID < result[j].ID
	})
	return result
}

type insightIPPairAccumulator struct {
	view          informationInsight
	identityKeys  map[string]bool
	identityTypes map[string]bool
	subjects      map[string]bool
	accounts      map[string]bool
	keys          map[string]bool
	creationIPs   map[string]bool
	usageIPs      map[string]bool
	sourceIPs     map[string]bool
	products      map[string]bool
	eventIDs      map[string]bool
	events        map[string]model.Event
}

// aggregateInformationInsightsByIPPair turns identity-scoped findings into
// relationship-scoped findings. An unordered pair is deliberate: if separate
// identities travel in opposite directions between the same two addresses,
// the information-insight page still shows that IP relationship exactly once.
func (a *App) aggregateInformationInsightsByIPPair(items []informationInsight) []informationInsight {
	pairs := make(map[string]*insightIPPairAccumulator)
	for _, item := range items {
		if item.CreationEvidenceMissing {
			for left := 0; left < len(item.UsageIPs); left++ {
				for right := left + 1; right < len(item.UsageIPs); right++ {
					mergeInsightIPPair(pairs, a.cfg.InstanceKey, item.UsageIPs[left], item.UsageIPs[right], item, "", "")
				}
			}
			continue
		}
		for _, creationIP := range item.CreationIPs {
			for _, usageIP := range item.UsageIPs {
				if creationIP == "" || usageIP == "" || creationIP == usageIP {
					continue
				}
				mergeInsightIPPair(pairs, a.cfg.InstanceKey, creationIP, usageIP, item, creationIP, usageIP)
			}
		}
	}
	result := make([]informationInsight, 0, len(pairs))
	for _, pair := range pairs {
		result = append(result, pair.finish())
	}
	return result
}

func mergeInsightIPPair(pairs map[string]*insightIPPairAccumulator, instanceKey, leftIP, rightIP string, item informationInsight, creationIP, usageIP string) {
	leftIP = strings.TrimSpace(leftIP)
	rightIP = strings.TrimSpace(rightIP)
	if leftIP == "" || rightIP == "" || leftIP == rightIP {
		return
	}
	if rightIP < leftIP {
		leftIP, rightIP = rightIP, leftIP
	}
	pairKey := leftIP + "\x00" + rightIP
	pair := pairs[pairKey]
	if pair == nil {
		pair = &insightIPPairAccumulator{
			view: informationInsight{
				ID:        "insight_" + security.Fingerprint(instanceKey, "ip-pair\x00"+pairKey)[:20],
				FirstSeen: time.Time{},
				Events:    make([]model.Event, 0),
			},
			identityKeys:  make(map[string]bool),
			identityTypes: make(map[string]bool),
			subjects:      make(map[string]bool),
			accounts:      make(map[string]bool),
			keys:          make(map[string]bool),
			creationIPs:   make(map[string]bool),
			usageIPs:      make(map[string]bool),
			sourceIPs:     make(map[string]bool),
			products:      make(map[string]bool),
			eventIDs:      make(map[string]bool),
			events:        make(map[string]model.Event),
		}
		pairs[pairKey] = pair
	}
	pair.sourceIPs[leftIP] = true
	pair.sourceIPs[rightIP] = true
	if creationIP == "" && usageIP == "" {
		pair.usageIPs[leftIP] = true
		pair.usageIPs[rightIP] = true
	}
	pair.add(item, creationIP, usageIP)
}

func (a *insightIPPairAccumulator) add(item informationInsight, creationIP, usageIP string) {
	identityKey := item.IdentityType + "\x00" + item.SubjectFingerprint
	if item.SubjectFingerprint != "" {
		a.identityKeys[identityKey] = true
		a.subjects[item.SubjectFingerprint] = true
	}
	if item.IdentityType != "" {
		a.identityTypes[item.IdentityType] = true
	}
	switch item.IdentityType {
	case insightAccount:
		if item.SubjectFingerprint != "" {
			a.accounts[item.SubjectFingerprint] = true
		}
	case insightKey:
		if item.SubjectFingerprint != "" {
			a.keys[item.SubjectFingerprint] = true
		}
	}
	if creationIP != "" {
		a.creationIPs[creationIP] = true
	}
	if usageIP != "" {
		a.usageIPs[usageIP] = true
	}
	a.view.CreationEvidenceMissing = a.view.CreationEvidenceMissing || item.CreationEvidenceMissing
	for _, product := range item.Products {
		a.products[product] = true
	}
	for _, eventID := range item.EventIDs {
		if eventID != "" && a.sourceIPs[item.EventSourceIPs[eventID]] {
			a.eventIDs[eventID] = true
		}
	}
	for _, event := range item.Events {
		if event.EventID == "" || !a.sourceIPs[event.SourceIP] {
			continue
		}
		if _, exists := a.events[event.EventID]; !exists {
			a.events[event.EventID] = event
		}
	}
	if a.view.FirstSeen.IsZero() || (!item.FirstSeen.IsZero() && item.FirstSeen.Before(a.view.FirstSeen)) {
		a.view.FirstSeen = item.FirstSeen
	}
	if item.LastSeen.After(a.view.LastSeen) {
		a.view.LastSeen = item.LastSeen
	}
	if item.Score > a.view.Score {
		a.view.Score = item.Score
	}
}

func (a *insightIPPairAccumulator) finish() informationInsight {
	a.view.IdentityTypes = sortedInsightSet(a.identityTypes)
	if len(a.view.IdentityTypes) == 1 {
		a.view.IdentityType = a.view.IdentityTypes[0]
	} else {
		a.view.IdentityType = insightIdentity
	}
	a.view.SubjectFingerprints = sortedInsightSet(a.subjects)
	if len(a.view.SubjectFingerprints) == 1 {
		a.view.SubjectFingerprint = a.view.SubjectFingerprints[0]
	}
	a.view.IdentityCount = len(a.identityKeys)
	a.view.RelatedAccounts = sortedInsightSet(a.accounts)
	a.view.RelatedKeys = sortedInsightSet(a.keys)
	a.view.CreationIPs = sortedInsightSet(a.creationIPs)
	a.view.UsageIPs = sortedInsightSet(a.usageIPs)
	a.view.SourceIPs = sortedInsightSet(a.sourceIPs)
	a.view.Products = sortedInsightSet(a.products)
	a.view.DifferentIPCount = 1
	a.view.EventIDs = sortedInsightSet(a.eventIDs)
	a.view.EventCount = len(a.view.EventIDs)
	a.view.Events = make([]model.Event, 0, len(a.events))
	for _, event := range a.events {
		a.view.Events = append(a.view.Events, event)
	}
	sort.SliceStable(a.view.Events, func(i, j int) bool {
		return insightEventBefore(a.view.Events[i], a.view.Events[j])
	})
	if len(a.view.Events) > 200 {
		a.view.Events = append([]model.Event(nil), a.view.Events[len(a.view.Events)-200:]...)
	}
	return a.view
}

func newInsightAccumulator(key, identityType, subject string) *insightAccumulator {
	return &insightAccumulator{
		view: informationInsight{
			ID:                 "insight_" + security.Fingerprint(key, identityType+"\x00"+subject)[:20],
			IdentityType:       identityType,
			SubjectFingerprint: subject,
			FirstSeen:          time.Time{},
			Events:             make([]model.Event, 0),
			EventSourceIPs:     make(map[string]string),
		},
		creationIPs: make(map[string]bool),
		usageIPs:    make(map[string]bool),
		sourceIPs:   make(map[string]bool),
		products:    make(map[string]bool),
		eventIDs:    make(map[string]bool),
	}
}

func (a *insightAccumulator) addCreation(event model.Event) {
	if event.SourceIP != "" {
		a.creationIPs[event.SourceIP] = true
	}
}

func (a *insightAccumulator) addPersistedCreation(ip string, createdAt time.Time) {
	ip = strings.TrimSpace(ip)
	if ip != "" {
		a.creationSeen = true
		a.creationIPs[ip] = true
	}
	if !createdAt.IsZero() && (a.view.FirstSeen.IsZero() || createdAt.Before(a.view.FirstSeen)) {
		a.view.FirstSeen = createdAt
	}
}

func (a *insightAccumulator) addUsage(event model.Event) {
	if event.SourceIP != "" {
		a.usageIPs[event.SourceIP] = true
	}
}

func (a *insightAccumulator) addEvent(event model.Event) {
	if event.EventID != "" && a.eventIDs[event.EventID] {
		return
	}
	if event.EventID != "" {
		a.eventIDs[event.EventID] = true
		a.view.EventSourceIPs[event.EventID] = event.SourceIP
	}
	for _, eventID := range event.AggregateEventIDs {
		if eventID != "" {
			a.eventIDs[eventID] = true
			a.view.EventSourceIPs[eventID] = event.SourceIP
		}
	}
	a.eventCount++
	if len(a.view.Events) < 200 {
		a.view.Events = append(a.view.Events, event)
	} else {
		oldest := 0
		for index := 1; index < len(a.view.Events); index++ {
			if insightEventBefore(a.view.Events[index], a.view.Events[oldest]) {
				oldest = index
			}
		}
		if insightEventBefore(a.view.Events[oldest], event) {
			a.view.Events[oldest] = event
		}
	}
	if event.SourceIP != "" {
		a.sourceIPs[event.SourceIP] = true
	}
	if event.Product != "" {
		a.products[event.Product] = true
	}
	if a.view.FirstSeen.IsZero() || (!event.ObservedAt.IsZero() && event.ObservedAt.Before(a.view.FirstSeen)) {
		a.view.FirstSeen = event.ObservedAt
	}
	if event.ObservedAt.After(a.view.LastSeen) {
		a.view.LastSeen = event.ObservedAt
	}
	if event.Score > a.view.Score {
		a.view.Score = event.Score
	}
}

func (a *insightAccumulator) finish() informationInsight {
	if a.creationSeen {
		for ip := range a.usageIPs {
			if !a.creationIPs[ip] {
				a.view.DifferentIPCount++
			}
		}
	} else if a.persistentIdentity && len(a.usageIPs) > 1 {
		a.view.DifferentIPCount = len(a.usageIPs) - 1
		a.view.CreationEvidenceMissing = true
	}
	a.view.CreationIPs = sortedInsightSet(a.creationIPs)
	a.view.UsageIPs = sortedInsightSet(a.usageIPs)
	a.view.SourceIPs = sortedInsightSet(a.sourceIPs)
	a.view.Products = sortedInsightSet(a.products)
	a.view.EventCount = a.eventCount
	a.view.EventIDs = make([]string, 0, len(a.eventIDs))
	for eventID := range a.eventIDs {
		a.view.EventIDs = append(a.view.EventIDs, eventID)
	}
	sort.Strings(a.view.EventIDs)
	sort.SliceStable(a.view.Events, func(i, j int) bool {
		if !a.view.Events[i].ObservedAt.Equal(a.view.Events[j].ObservedAt) {
			return a.view.Events[i].ObservedAt.Before(a.view.Events[j].ObservedAt)
		}
		return a.view.Events[i].EventID < a.view.Events[j].EventID
	})
	return a.view
}

func insightEventBefore(left, right model.Event) bool {
	if !left.ObservedAt.Equal(right.ObservedAt) {
		return left.ObservedAt.Before(right.ObservedAt)
	}
	return left.EventID < right.EventID
}

func sortedInsightSet(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func (a *App) insightAccountID(event model.Event) (string, bool) {
	userID := strings.TrimSpace(event.Metadata["honey_user_id"])
	if userID == "" || a.isNewAPIRootUserID(userID) {
		return "", false
	}
	return security.Fingerprint(a.cfg.InstanceKey, "account\x00"+userID)[:20], true
}

func insightKeyID(event model.Event) string {
	value := strings.TrimSpace(event.CredentialFingerprint)
	if value == "" {
		value = strings.TrimSpace(event.Metadata["key_fingerprint"])
	}
	return value
}

func isInsightAccountCreation(event model.Event) bool {
	return event.EventType == "newapi.user.register.success" || event.EventType == "sub2api.user.register.success"
}

func isInsightKeyCreation(event model.Event) bool {
	return event.EventType == "newapi.token.created" || event.EventType == "sub2api.key.created"
}

func isInsightAccountUse(event model.Event) bool {
	if strings.HasPrefix(event.EventType, "frontend.detection.") || isInsightAccountCreation(event) {
		return false
	}
	return event.Metadata["honey_user_id"] != ""
}

func isInsightKeyUse(event model.Event) bool {
	if isInsightKeyCreation(event) || strings.HasPrefix(event.EventType, "frontend.detection.") {
		return false
	}
	return insightKeyID(event) != ""
}

func detectionFinding(event model.Event) map[string]any {
	kind := event.Metadata["detection_kind"]
	if kind == "" {
		switch event.Metadata["detection_result"] {
		case "consistent":
			kind = "detection_consistent"
		case "indeterminate":
			kind = "detection_indeterminate"
		default:
			kind = "detection_result"
		}
	}
	return map[string]any{
		"event_id":          event.EventID,
		"kind":              kind,
		"result":            event.Metadata["detection_result"],
		"region_status":     event.Metadata["region_consistency_status"],
		"webrtc_status":     event.Metadata["webrtc_check_status"],
		"webrtc_candidates": event.Metadata["webrtc_public_candidate_count"],
		"inferred_ip":       event.Metadata["inferred_ip"],
		"inferred_region":   event.Metadata["inferred_region"],
		"visitor_region":    event.Metadata["visitor_region"],
		"visitor_timezone":  event.Metadata["visitor_timezone"],
		"server_ip":         event.Metadata["server_ip"],
		"ip_region":         event.Metadata["ip_region"],
		"ip_country_code":   event.Metadata["ip_country_code"],
		"geo_source":        event.Metadata["geo_source"],
		"geo_status":        event.Metadata["geo_status"],
		"observed_at":       event.ObservedAt,
	}
}

func (a *App) findInformationInsight(ctx context.Context, id string) (informationInsight, bool, error) {
	events, err := a.store.EventSummariesContext(ctx, -1, "", "")
	if err != nil {
		return informationInsight{}, false, err
	}
	for _, item := range a.buildInformationInsights(events) {
		if item.ID == id {
			return item, true, nil
		}
	}
	return informationInsight{}, false, nil
}

func (a *App) adminInsightDetail(w http.ResponseWriter, r *http.Request, rawID string) {
	id, ok := decodeAdminTarget(rawID, "insight")
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "insight not found"})
		return
	}
	item, found, err := a.findInformationInsight(r.Context(), id)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "insight query failed"})
		return
	}
	if !found {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "insight not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"insight": item, "synthetic_only": true})
}

func (a *App) adminDeleteInsight(w http.ResponseWriter, r *http.Request, rawID string) {
	id, ok := decodeAdminTarget(rawID, "insight")
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "insight not found"})
		return
	}
	if !a.allowAdminDelete(w, r, "insight") {
		return
	}
	item, found, err := a.findInformationInsight(r.Context(), id)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "insight delete failed"})
		return
	}
	if !found {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "insight not found"})
		return
	}
	ids := append([]string(nil), item.EventIDs...)
	deleted, err := a.store.SoftDeleteEventIDs(uniqueStrings(ids))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "insight delete failed"})
		return
	}
	if deleted == 0 {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "insight not found"})
		return
	}
	a.recordAudit(r, "information-insight.delete", id, "success", map[string]string{"deleted_events": strconv.Itoa(deleted), "logical": "true"})
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": true, "deleted_events": deleted, "id": id, "logical": true})
}
