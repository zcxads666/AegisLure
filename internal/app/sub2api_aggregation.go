package app

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

const (
	sub2APIHomeDisplayRoute        = "sub2api首页"
	sub2APIHomeAggregationWindow   = 15 * time.Second
	sub2APIHomeAggregationMetadata = "sub2api_home_frontend_get"
	newAPIHomeDisplayRoute         = "newapi首页"
	newAPIHomeAggregationMetadata  = "newapi_home_frontend_get"
)

type homeFrontendAggregationSpec struct {
	product              string
	displayRoute         string
	aggregationMetadata  string
	spaRouteTemplate     string
	homePaths            map[string]struct{}
	staticRouteTemplates map[string]struct{}
}

var (
	sub2APIHomeAggregationSpec = homeFrontendAggregationSpec{
		product:             model.ProductSub2API,
		displayRoute:        sub2APIHomeDisplayRoute,
		aggregationMetadata: sub2APIHomeAggregationMetadata,
		spaRouteTemplate:    "sub2api.spa",
		homePaths: map[string]struct{}{
			"":      {},
			"/":     {},
			"/home": {},
		},
		staticRouteTemplates: map[string]struct{}{
			"sub2api.asset": {},
			"sub2api.logo":  {},
		},
	}
	newAPIHomeAggregationSpec = homeFrontendAggregationSpec{
		product:             model.ProductNewAPI,
		displayRoute:        newAPIHomeDisplayRoute,
		aggregationMetadata: newAPIHomeAggregationMetadata,
		spaRouteTemplate:    "newapi.spa",
		homePaths: map[string]struct{}{
			"":  {},
			"/": {},
		},
		staticRouteTemplates: map[string]struct{}{
			"newapi.asset": {},
			"newapi.logo":  {},
		},
	}
)

// adminDisplayEvents creates the presentation projection used by management
// lists. The event store remains append-only and keeps every raw frontend GET.
func adminDisplayEvents(events []model.Event) []model.Event {
	events = aggregateHomeFrontendEvents(events, sub2APIHomeAggregationSpec)
	return aggregateHomeFrontendEvents(events, newAPIHomeAggregationSpec)
}

func isFrontendGET(event model.Event, spec homeFrontendAggregationSpec) bool {
	return event.Product == spec.product && strings.EqualFold(strings.TrimSpace(event.Method), "GET")
}

func isSub2APIFrontendGET(event model.Event) bool {
	return isFrontendGET(event, sub2APIHomeAggregationSpec)
}

func isNewAPIFrontendGET(event model.Event) bool {
	return isFrontendGET(event, newAPIHomeAggregationSpec)
}

func frontendRequestPath(event model.Event) string {
	if event.RawRequest == nil {
		return ""
	}
	candidate := strings.TrimSpace(event.RawRequest.Route)
	if candidate == "" {
		candidate = strings.TrimSpace(event.RawRequest.URL)
	}
	if candidate == "" {
		return ""
	}
	if parsed, err := url.Parse(candidate); err == nil && parsed.Path != "" {
		return parsed.Path
	}
	if query := strings.IndexByte(candidate, '?'); query >= 0 {
		return candidate[:query]
	}
	return candidate
}

// Kept as a compatibility wrapper for the existing Sub2API aggregation tests.
func sub2APIFrontendPath(event model.Event) string {
	return frontendRequestPath(event)
}

func isHomeNavigationEvent(event model.Event, spec homeFrontendAggregationSpec) bool {
	if !isFrontendGET(event, spec) || event.RouteTemplate != spec.spaRouteTemplate {
		return false
	}
	// A missing raw envelope is a legacy/synthetic event. The route template is
	// still the only available signal, so keep the old behavior for it.
	_, ok := spec.homePaths[frontendRequestPath(event)]
	return ok
}

func isSub2APIHomeNavigationEvent(event model.Event) bool {
	return isHomeNavigationEvent(event, sub2APIHomeAggregationSpec)
}

func isNewAPIHomeNavigationEvent(event model.Event) bool {
	return isHomeNavigationEvent(event, newAPIHomeAggregationSpec)
}

func isHomeStaticEvent(event model.Event, spec homeFrontendAggregationSpec) bool {
	if !isFrontendGET(event, spec) {
		return false
	}
	_, ok := spec.staticRouteTemplates[event.RouteTemplate]
	return ok
}

func isSub2APIHomeStaticEvent(event model.Event) bool {
	return isHomeStaticEvent(event, sub2APIHomeAggregationSpec)
}

func isNewAPIHomeStaticEvent(event model.Event) bool {
	return isHomeStaticEvent(event, newAPIHomeAggregationSpec)
}

func isHomeFrontendEvent(event model.Event, spec homeFrontendAggregationSpec) bool {
	return isHomeNavigationEvent(event, spec) || isHomeStaticEvent(event, spec)
}

func isSub2APIHomeFrontendEvent(event model.Event) bool {
	return isHomeFrontendEvent(event, sub2APIHomeAggregationSpec)
}

func isNewAPIHomeFrontendEvent(event model.Event) bool {
	return isHomeFrontendEvent(event, newAPIHomeAggregationSpec)
}

func isNonHomeSPAEvent(event model.Event, spec homeFrontendAggregationSpec) bool {
	return isFrontendGET(event, spec) && event.RouteTemplate == spec.spaRouteTemplate && !isHomeNavigationEvent(event, spec)
}

func isSub2APINonHomeSPAEvent(event model.Event) bool {
	return isNonHomeSPAEvent(event, sub2APIHomeAggregationSpec)
}

type homeAggregationGroup struct {
	navigation   []int
	staticAssets []int
	latest       time.Time
}

// aggregateSub2APIHomeEvents collapses the static HTML, asset, and logo GETs
// emitted while the Sub2API home page is loading. Other SPA routes such as
// /login and /model-plaza remain independent observations. A new home load
// after the short coalescing window gets its own display row, while all source
// event IDs stay attached to the aggregate for deletion and audit purposes.
func aggregateSub2APIHomeEvents(events []model.Event) []model.Event {
	return aggregateHomeFrontendEvents(events, sub2APIHomeAggregationSpec)
}

// aggregateNewAPIHomeEvents applies the same lossless presentation projection
// to the official New API home shell at /. Non-home SPA routes remain raw rows.
func aggregateNewAPIHomeEvents(events []model.Event) []model.Event {
	return aggregateHomeFrontendEvents(events, newAPIHomeAggregationSpec)
}

func aggregateHomeFrontendEvents(events []model.Event, spec homeFrontendAggregationSpec) []model.Event {
	if len(events) == 0 {
		return []model.Event{}
	}
	ordered := append([]model.Event(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return adminEventOldestFirst(ordered[i], ordered[j])
	})

	groupsByKey := make(map[string][]*homeAggregationGroup)
	nonHomeByKey := make(map[string][]model.Event)
	for index, event := range ordered {
		key := homeAggregationKey(event)
		if isNonHomeSPAEvent(event, spec) {
			nonHomeByKey[key] = append(nonHomeByKey[key], event)
			continue
		}
		if !isHomeNavigationEvent(event, spec) {
			continue
		}

		groups := groupsByKey[key]
		var group *homeAggregationGroup
		if len(groups) > 0 {
			candidate := groups[len(groups)-1]
			if homeEventsWithinWindow(candidate.latest, event.ObservedAt) && !homeBoundaryBetween(nonHomeByKey[key], candidate.latest, event.ObservedAt) {
				group = candidate
			}
		}
		if group == nil {
			group = &homeAggregationGroup{}
			groupsByKey[key] = append(groups, group)
		}
		group.navigation = append(group.navigation, index)
		if group.latest.IsZero() || event.ObservedAt.After(group.latest) {
			group.latest = event.ObservedAt
		}
	}

	assigned := make(map[int]*homeAggregationGroup)
	for index, event := range ordered {
		if !isHomeStaticEvent(event, spec) {
			continue
		}
		key := homeAggregationKey(event)
		var best *homeAggregationGroup
		bestDelta := time.Duration(1<<63 - 1)
		for _, group := range groupsByKey[key] {
			for _, navigationIndex := range group.navigation {
				navigation := ordered[navigationIndex]
				if !homeEventsWithinWindow(navigation.ObservedAt, event.ObservedAt) || homeBoundaryBetween(nonHomeByKey[key], navigation.ObservedAt, event.ObservedAt) {
					continue
				}
				delta := homeEventDelta(navigation.ObservedAt, event.ObservedAt)
				if best == nil || delta < bestDelta || (delta == bestDelta && navigation.ObservedAt.After(ordered[best.navigation[0]].ObservedAt)) {
					best = group
					bestDelta = delta
				}
			}
		}
		if best != nil {
			best.staticAssets = append(best.staticAssets, index)
			assigned[index] = best
		}
	}

	result := make([]model.Event, 0, len(ordered))
	for _, groups := range groupsByKey {
		for _, group := range groups {
			indices := append(append([]int(nil), group.navigation...), group.staticAssets...)
			if len(indices) == 0 {
				continue
			}
			sort.SliceStable(indices, func(i, j int) bool {
				return adminEventNewestFirst(ordered[indices[i]], ordered[indices[j]])
			})
			aggregate := newHomeAggregate(ordered[indices[0]], spec)
			for _, index := range indices[1:] {
				mergeHomeEvent(&aggregate, ordered[index], spec)
			}
			for _, index := range indices {
				assigned[index] = group
			}
			result = append(result, aggregate)
		}
	}
	for index, event := range ordered {
		if assigned[index] == nil {
			result = append(result, event)
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		return adminEventNewestFirst(result[i], result[j])
	})
	return result
}

func homeBoundaryBetween(events []model.Event, left, right time.Time) bool {
	if left.IsZero() || right.IsZero() {
		return false
	}
	start, end := left, right
	if start.After(end) {
		start, end = end, start
	}
	for _, event := range events {
		if event.ObservedAt.IsZero() {
			continue
		}
		if !event.ObservedAt.Before(start) && !event.ObservedAt.After(end) {
			return true
		}
	}
	return false
}

func homeEventDelta(left, right time.Time) time.Duration {
	if left.IsZero() || right.IsZero() {
		return 0
	}
	delta := left.Sub(right)
	if delta < 0 {
		return -delta
	}
	return delta
}

func homeAggregationKey(event model.Event) string {
	if sessionID := strings.TrimSpace(event.SessionID); sessionID != "" {
		return "session:" + sessionID
	}
	day := "unknown-day"
	if !event.ObservedAt.IsZero() {
		location, err := time.LoadLocation(model.InteractionChainTimezone)
		if err != nil {
			location = time.FixedZone(model.InteractionChainTimezone, 8*60*60)
		}
		day = event.ObservedAt.In(location).Format("2006-01-02")
	}
	return "source:" + event.SourceIP + "\x00" + event.UserAgent + "\x00" + day
}

func homeEventsWithinWindow(latest, observedAt time.Time) bool {
	if latest.IsZero() || observedAt.IsZero() {
		return true
	}
	delta := latest.Sub(observedAt)
	if delta < 0 {
		delta = -delta
	}
	return delta <= sub2APIHomeAggregationWindow
}

func newHomeAggregate(event model.Event, spec homeFrontendAggregationSpec) model.Event {
	aggregate := event
	aggregate.DisplayRoute = spec.displayRoute
	aggregate.AggregateCount = homeEventCount(event)
	aggregate.AggregateRoutes = uniqueStrings(homeEventRoutes(event))
	aggregate.AggregateEventIDs = uniqueStrings(homeEventIDs(event))
	aggregate.Metadata = cloneEventMetadata(event.Metadata)
	aggregate.Metadata["display_route"] = spec.displayRoute
	aggregate.Metadata["aggregation"] = spec.aggregationMetadata
	aggregate.Metadata["aggregate_count"] = strconv.Itoa(aggregate.AggregateCount)
	return aggregate
}

func mergeHomeEvent(aggregate *model.Event, event model.Event, spec homeFrontendAggregationSpec) {
	if aggregate == nil {
		return
	}
	if aggregate.AggregateCount < 1 {
		aggregate.AggregateCount = 1
	}
	aggregate.AggregateCount += homeEventCount(event)
	aggregate.RequestBytes += event.RequestBytes
	aggregate.ResponseBytes += event.ResponseBytes
	aggregate.DurationMS += event.DurationMS
	aggregate.ResponseObserved = aggregate.ResponseObserved || event.ResponseObserved
	if event.Score > aggregate.Score {
		aggregate.Score = event.Score
	}
	if confidenceRank(event.Confidence) > confidenceRank(aggregate.Confidence) {
		aggregate.Confidence = event.Confidence
	}
	if aggregate.IntentClass == "" {
		aggregate.IntentClass = event.IntentClass
	}
	if aggregate.EventType == "" {
		aggregate.EventType = event.EventType
	}
	aggregate.ReasonCodes = uniqueStrings(append(aggregate.ReasonCodes, event.ReasonCodes...))
	aggregate.MatchedRuleIDs = uniqueStrings(append(aggregate.MatchedRuleIDs, event.MatchedRuleIDs...))
	aggregate.AggregateRoutes = uniqueStrings(append(aggregate.AggregateRoutes, homeEventRoutes(event)...))
	aggregate.AggregateEventIDs = uniqueStrings(append(aggregate.AggregateEventIDs, homeEventIDs(event)...))
	if aggregate.Metadata == nil {
		aggregate.Metadata = cloneEventMetadata(event.Metadata)
	}
	aggregate.Metadata["display_route"] = spec.displayRoute
	aggregate.Metadata["aggregation"] = spec.aggregationMetadata
	aggregate.Metadata["aggregate_count"] = strconv.Itoa(aggregate.AggregateCount)
}

// Compatibility wrappers retain the previous Sub2API helper surface for
// package-local tests while the implementation is shared with New API.
func sub2APIHomeBoundaryBetween(events []model.Event, left, right time.Time) bool {
	return homeBoundaryBetween(events, left, right)
}

func sub2APIHomeEventDelta(left, right time.Time) time.Duration {
	return homeEventDelta(left, right)
}

func sub2APIHomeAggregationKey(event model.Event) string {
	return homeAggregationKey(event)
}

func sub2APIHomeEventsWithinWindow(latest, observedAt time.Time) bool {
	return homeEventsWithinWindow(latest, observedAt)
}

func newSub2APIHomeAggregate(event model.Event) model.Event {
	return newHomeAggregate(event, sub2APIHomeAggregationSpec)
}

func mergeSub2APIHomeEvent(aggregate *model.Event, event model.Event) {
	mergeHomeEvent(aggregate, event, sub2APIHomeAggregationSpec)
}

func sub2APIEventCount(event model.Event) int {
	return homeEventCount(event)
}

func homeEventCount(event model.Event) int {
	if event.AggregateCount > 0 {
		return event.AggregateCount
	}
	return 1
}

func sub2APIHomeEventRoutes(event model.Event) []string {
	return homeEventRoutes(event)
}

func homeEventRoutes(event model.Event) []string {
	routes := append([]string(nil), event.AggregateRoutes...)
	if event.RawRequest != nil {
		if route := strings.TrimSpace(event.RawRequest.Route); route != "" {
			routes = append(routes, route)
		}
		if target := strings.TrimSpace(event.RawRequest.URL); target != "" {
			routes = append(routes, target)
		}
	}
	if len(routes) == 0 && strings.TrimSpace(event.RouteTemplate) != "" {
		routes = append(routes, event.RouteTemplate)
	}
	return routes
}

func sub2APIHomeEventIDs(event model.Event) []string {
	return homeEventIDs(event)
}

func homeEventIDs(event model.Event) []string {
	ids := append([]string(nil), event.AggregateEventIDs...)
	if event.EventID != "" {
		ids = append(ids, event.EventID)
	}
	return ids
}

func cloneEventMetadata(metadata map[string]string) map[string]string {
	clone := make(map[string]string, len(metadata)+3)
	for key, value := range metadata {
		clone[key] = value
	}
	return clone
}

func adminEventNewestFirst(left, right model.Event) bool {
	if !left.ObservedAt.Equal(right.ObservedAt) {
		return left.ObservedAt.After(right.ObservedAt)
	}
	if left.Sequence != right.Sequence {
		return left.Sequence > right.Sequence
	}
	return left.EventID > right.EventID
}

func adminEventOldestFirst(left, right model.Event) bool {
	if !left.ObservedAt.Equal(right.ObservedAt) {
		return left.ObservedAt.Before(right.ObservedAt)
	}
	if left.Sequence != right.Sequence {
		return left.Sequence < right.Sequence
	}
	return left.EventID < right.EventID
}

func confidenceRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func adminDisplayEventIDs(event model.Event) []string {
	ids := uniqueStrings(event.AggregateEventIDs)
	if len(ids) == 0 && event.EventID != "" {
		ids = []string{event.EventID}
	}
	return ids
}
