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
)

// adminDisplayEvents creates the presentation projection used by management
// lists. The event store remains append-only and keeps every raw frontend GET.
func adminDisplayEvents(events []model.Event) []model.Event {
	return aggregateSub2APIHomeEvents(events)
}

func isSub2APIFrontendGET(event model.Event) bool {
	return event.Product == model.ProductSub2API && strings.EqualFold(strings.TrimSpace(event.Method), "GET")
}

func sub2APIFrontendPath(event model.Event) string {
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

func isSub2APIHomeNavigationEvent(event model.Event) bool {
	if !isSub2APIFrontendGET(event) || event.RouteTemplate != "sub2api.spa" {
		return false
	}
	// A missing raw envelope is a legacy/synthetic event. The route template is
	// still the only available signal, so keep the old behavior for it.
	switch sub2APIFrontendPath(event) {
	case "", "/", "/home":
		return true
	default:
		return false
	}
}

func isSub2APIHomeStaticEvent(event model.Event) bool {
	if !isSub2APIFrontendGET(event) {
		return false
	}
	switch event.RouteTemplate {
	case "sub2api.asset", "sub2api.logo":
		return true
	default:
		return false
	}
}

func isSub2APIHomeFrontendEvent(event model.Event) bool {
	return isSub2APIHomeNavigationEvent(event) || isSub2APIHomeStaticEvent(event)
}

func isSub2APINonHomeSPAEvent(event model.Event) bool {
	return isSub2APIFrontendGET(event) && event.RouteTemplate == "sub2api.spa" && !isSub2APIHomeNavigationEvent(event)
}

type sub2APIHomeAggregationGroup struct {
	key          string
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
	if len(events) == 0 {
		return []model.Event{}
	}
	ordered := append([]model.Event(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return adminEventOldestFirst(ordered[i], ordered[j])
	})

	groupsByKey := make(map[string][]*sub2APIHomeAggregationGroup)
	nonHomeByKey := make(map[string][]model.Event)
	for index, event := range ordered {
		key := sub2APIHomeAggregationKey(event)
		if isSub2APINonHomeSPAEvent(event) {
			nonHomeByKey[key] = append(nonHomeByKey[key], event)
			continue
		}
		if !isSub2APIHomeNavigationEvent(event) {
			continue
		}

		groups := groupsByKey[key]
		var group *sub2APIHomeAggregationGroup
		if len(groups) > 0 {
			candidate := groups[len(groups)-1]
			if sub2APIHomeEventsWithinWindow(candidate.latest, event.ObservedAt) && !sub2APIHomeBoundaryBetween(nonHomeByKey[key], candidate.latest, event.ObservedAt) {
				group = candidate
			}
		}
		if group == nil {
			group = &sub2APIHomeAggregationGroup{key: key}
			groupsByKey[key] = append(groups, group)
		}
		group.navigation = append(group.navigation, index)
		if group.latest.IsZero() || event.ObservedAt.After(group.latest) {
			group.latest = event.ObservedAt
		}
	}

	assigned := make(map[int]*sub2APIHomeAggregationGroup)
	for index, event := range ordered {
		if !isSub2APIHomeStaticEvent(event) {
			continue
		}
		key := sub2APIHomeAggregationKey(event)
		var best *sub2APIHomeAggregationGroup
		bestDelta := time.Duration(1<<63 - 1)
		for _, group := range groupsByKey[key] {
			for _, navigationIndex := range group.navigation {
				navigation := ordered[navigationIndex]
				if !sub2APIHomeEventsWithinWindow(navigation.ObservedAt, event.ObservedAt) || sub2APIHomeBoundaryBetween(nonHomeByKey[key], navigation.ObservedAt, event.ObservedAt) {
					continue
				}
				delta := sub2APIHomeEventDelta(navigation.ObservedAt, event.ObservedAt)
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
			aggregate := newSub2APIHomeAggregate(ordered[indices[0]])
			for _, index := range indices[1:] {
				mergeSub2APIHomeEvent(&aggregate, ordered[index])
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

func sub2APIHomeBoundaryBetween(events []model.Event, left, right time.Time) bool {
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

func sub2APIHomeEventDelta(left, right time.Time) time.Duration {
	if left.IsZero() || right.IsZero() {
		return 0
	}
	delta := left.Sub(right)
	if delta < 0 {
		return -delta
	}
	return delta
}

func sub2APIHomeAggregationKey(event model.Event) string {
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

func sub2APIHomeEventsWithinWindow(latest, observedAt time.Time) bool {
	if latest.IsZero() || observedAt.IsZero() {
		return true
	}
	delta := latest.Sub(observedAt)
	if delta < 0 {
		delta = -delta
	}
	return delta <= sub2APIHomeAggregationWindow
}

func newSub2APIHomeAggregate(event model.Event) model.Event {
	aggregate := event
	aggregate.DisplayRoute = sub2APIHomeDisplayRoute
	aggregate.AggregateCount = sub2APIEventCount(event)
	aggregate.AggregateRoutes = uniqueStrings(sub2APIHomeEventRoutes(event))
	aggregate.AggregateEventIDs = uniqueStrings(sub2APIHomeEventIDs(event))
	aggregate.Metadata = cloneEventMetadata(event.Metadata)
	aggregate.Metadata["display_route"] = sub2APIHomeDisplayRoute
	aggregate.Metadata["aggregation"] = sub2APIHomeAggregationMetadata
	aggregate.Metadata["aggregate_count"] = strconv.Itoa(aggregate.AggregateCount)
	return aggregate
}

func mergeSub2APIHomeEvent(aggregate *model.Event, event model.Event) {
	if aggregate == nil {
		return
	}
	if aggregate.AggregateCount < 1 {
		aggregate.AggregateCount = 1
	}
	aggregate.AggregateCount += sub2APIEventCount(event)
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
	aggregate.AggregateRoutes = uniqueStrings(append(aggregate.AggregateRoutes, sub2APIHomeEventRoutes(event)...))
	aggregate.AggregateEventIDs = uniqueStrings(append(aggregate.AggregateEventIDs, sub2APIHomeEventIDs(event)...))
	if aggregate.Metadata == nil {
		aggregate.Metadata = cloneEventMetadata(event.Metadata)
	}
	aggregate.Metadata["display_route"] = sub2APIHomeDisplayRoute
	aggregate.Metadata["aggregation"] = sub2APIHomeAggregationMetadata
	aggregate.Metadata["aggregate_count"] = strconv.Itoa(aggregate.AggregateCount)
}

func sub2APIEventCount(event model.Event) int {
	if event.AggregateCount > 0 {
		return event.AggregateCount
	}
	return 1
}

func sub2APIHomeEventRoutes(event model.Event) []string {
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
