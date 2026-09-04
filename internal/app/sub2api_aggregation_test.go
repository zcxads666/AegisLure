package app

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestSub2APIHomeFrontendGETsAggregateAcrossAdminLists(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	profile := sub2APIProfileForTest(a, cfg)
	public := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	for _, path := range []string{
		"/",
		"/logo.svg",
		"/assets/index-B9eRoPy0.js",
		"/assets/vendor-vue-Dzwqm9Y9.js",
		"/assets/vendor-misc-B-nM3tYW.js",
		"/assets/index-Dk1wwGAt.css",
	} {
		resp, _ := doRawJSON(t, public, http.MethodGet, path, nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("official Sub2API frontend request %s = %d", path, resp.StatusCode)
		}
	}
	rawEvents, err := st.Events(-1, model.ProductSub2API, "")
	if err != nil {
		t.Fatal(err)
	}
	rawHomeCount := 0
	for _, event := range rawEvents {
		if isSub2APIHomeFrontendEvent(event) {
			rawHomeCount++
		}
	}
	if rawHomeCount != 6 {
		t.Fatalf("raw frontend GET count = %d, want 6", rawHomeCount)
	}

	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}

	resp, observations := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events?product=sub2api", nil)
	if resp.StatusCode != http.StatusOK || observations["total"] != float64(1) {
		t.Fatalf("aggregated observation list = %d %#v", resp.StatusCode, observations)
	}
	observation := observations["events"].([]any)[0].(map[string]any)
	if observation["display_route"] != sub2APIHomeDisplayRoute || observation["aggregate_count"] != float64(rawHomeCount) {
		t.Fatalf("observation aggregate = %#v", observation)
	}
	if len(observation["aggregate_event_ids"].([]any)) != rawHomeCount {
		t.Fatalf("observation aggregate IDs = %#v", observation["aggregate_event_ids"])
	}

	resp, dashboard := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/dashboard", nil)
	counts := dashboard["counts"].(map[string]any)
	recent := dashboard["recent_events"].([]any)
	if resp.StatusCode != http.StatusOK || counts["events"] != float64(1) || len(recent) != 1 || recent[0].(map[string]any)["display_route"] != sub2APIHomeDisplayRoute {
		t.Fatalf("dashboard aggregate = %d %#v", resp.StatusCode, dashboard)
	}

	resp, chains := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/interaction-chains?product=sub2api", nil)
	if resp.StatusCode != http.StatusOK || len(chains["chains"].([]any)) != 1 {
		t.Fatalf("chain list aggregate = %d %#v", resp.StatusCode, chains)
	}
	chain := chains["chains"].([]any)[0].(map[string]any)
	chainEvents := chain["events"].([]any)
	if len(chainEvents) != 1 || chainEvents[0].(map[string]any)["display_route"] != sub2APIHomeDisplayRoute {
		t.Fatalf("chain events aggregate = %#v", chain)
	}

	resp, sessions := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/sessions?product=sub2api", nil)
	if resp.StatusCode != http.StatusOK || len(sessions["sessions"].([]any)) != 1 || sessions["sessions"].([]any)[0].(map[string]any)["event_count"] != float64(1) {
		t.Fatalf("session list aggregate = %d %#v", resp.StatusCode, sessions)
	}
	sessionID := sessions["sessions"].([]any)[0].(map[string]any)["id"].(string)
	resp, sessionDetail := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/sessions/"+url.PathEscape(sessionID), nil)
	if resp.StatusCode != http.StatusOK || len(sessionDetail["events"].([]any)) != 1 || sessionDetail["events"].([]any)[0].(map[string]any)["display_route"] != sub2APIHomeDisplayRoute {
		t.Fatalf("session detail aggregate = %d %#v", resp.StatusCode, sessionDetail)
	}

	sourceIP := rawEvents[0].SourceIP
	resp, actor := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/actors/"+url.PathEscape(sourceIP), nil)
	if resp.StatusCode != http.StatusOK || actor["event_count"] != float64(1) || len(actor["events"].([]any)) != 1 {
		t.Fatalf("actor detail aggregate = %d %#v", resp.StatusCode, actor)
	}

	aggregateID := observation["event_id"].(string)
	resp, deletion := doJSON(t, admin, http.MethodDelete, cfg.AdminPath+"admin/api/v1/events/"+url.PathEscape(aggregateID), nil)
	if resp.StatusCode != http.StatusOK || deletion["deleted_events"] != float64(rawHomeCount) {
		t.Fatalf("aggregate delete = %d %#v", resp.StatusCode, deletion)
	}
	remaining, err := st.Events(-1, model.ProductSub2API, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("aggregate delete left raw events visible: %d", len(remaining))
	}
}

func TestSub2APIHomeAggregationSeparatesDistinctPageLoads(t *testing.T) {
	base := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	events := []model.Event{
		{EventID: "new-home", Product: model.ProductSub2API, RouteTemplate: "sub2api.spa", Method: "GET", SourceIP: "192.0.2.20", SessionID: "session-1", ObservedAt: base.Add(20 * time.Second)},
		{EventID: "new-asset", Product: model.ProductSub2API, RouteTemplate: "sub2api.asset", Method: "GET", SourceIP: "192.0.2.20", SessionID: "session-1", ObservedAt: base.Add(19 * time.Second)},
		{EventID: "old-home", Product: model.ProductSub2API, RouteTemplate: "sub2api.spa", Method: "GET", SourceIP: "192.0.2.20", SessionID: "session-1", ObservedAt: base},
	}
	aggregated := aggregateSub2APIHomeEvents(events)
	if len(aggregated) != 2 || aggregated[0].DisplayRoute != sub2APIHomeDisplayRoute || aggregated[0].AggregateCount != 2 || aggregated[1].AggregateCount != 1 {
		t.Fatalf("distinct page-load aggregate = %#v", aggregated)
	}
}

func TestSub2APIHomeAggregationKeepsOtherSPARoutesIndependent(t *testing.T) {
	base := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	events := []model.Event{
		{EventID: "home", Product: model.ProductSub2API, RouteTemplate: "sub2api.spa", Method: "GET", SourceIP: "192.0.2.21", SessionID: "session-2", ObservedAt: base, RawRequest: &model.RawRequest{Route: "/", URL: "/"}},
		{EventID: "home-asset", Product: model.ProductSub2API, RouteTemplate: "sub2api.asset", Method: "GET", SourceIP: "192.0.2.21", SessionID: "session-2", ObservedAt: base.Add(time.Second), RawRequest: &model.RawRequest{Route: "/assets/index.js", URL: "/assets/index.js"}},
		{EventID: "plaza", Product: model.ProductSub2API, RouteTemplate: "sub2api.spa", Method: "GET", SourceIP: "192.0.2.21", SessionID: "session-2", ObservedAt: base.Add(2 * time.Second), RawRequest: &model.RawRequest{Route: "/model-plaza", URL: "/model-plaza"}},
		{EventID: "plaza-asset", Product: model.ProductSub2API, RouteTemplate: "sub2api.asset", Method: "GET", SourceIP: "192.0.2.21", SessionID: "session-2", ObservedAt: base.Add(3 * time.Second), RawRequest: &model.RawRequest{Route: "/assets/model.js", URL: "/assets/model.js"}},
	}

	aggregated := aggregateSub2APIHomeEvents(events)
	if len(aggregated) != 3 {
		t.Fatalf("independent SPA routes = %#v", aggregated)
	}
	var homeAggregate model.Event
	for _, event := range aggregated {
		if event.DisplayRoute == sub2APIHomeDisplayRoute {
			homeAggregate = event
			continue
		}
		if event.RawRequest == nil || event.RawRequest.Route == "/" || event.RawRequest.Route == "/home" {
			t.Fatalf("non-home event was mislabeled or lost: %#v", event)
		}
	}
	if homeAggregate.EventID == "" || homeAggregate.AggregateCount != 2 || len(homeAggregate.AggregateEventIDs) != 2 {
		t.Fatalf("home aggregate = %#v", homeAggregate)
	}
}
