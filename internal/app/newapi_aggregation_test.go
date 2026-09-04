package app

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
)

func TestNewAPIHomeFrontendGETsAggregateAcrossAdminLists(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	cfg.ProfilePorts[model.ProductNewAPI] = 3000
	profile := profiles.Build(cfg)[model.ProductNewAPI]
	public := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	paths := []string{
		"/",
		"/logo.png",
		"/favicon.ico",
		"/static/js/index.70ae9b5357.js",
		"/static/css/index.4a0fdd8fc5.css",
	}
	for _, path := range paths {
		resp, _ := doRawJSON(t, public, http.MethodGet, path, nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("official New API frontend request %s = %d", path, resp.StatusCode)
		}
	}

	rawEvents, err := st.Events(-1, model.ProductNewAPI, "")
	if err != nil {
		t.Fatal(err)
	}
	rawHomeCount := 0
	for _, event := range rawEvents {
		if isNewAPIHomeFrontendEvent(event) {
			rawHomeCount++
		}
	}
	if rawHomeCount != len(paths) {
		t.Fatalf("raw New API frontend GET count = %d, want %d", rawHomeCount, len(paths))
	}

	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}

	resp, observations := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events?product="+url.QueryEscape(model.ProductNewAPI), nil)
	if resp.StatusCode != http.StatusOK || observations["total"] != float64(1) {
		t.Fatalf("New API aggregated observation list = %d %#v", resp.StatusCode, observations)
	}
	observation := observations["events"].([]any)[0].(map[string]any)
	if observation["display_route"] != newAPIHomeDisplayRoute || observation["aggregate_count"] != float64(rawHomeCount) {
		t.Fatalf("New API observation aggregate = %#v", observation)
	}
	if len(observation["aggregate_event_ids"].([]any)) != rawHomeCount {
		t.Fatalf("New API observation aggregate IDs = %#v", observation["aggregate_event_ids"])
	}

	resp, dashboard := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/dashboard", nil)
	counts := dashboard["counts"].(map[string]any)
	recent := dashboard["recent_events"].([]any)
	if resp.StatusCode != http.StatusOK || counts["events"] != float64(1) || len(recent) != 1 || recent[0].(map[string]any)["display_route"] != newAPIHomeDisplayRoute {
		t.Fatalf("New API dashboard aggregate = %d %#v", resp.StatusCode, dashboard)
	}

	resp, chains := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/interaction-chains?product="+url.QueryEscape(model.ProductNewAPI), nil)
	if resp.StatusCode != http.StatusOK || len(chains["chains"].([]any)) != 1 {
		t.Fatalf("New API chain list aggregate = %d %#v", resp.StatusCode, chains)
	}
	chain := chains["chains"].([]any)[0].(map[string]any)
	chainEvents := chain["events"].([]any)
	if len(chainEvents) != 1 || chainEvents[0].(map[string]any)["display_route"] != newAPIHomeDisplayRoute {
		t.Fatalf("New API chain events aggregate = %#v", chain)
	}

	resp, sessions := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/sessions?product="+url.QueryEscape(model.ProductNewAPI), nil)
	if resp.StatusCode != http.StatusOK || len(sessions["sessions"].([]any)) != 1 || sessions["sessions"].([]any)[0].(map[string]any)["event_count"] != float64(1) {
		t.Fatalf("New API session list aggregate = %d %#v", resp.StatusCode, sessions)
	}
	sessionID := sessions["sessions"].([]any)[0].(map[string]any)["id"].(string)
	resp, sessionDetail := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/sessions/"+url.PathEscape(sessionID), nil)
	if resp.StatusCode != http.StatusOK || len(sessionDetail["events"].([]any)) != 1 || sessionDetail["events"].([]any)[0].(map[string]any)["display_route"] != newAPIHomeDisplayRoute {
		t.Fatalf("New API session detail aggregate = %d %#v", resp.StatusCode, sessionDetail)
	}

	sourceIP := rawEvents[0].SourceIP
	resp, actor := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/actors/"+url.PathEscape(sourceIP), nil)
	if resp.StatusCode != http.StatusOK || actor["event_count"] != float64(1) || len(actor["events"].([]any)) != 1 {
		t.Fatalf("New API actor detail aggregate = %d %#v", resp.StatusCode, actor)
	}

	aggregateID := observation["event_id"].(string)
	resp, deletion := doJSON(t, admin, http.MethodDelete, cfg.AdminPath+"admin/api/v1/events/"+url.PathEscape(aggregateID), nil)
	if resp.StatusCode != http.StatusOK || deletion["deleted_events"] != float64(rawHomeCount) {
		t.Fatalf("New API aggregate delete = %d %#v", resp.StatusCode, deletion)
	}
	remaining, err := st.Events(-1, model.ProductNewAPI, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 0 {
		t.Fatalf("New API aggregate delete left raw events visible: %d", len(remaining))
	}
}

func TestNewAPIHomeAggregationKeepsOtherSPARoutesIndependent(t *testing.T) {
	base := time.Date(2026, 9, 4, 10, 0, 0, 0, time.UTC)
	events := []model.Event{
		{EventID: "home", Product: model.ProductNewAPI, RouteTemplate: "newapi.spa", Method: "GET", SourceIP: "192.0.2.30", SessionID: "session-newapi", ObservedAt: base, RawRequest: &model.RawRequest{Route: "/", URL: "/"}},
		{EventID: "home-asset", Product: model.ProductNewAPI, RouteTemplate: "newapi.asset", Method: "GET", SourceIP: "192.0.2.30", SessionID: "session-newapi", ObservedAt: base.Add(time.Second), RawRequest: &model.RawRequest{Route: "/static/js/index.js", URL: "/static/js/index.js"}},
		{EventID: "login", Product: model.ProductNewAPI, RouteTemplate: "newapi.spa", Method: "GET", SourceIP: "192.0.2.30", SessionID: "session-newapi", ObservedAt: base.Add(2 * time.Second), RawRequest: &model.RawRequest{Route: "/login", URL: "/login"}},
		{EventID: "login-asset", Product: model.ProductNewAPI, RouteTemplate: "newapi.asset", Method: "GET", SourceIP: "192.0.2.30", SessionID: "session-newapi", ObservedAt: base.Add(3 * time.Second), RawRequest: &model.RawRequest{Route: "/static/js/login.js", URL: "/static/js/login.js"}},
	}

	aggregated := aggregateNewAPIHomeEvents(events)
	if len(aggregated) != 3 {
		t.Fatalf("New API independent SPA routes = %#v", aggregated)
	}
	var homeAggregate model.Event
	for _, event := range aggregated {
		if event.DisplayRoute == newAPIHomeDisplayRoute {
			homeAggregate = event
			continue
		}
		if event.RawRequest == nil || event.RawRequest.Route == "/" {
			t.Fatalf("New API non-home event was mislabeled or lost: %#v", event)
		}
	}
	if homeAggregate.EventID == "" || homeAggregate.AggregateCount != 2 || len(homeAggregate.AggregateEventIDs) != 2 {
		t.Fatalf("New API home aggregate = %#v", homeAggregate)
	}
}
