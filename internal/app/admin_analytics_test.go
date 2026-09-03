package app

import (
	"net/http"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestAdminDashboardAnalyticsAndActorActions(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()

	now := time.Now().UTC()
	events := []model.Event{
		{EventID: "analytics-local", Product: model.ProductOllama, SourceIP: "127.0.0.1", ObservedAt: now.Add(-30 * time.Minute), Score: 12, EventType: "http.request.classified"},
		{EventID: "analytics-doc-medium", Product: model.ProductNewAPI, SourceIP: "192.0.2.5", ObservedAt: now.Add(-2 * time.Hour), Score: 45, EventType: "http.request.classified"},
		{EventID: "analytics-doc-high", Product: model.ProductVLLM, SourceIP: "198.51.100.8", ObservedAt: now.Add(-26 * time.Hour), Score: 80, EventType: "http.request.classified"},
	}
	for _, event := range events {
		if err := st.AppendEvent(event); err != nil {
			t.Fatalf("append analytics event: %v", err)
		}
	}

	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}

	resp, dashboard := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/dashboard", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard status = %d %#v", resp.StatusCode, dashboard)
	}
	if dashboard["risk_activity"] == nil || dashboard["source_countries"] == nil || dashboard["honeypot_distribution"] == nil || dashboard["risk_trigger_distribution"] == nil {
		t.Fatalf("dashboard analytics fields missing: %#v", dashboard)
	}
	counts := dashboard["counts"].(map[string]any)
	if counts["risk_events"] != float64(2) || counts["risk_rate"] != float64(67) {
		t.Fatalf("dashboard risk summary = %#v", counts)
	}
	riskActivity := dashboard["risk_activity"].(map[string]any)
	for _, key := range []string{"hour", "week", "month"} {
		series := riskActivity[key].(map[string]any)
		points := series["points"].([]any)
		want := map[string]int{"hour": 24, "week": 7, "month": 30}[key]
		if len(points) != want || points[0].(map[string]any)["risk_count"] == nil {
			t.Fatalf("risk activity %s = %#v", key, series)
		}
	}
	if riskActivity["day"] == nil {
		t.Fatal("risk activity compatibility alias is missing")
	}
	countries := dashboard["source_countries"].([]any)
	if len(countries) != 1 || countries[0].(map[string]any)["name"] != "文档地址" || countries[0].(map[string]any)["count"] != float64(2) || countries[0].(map[string]any)["percentage"] != float64(100) {
		t.Fatalf("source country aggregation = %#v", countries)
	}
	honeypots := dashboard["honeypot_distribution"].([]any)
	if len(honeypots) != 3 || honeypots[0].(map[string]any)["percentage"] != float64(33) {
		t.Fatalf("honeypot distribution = %#v", honeypots)
	}
	riskTriggers := dashboard["risk_trigger_distribution"].([]any)
	if len(riskTriggers) != 3 || riskTriggers[0].(map[string]any)["key"] != "high" || riskTriggers[0].(map[string]any)["count"] != float64(1) {
		t.Fatalf("risk trigger distribution = %#v", riskTriggers)
	}

	resp, actor := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/actors/192.0.2.5", nil)
	if resp.StatusCode != http.StatusOK || actor["country"] != "文档地址" || actor["event_count"] != float64(1) || len(actor["events"].([]any)) != 1 {
		t.Fatalf("actor action detail = %d %#v", resp.StatusCode, actor)
	}
}

func TestDashboardTimeSeriesUsesCalendarBucketsAndRefreshBoundaries(t *testing.T) {
	location := time.FixedZone("CST", 8*60*60)
	now := time.Date(2026, time.September, 3, 10, 37, 0, 0, location)
	events := []model.Event{
		{EventID: "hour-current", ObservedAt: time.Date(2026, time.September, 3, 10, 12, 0, 0, location), Score: 55},
		{EventID: "hour-previous", ObservedAt: time.Date(2026, time.September, 3, 9, 41, 0, 0, location), Score: 20},
		{EventID: "day-previous", ObservedAt: time.Date(2026, time.September, 2, 23, 40, 0, 0, location), Score: 80},
		{EventID: "day-current", ObservedAt: time.Date(2026, time.September, 3, 0, 10, 0, 0, location), Score: 40},
	}

	hour := dashboardTimeSeries(events, now, 24, time.Hour, "01/02 15:00")
	hourPoints := hour["points"].([]map[string]any)
	if len(hourPoints) != 24 {
		t.Fatalf("hour point count = %d", len(hourPoints))
	}
	if got := hourPoints[len(hourPoints)-1]["label"]; got != "09/03 10:00" {
		t.Fatalf("current hour label = %v", got)
	}
	if got := hourPoints[len(hourPoints)-1]["count"]; got != 1 {
		t.Fatalf("current hour count = %v", got)
	}
	if got := hourPoints[len(hourPoints)-2]["count"]; got != 1 {
		t.Fatalf("previous hour count = %v", got)
	}
	if got := hour["next_refresh_at"].(time.Time); !got.Equal(time.Date(2026, time.September, 3, 11, 0, 0, 0, location).UTC()) {
		t.Fatalf("hour next refresh = %s", got)
	}

	week := dashboardTimeSeries(events, now, 7, 24*time.Hour, "01/02")
	weekPoints := week["points"].([]map[string]any)
	if got := weekPoints[len(weekPoints)-2]["count"]; got != 1 {
		t.Fatalf("previous calendar day count = %v", got)
	}
	if got := weekPoints[len(weekPoints)-1]["count"]; got != 3 {
		t.Fatalf("current calendar day count = %v", got)
	}
	if got := weekPoints[len(weekPoints)-2]["label"]; got != "09/02" {
		t.Fatalf("previous calendar day label = %v", got)
	}
	if got := weekPoints[len(weekPoints)-1]["label"]; got != "09/03" {
		t.Fatalf("current calendar day label = %v", got)
	}
	nextDay := dashboardTimeSeries(events, time.Date(2026, time.September, 4, 0, 5, 0, 0, location), 7, 24*time.Hour, "01/02")
	if got, want := week["window_start_at"].(time.Time), time.Date(2026, time.August, 28, 0, 0, 0, 0, location).UTC(); !got.Equal(want) {
		t.Fatalf("week window start = %s, want %s", got, want)
	}
	if got, want := nextDay["window_start_at"].(time.Time), time.Date(2026, time.August, 29, 0, 0, 0, 0, location).UTC(); !got.Equal(want) {
		t.Fatalf("next-day week window start = %s, want %s", got, want)
	}

	month := dashboardTimeSeries(events, now, 30, 24*time.Hour, "01/02")
	if got := month["bucket"]; got != "day" {
		t.Fatalf("month bucket = %v", got)
	}
	if got, want := month["next_refresh_at"].(time.Time), time.Date(2026, time.September, 4, 0, 0, 0, 0, location).UTC(); !got.Equal(want) {
		t.Fatalf("month next refresh = %s, want %s", got, want)
	}
}

func TestDashboardTimeSeriesUsesAsiaShanghaiWhenInputIsUTC(t *testing.T) {
	now := time.Date(2026, time.September, 3, 6, 37, 0, 0, time.UTC)
	events := []model.Event{
		{EventID: "utc-current-hour", ObservedAt: time.Date(2026, time.September, 3, 6, 12, 0, 0, time.UTC), Score: 55},
		{EventID: "utc-previous-hour", ObservedAt: time.Date(2026, time.September, 3, 5, 41, 0, 0, time.UTC), Score: 20},
	}

	series := dashboardTimeSeries(events, now, 24, time.Hour, "01/02 15:00")
	points := series["points"].([]map[string]any)
	latest := points[len(points)-1]
	previous := points[len(points)-2]
	if got := latest["label"]; got != "09/03 14:00" {
		t.Fatalf("UTC input must render the Shanghai current-hour label, got %v", got)
	}
	if latest["count"] != 1 || previous["count"] != 1 {
		t.Fatalf("UTC input was not assigned to Shanghai calendar hours: latest=%v previous=%v", latest["count"], previous["count"])
	}
	wantNext := time.Date(2026, time.September, 3, 15, 0, 0, 0, dashboardShanghaiLocation).UTC()
	if got := series["next_refresh_at"].(time.Time); !got.Equal(wantNext) {
		t.Fatalf("Shanghai next refresh = %s, want %s", got, wantNext)
	}
	if got := series["timezone"]; got != model.InteractionChainTimezone {
		t.Fatalf("dashboard timezone = %v", got)
	}
}
