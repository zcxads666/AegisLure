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
	for _, key := range []string{"day", "week", "month"} {
		series := riskActivity[key].(map[string]any)
		points := series["points"].([]any)
		want := map[string]int{"day": 12, "week": 7, "month": 30}[key]
		if len(points) != want || points[0].(map[string]any)["risk_count"] == nil {
			t.Fatalf("risk activity %s = %#v", key, series)
		}
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
