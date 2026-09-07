package app

import (
	"net/http"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func indicatorIPsFromResponse(t *testing.T, body map[string]any) []string {
	t.Helper()
	rawItems, ok := body["items"].([]any)
	if !ok {
		t.Fatalf("indicator response items = %#v", body["items"])
	}
	ips := make([]string, 0, len(rawItems))
	for _, raw := range rawItems {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("indicator item = %#v", raw)
		}
		ip, ok := item["ip"].(string)
		if !ok {
			t.Fatalf("indicator ip = %#v", item["ip"])
		}
		ips = append(ips, ip)
	}
	return ips
}

func TestAdminIndicatorsDefaultSortRiskSortAndRiskLevelFilter(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()

	base := time.Date(2026, time.September, 7, 10, 0, 0, 0, time.UTC)
	events := []model.Event{
		{EventID: "indicator-latest-low", Product: model.ProductOllama, SourceIP: "203.0.113.10", ObservedAt: base.Add(4 * time.Minute), Score: 20},
		{EventID: "indicator-medium", Product: model.ProductOllama, SourceIP: "203.0.113.11", ObservedAt: base.Add(time.Minute), Score: 45},
		{EventID: "indicator-high", Product: model.ProductOllama, SourceIP: "203.0.113.12", ObservedAt: base.Add(2 * time.Minute), Score: 80},
		{EventID: "indicator-high-later", Product: model.ProductOllama, SourceIP: "203.0.113.13", ObservedAt: base.Add(3 * time.Minute), Score: 60},
	}
	for _, event := range events {
		if err := st.AppendEvent(event); err != nil {
			t.Fatalf("append indicator event: %v", err)
		}
	}

	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}

	resp, body := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators", nil)
	if resp.StatusCode != http.StatusOK || body["sort"] != "latest" || body["risk_level"] != "all" {
		t.Fatalf("default indicator list = %d %#v", resp.StatusCode, body)
	}
	if got, want := indicatorIPsFromResponse(t, body), []string{"203.0.113.10", "203.0.113.13", "203.0.113.12", "203.0.113.11"}; !equalStrings(got, want) {
		t.Fatalf("default indicator order = %v, want %v", got, want)
	}

	resp, body = doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators?sort=risk", nil)
	if resp.StatusCode != http.StatusOK || body["sort"] != "risk" {
		t.Fatalf("risk-sorted indicator list = %d %#v", resp.StatusCode, body)
	}
	if got, want := indicatorIPsFromResponse(t, body), []string{"203.0.113.12", "203.0.113.13", "203.0.113.11", "203.0.113.10"}; !equalStrings(got, want) {
		t.Fatalf("risk indicator order = %v, want %v", got, want)
	}

	for _, test := range []struct {
		level string
		want  []string
	}{
		{level: "high", want: []string{"203.0.113.13", "203.0.113.12"}},
		{level: "medium", want: []string{"203.0.113.11"}},
		{level: "low", want: []string{"203.0.113.10"}},
	} {
		resp, body = doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators?risk_level="+test.level, nil)
		if resp.StatusCode != http.StatusOK || body["risk_level"] != test.level {
			t.Fatalf("%s indicator filter = %d %#v", test.level, resp.StatusCode, body)
		}
		if got := indicatorIPsFromResponse(t, body); !equalStrings(got, test.want) {
			t.Fatalf("%s indicator order = %v, want %v", test.level, got, test.want)
		}
	}

	for _, query := range []string{"risk_level=critical", "sort=oldest"} {
		resp, _ = doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators?"+query, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("invalid indicator query %q status = %d", query, resp.StatusCode)
		}
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
