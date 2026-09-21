package app

import (
	"io"
	"net/http"
	"strings"
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

	raw := admin.do(t, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators?format=csv", nil, "")
	allCSV, err := io.ReadAll(raw.Body)
	_ = raw.Body.Close()
	if err != nil || raw.StatusCode != http.StatusOK || !strings.Contains(string(allCSV), "203.0.113.10") || !strings.Contains(string(allCSV), "203.0.113.13") || len(strings.Split(strings.TrimSpace(string(allCSV)), "\n")) != 5 {
		t.Fatalf("full indicator CSV export = %d %v %s", raw.StatusCode, err, allCSV)
	}
	raw = admin.do(t, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators?format=plain&q=203.0.113.12&risk_level=high", nil, "")
	filteredPlain, err := io.ReadAll(raw.Body)
	_ = raw.Body.Close()
	if err != nil || raw.StatusCode != http.StatusOK || string(filteredPlain) != "203.0.113.12\n" {
		t.Fatalf("filtered indicator plain export = %d %v %q", raw.StatusCode, err, filteredPlain)
	}
	raw = admin.do(t, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators?format=csv&q=203.0.113.12&risk_level=high", nil, "")
	filteredCSV, err := io.ReadAll(raw.Body)
	_ = raw.Body.Close()
	if err != nil || raw.StatusCode != http.StatusOK || len(strings.Split(strings.TrimSpace(string(filteredCSV)), "\n")) != 2 || !strings.Contains(string(filteredCSV), "203.0.113.12") {
		t.Fatalf("filtered indicator CSV export = %d %v %s", raw.StatusCode, err, filteredCSV)
	}
}

func TestAdminIndicatorsExposeAssociatedIPMarker(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	base := time.Date(2026, time.September, 9, 10, 0, 0, 0, time.UTC)
	if err := st.AppendEvent(model.Event{
		EventID:    "associated-indicator-source",
		Product:    model.ProductNewAPI,
		SourceIP:   "198.51.100.20",
		ObservedAt: base,
		Score:      41,
		Metadata: map[string]string{
			model.MetadataRiskAssociatedIPs:     "198.51.100.21",
			model.MetadataRiskAssociationReason: "frontend_webrtc_ip_mismatch",
		},
	}); err != nil {
		t.Fatal(err)
	}
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	resp, body := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators?sort=risk", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("indicator response status = %d body = %#v", resp.StatusCode, body)
	}
	rawItems, ok := body["items"].([]any)
	if !ok || len(rawItems) != 2 {
		t.Fatalf("associated indicator items = %#v", body["items"])
	}
	for _, raw := range rawItems {
		item := raw.(map[string]any)
		if item["associated"] != true || item["score"] != float64(41) {
			t.Fatalf("indicator association marker = %#v", item)
		}
		peers, ok := item["associated_ips"].([]any)
		if !ok || len(peers) != 1 {
			t.Fatalf("indicator associated peers = %#v", item["associated_ips"])
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
