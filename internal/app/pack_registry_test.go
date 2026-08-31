package app

import (
	"net/http"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
)

func TestAdminDetectorPackLifecycleAndHotLoad(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	definition := map[string]any{
		"schema_version": 1,
		"revision":       "custom-r1",
		"rules": []any{map[string]any{
			"id":          "CUSTOM_HOME_V1",
			"type":        "atomic",
			"reason_code": "custom_home_probe",
			"score":       22,
			"confidence":  "medium",
			"where":       map[string]any{"field": "route_template", "op": "eq", "value": "ollama.home"},
		}},
	}
	resp, created := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/rule-packs", map[string]any{"id": "custom-detector", "definition": definition})
	if resp.StatusCode != http.StatusCreated || created["pack"] == nil {
		t.Fatalf("create detector pack = %d %#v", resp.StatusCode, created)
	}
	resp, validated := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/rule-packs/custom-detector:validate", nil)
	if resp.StatusCode != http.StatusOK || validated["valid"] != true {
		t.Fatalf("validate detector pack = %d %#v", resp.StatusCode, validated)
	}
	resp, activated := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/rule-packs/custom-detector:activate", nil)
	if resp.StatusCode != http.StatusOK || activated["pack"] == nil {
		t.Fatalf("activate detector pack = %d %#v", resp.StatusCode, activated)
	}
	resp, rules := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/rule-packs/custom-detector/rules", nil)
	if resp.StatusCode != http.StatusOK || rules["count"] != float64(1) {
		t.Fatalf("list detector rules = %d %#v", resp.StatusCode, rules)
	}

	public := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductOllama]), cookies: map[string]string{}}
	resp = public.do(t, http.MethodGet, "/", nil, "")
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("custom rule request status = %d", resp.StatusCode)
	}
	events, err := st.Events(20, model.ProductOllama, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 || !strings.Contains(strings.Join(events[0].MatchedRuleIDs, ","), "CUSTOM_HOME_V1") || events[0].Score < 22 {
		t.Fatalf("custom rule was not hot-loaded: %#v", events)
	}

	resp, added := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/rule-packs/custom-detector/rules", map[string]any{"id": "CUSTOM_STATUS_V1", "type": "atomic", "reason_code": "custom_status_probe", "score": 10, "where": map[string]any{"field": "status", "op": "eq", "value": 200}})
	if resp.StatusCode != http.StatusCreated || added["pack"] == nil {
		t.Fatalf("add detector rule = %d %#v", resp.StatusCode, added)
	}
	resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/rule-packs/custom-detector:activate", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("activate edited detector pack status = %d", resp.StatusCode)
	}
	resp, rolledBack := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/rule-packs/custom-detector:rollback", nil)
	if resp.StatusCode != http.StatusOK || rolledBack["pack"] == nil || rolledBack["pack"].(map[string]any)["revision"] != "custom-r1" {
		t.Fatalf("rollback detector pack = %d %#v", resp.StatusCode, rolledBack)
	}
}
