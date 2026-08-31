package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

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

func TestAdminModelAndAllPackBindingsApplyToTheLocalProfile(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	modelDefinition := map[string]any{
		"schema_version": 1,
		"revision":       "custom-model-r1",
		"catalogs": []any{map[string]any{
			"id":            "custom-newapi",
			"origin_policy": "closed",
			"products":      []string{model.ProductNewAPI},
			"models":        []string{"provider/custom-model"},
		}},
		"safety_contract": map[string]bool{"contains_endpoint": false, "contains_secret": false, "contains_download_url": false, "real_inference": false},
	}
	resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/model-catalogs", map[string]any{"id": "custom-model", "definition": modelDefinition})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create model pack status = %d", resp.StatusCode)
	}
	for _, action := range []string{"validate", "activate"} {
		resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/model-catalogs/custom-model:"+action, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("model pack %s status = %d", action, resp.StatusCode)
		}
	}
	resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/instances/new-api:assign-model-catalog", map[string]string{"pack_id": "custom-model"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("model pack assignment status = %d", resp.StatusCode)
	}
	public := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductNewAPI]), cookies: map[string]string{}}
	resp, body := doRawJSON(t, public, http.MethodGet, "/v1/models", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("custom model list status = %d", resp.StatusCode)
	}
	var listed struct {
		Data []profiles.CatalogEntry `json:"data"`
	}
	if err := json.Unmarshal(body, &listed); err != nil || len(listed.Data) != 1 || listed.Data[0].ID != "provider/custom-model" {
		t.Fatalf("custom model catalog was not applied: %s", body)
	}
	if entry, ok := a.resolveCatalogModel(model.ProductNewAPI, "provider/custom-model"); !ok || entry.ID != "provider/custom-model" {
		t.Fatalf("custom model resolver did not use the bound catalog: %#v %v", entry, ok)
	}

	bindings := []struct {
		path   string
		packID string
	}{
		{path: "fingerprint", packID: "newapi-web-v1"},
		{path: "scenario", packID: "builtin-safe-v1"},
		{path: "detector", packID: "builtin-rules-v1"},
	}
	for _, binding := range bindings {
		resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/instances/new-api:assign-"+binding.path, map[string]string{"pack_id": binding.packID})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s pack assignment status = %d", binding.path, resp.StatusCode)
		}
	}
	scenarioDefinition := map[string]any{
		"schema_version": 1,
		"revision":       "custom-scenario-r1",
		"packs": []any{map[string]any{
			"id":                 "custom-newapi-scenario",
			"product":            model.ProductNewAPI,
			"auth_posture":       "guest_then_honey_key",
			"effect_scope":       "actor",
			"effect_ttl_seconds": 7,
		}},
	}
	resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/scenario-packs", map[string]any{"id": "custom-scenario", "definition": scenarioDefinition})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create scenario pack status = %d", resp.StatusCode)
	}
	for _, action := range []string{"validate", "activate"} {
		resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/scenario-packs/custom-scenario:"+action, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("scenario pack %s status = %d", action, resp.StatusCode)
		}
	}
	resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/instances/new-api:assign-scenario", map[string]string{"pack_id": "custom-scenario"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scenario pack assignment status = %d", resp.StatusCode)
	}
	runtimeProfile := a.applyRuntimePacks(profiles.Build(cfg)[model.ProductNewAPI])
	if runtimeProfile.Scenario != "guest_then_honey_key" || runtimeProfile.EffectScope != "actor" || runtimeProfile.EffectTTL != 7*time.Second {
		t.Fatalf("custom scenario was not applied to the runtime profile: %#v", runtimeProfile)
	}
	if len(st.PackBindings()) != 4 {
		t.Fatalf("local profile did not retain all pack bindings: %#v", st.PackBindings())
	}
}

func TestRichModelCatalogVisibilityAndPublicRenderer(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	definition := map[string]any{
		"schema_version": 1,
		"revision":       "rich-model-r1",
		"catalogs": []any{map[string]any{
			"id":            "rich-newapi",
			"origin_policy": "closed",
			"products":      []string{model.ProductNewAPI},
			"entries": []any{
				map[string]any{
					"id":                     "entry-guest",
					"public_model_id":        "provider/guest-model",
					"display_name":           "Guest Model",
					"provider":               "provider",
					"origin":                 "closed",
					"capabilities":           []string{"chat", "tools"},
					"api_families":           []string{"openai-compatible"},
					"visibility":             []string{"guest", "user"},
					"auth_requirement":       "honey_key",
					"virtual_context_tokens": 32768,
					"virtual_price_profile":  "closed-tier-standard",
					"response_template_set":  "general-chat-v2",
					"status":                 "active",
					"aliases":                []string{"guest-alias"},
				},
				map[string]any{
					"id":              "entry-user",
					"public_model_id": "provider/user-model",
					"display_name":    "User Model",
					"provider":        "provider",
					"origin":          "closed",
					"capabilities":    []string{"chat"},
					"visibility":      []string{"user"},
					"status":          "active",
				},
			},
		}},
		"safety_contract": map[string]bool{"contains_endpoint": false, "contains_secret": false, "contains_download_url": false, "real_inference": false},
	}
	resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/model-catalogs", map[string]any{"id": "rich-model", "definition": definition})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create rich model pack status = %d", resp.StatusCode)
	}
	for _, action := range []string{"validate", "activate"} {
		resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/model-catalogs/rich-model:"+action, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("rich model pack %s status = %d", action, resp.StatusCode)
		}
	}
	resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/instances/new-api:assign-model-catalog", map[string]string{"pack_id": "rich-model"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rich model pack assignment status = %d", resp.StatusCode)
	}

	public := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductNewAPI]), cookies: map[string]string{}}
	resp, body := doRawJSON(t, public, http.MethodGet, "/v1/models", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rich model list status = %d", resp.StatusCode)
	}
	var listed struct {
		Data []profiles.OllamaOpenAIModel `json:"data"`
	}
	if err := json.Unmarshal(body, &listed); err != nil || len(listed.Data) != 1 || listed.Data[0].ID != "provider/guest-model" || listed.Data[0].OwnedBy != "new-api" {
		t.Fatalf("guest model renderer/visibility failed: %s %#v", body, listed)
	}
	for _, internalField := range []string{"\"display_name\"", "\"provider\"", "\"origin\"", "\"capabilities\"", "\"aliases\"", "\"virtual_context_tokens\"", "closed-tier-standard"} {
		if strings.Contains(string(body), internalField) {
			t.Fatalf("public model renderer leaked %q: %s", internalField, body)
		}
	}
	if _, ok := a.resolveCatalogModelForAudience(model.ProductNewAPI, "provider/user-model", "guest"); ok {
		t.Fatal("user-only model was visible to guest audience")
	}
	entry, ok := a.resolveCatalogModelForAudience(model.ProductNewAPI, "guest-alias", "user")
	if !ok || entry.ID != "provider/guest-model" || entry.VirtualContextTokens != 32768 || entry.AuthRequirement != "honey_key" {
		t.Fatalf("rich catalog metadata or alias was not retained internally: %#v %v", entry, ok)
	}
	if entry, ok = a.resolveCatalogModelForAudience(model.ProductNewAPI, "provider/user-model", "user"); !ok || entry.ID != "provider/user-model" {
		t.Fatalf("user-only model was not available to user audience: %#v %v", entry, ok)
	}
	resp, catalogView := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/model-catalogs/rich-model/models", nil)
	if resp.StatusCode != http.StatusOK || len(catalogView["catalogs"].([]any)) != 1 {
		t.Fatalf("rich model catalog detail status = %d %#v", resp.StatusCode, catalogView)
	}
	resp, patched := doJSON(t, admin, http.MethodPatch, cfg.AdminPath+"admin/api/v1/model-catalogs/rich-model/models/entry-guest", map[string]any{"display_name": "Guest Model Revised", "virtual_context_tokens": 65536})
	if resp.StatusCode != http.StatusOK || patched["pack"] == nil {
		t.Fatalf("rich model entry patch status = %d %#v", resp.StatusCode, patched)
	}
	latest, ok := st.GetPack(model.PackKindModel, "rich-model")
	if !ok || latest.Lifecycle != model.PackDraft || latest.PreviousRevision == "" {
		t.Fatalf("model patch did not create a draft revision: %#v", latest)
	}
	for _, action := range []string{"validate", "activate"} {
		resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/model-catalogs/rich-model:"+action, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("patched rich model pack %s status = %d", action, resp.StatusCode)
		}
	}
	resp, cloned := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/model-catalogs/rich-model:clone", map[string]string{"id": "rich-model-copy", "revision": "rich-model-copy-r1"})
	if resp.StatusCode != http.StatusCreated || cloned["pack"] == nil {
		t.Fatalf("rich model clone status = %d %#v", resp.StatusCode, cloned)
	}
}

func TestModelCatalogRevisionIsPinnedPerPublicSession(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	createAndAssign := func(packID, revision, publicModelID string) {
		t.Helper()
		definition := map[string]any{"schema_version": 1, "revision": revision, "catalogs": []any{map[string]any{
			"id": "catalog-" + packID, "origin_policy": "closed", "products": []string{model.ProductNewAPI}, "entries": []any{map[string]any{
				"id": "entry-" + packID, "public_model_id": publicModelID, "display_name": publicModelID, "provider": "provider", "origin": "closed", "capabilities": []string{"chat"}, "visibility": []string{"guest", "user"}, "status": "active",
			}},
		}}, "safety_contract": map[string]bool{"contains_endpoint": false, "contains_secret": false, "contains_download_url": false, "real_inference": false}}
		resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/model-catalogs", map[string]any{"id": packID, "definition": definition})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s status = %d", packID, resp.StatusCode)
		}
		for _, action := range []string{"validate", "activate"} {
			resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/model-catalogs/"+packID+":"+action, nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s %s status = %d", packID, action, resp.StatusCode)
			}
		}
		resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/instances/new-api:assign-model-catalog", map[string]string{"pack_id": packID})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("assign %s status = %d", packID, resp.StatusCode)
		}
	}
	createAndAssign("catalog-a", "catalog-a-r1", "provider/model-a")
	clientA := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductNewAPI]), cookies: map[string]string{}}
	resp, body := doRawJSON(t, clientA, http.MethodGet, "/v1/models", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "provider/model-a") || strings.Contains(string(body), "provider/model-b") {
		t.Fatalf("initial session catalog = %d %s", resp.StatusCode, body)
	}
	createAndAssign("catalog-b", "catalog-b-r1", "provider/model-b")
	resp, body = doRawJSON(t, clientA, http.MethodGet, "/v1/models", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "provider/model-a") || strings.Contains(string(body), "provider/model-b") {
		t.Fatalf("pinned session catalog changed after activation = %d %s", resp.StatusCode, body)
	}
	clientB := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductNewAPI]), cookies: map[string]string{}}
	resp, body = doRawJSON(t, clientB, http.MethodGet, "/v1/models", nil, map[string]string{"User-Agent": "new-session-client"})
	if resp.StatusCode != http.StatusOK || strings.Contains(string(body), "provider/model-a") || !strings.Contains(string(body), "provider/model-b") {
		t.Fatalf("new session did not use current catalog = %d %s", resp.StatusCode, body)
	}
}
