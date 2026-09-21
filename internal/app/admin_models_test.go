package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
)

func TestAdminInstanceModelSettingsCoverEveryProductAndPublicSurface(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}

	publicRoutes := map[string]string{
		model.ProductNewAPI: "/v1/models", model.ProductVLLM: "/v1/models", model.ProductOllama: "/api/tags",
		model.ProductSGLang: "/v1/models", model.ProductLocalAI: "/models/available",
	}
	for _, product := range model.Products() {
		resp, initial := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/instances/"+product+"/models", nil)
		if resp.StatusCode != http.StatusOK || len(initial["models"].([]any)) == 0 || len(initial["surfaces"].([]any)) == 0 {
			t.Fatalf("initial %s model settings = %d %#v", product, resp.StatusCode, initial)
		}
		resp, roundTripped := doJSON(t, admin, http.MethodPut, cfg.AdminPath+"admin/api/v1/instances/"+product+"/models", map[string]any{"models": initial["models"]})
		if resp.StatusCode != http.StatusOK || roundTripped["model_count"] != float64(len(initial["models"].([]any))) {
			t.Fatalf("default %s models could not round trip through settings = %d %#v", product, resp.StatusCode, roundTripped)
		}
		firstID, secondID := "custom-"+product+"-primary", "custom-"+product+"-secondary"
		models := []any{
			map[string]any{"id": "entry-primary", "public_model_id": firstID, "display_name": "Primary " + product, "provider": "openai", "origin": "closed", "capabilities": []string{"chat", "tools"}, "api_families": []string{"openai", "responses"}, "visibility": []string{"guest", "user"}, "auth_requirement": "honey_key", "virtual_context_tokens": 65536, "virtual_price_profile": "test-tier", "status": "active", "aliases": []string{}, "response_template_set": "openai", "architecture": "test-arch", "families": []string{"test-family"}, "parameter_size": "7B", "quantization_level": "Q4_K_M", "approx_size": 1234567},
			map[string]any{"id": "entry-secondary", "public_model_id": secondID, "display_name": "Secondary " + product, "provider": "openai-codex", "origin": "closed", "capabilities": []string{"chat"}, "visibility": []string{"guest", "user"}, "status": "active"},
			map[string]any{"id": "entry-disabled", "public_model_id": "custom-" + product + "-disabled", "display_name": "Disabled " + product, "provider": "openai", "origin": "closed", "capabilities": []string{"chat"}, "visibility": []string{"user"}, "status": "disabled"},
			map[string]any{"id": "entry-user", "public_model_id": "custom-" + product + "-user", "display_name": "User " + product, "provider": "openai", "origin": "closed", "capabilities": []string{"chat"}, "visibility": []string{"user"}, "status": "active"},
		}
		resp, updated := doJSON(t, admin, http.MethodPut, cfg.AdminPath+"admin/api/v1/instances/"+product+"/models", map[string]any{"models": models})
		if resp.StatusCode != http.StatusOK || updated["custom"] != true || updated["model_count"] != float64(4) {
			t.Fatalf("updated %s model settings = %d %#v", product, resp.StatusCode, updated)
		}
		catalog := a.catalogFor(product)
		if len(catalog) != 2 || catalog[0].ID != firstID || catalog[0].DisplayName != "Primary "+product || catalog[0].VirtualContextTokens != 65536 || catalog[0].Architecture != "test-arch" || catalog[1].ID != secondID {
			t.Fatalf("runtime %s catalog = %#v", product, catalog)
		}
		if userCatalog := a.catalogForAudience(product, "user"); len(userCatalog) != 3 || userCatalog[2].ID != "custom-"+product+"-user" {
			t.Fatalf("user-visible %s catalog = %#v", product, userCatalog)
		}
		if route := publicRoutes[product]; route != "" {
			public := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[product]), cookies: map[string]string{}}
			resp, body := doRawJSON(t, public, http.MethodGet, route, nil, map[string]string{"User-Agent": "model-settings-" + product})
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), firstID) || !strings.Contains(string(body), secondID) {
				t.Fatalf("%s public model surface %s = %d %s", product, route, resp.StatusCode, body)
			}
		}
		if product == model.ProductSGLang {
			public := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[product]), cookies: map[string]string{}}
			for _, route := range []string{"/get_model_info", "/server_info"} {
				resp, body := doRawJSON(t, public, http.MethodGet, route, nil, map[string]string{"User-Agent": "sglang-model-info-" + route})
				if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), firstID) || strings.Contains(string(body), "Qwen/Qwen3.6") {
					t.Fatalf("SGLang %s did not use configured model: %d %s", route, resp.StatusCode, body)
				}
			}
		}
		if product == model.ProductNewAPI {
			public := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[product]), cookies: map[string]string{}}
			resp, body := doRawJSON(t, public, http.MethodGet, "/v1/models", nil, map[string]string{"User-Agent": "anthropic-model-settings", "x-api-key": "honey", "anthropic-version": "2023-06-01"})
			if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "Primary new-api") || !strings.Contains(string(body), "Secondary new-api") {
				t.Fatalf("Anthropic display names did not use runtime catalog: %d %s", resp.StatusCode, body)
			}
		}
		if product == model.ProductSub2API {
			plaza, _ := json.Marshal(sub2APIModelPlaza(catalog))
			codex, _ := json.Marshal(sub2APICodexModelsManifest(catalog))
			if !strings.Contains(string(plaza), firstID) || !strings.Contains(string(plaza), secondID) || !strings.Contains(string(codex), firstID) || !strings.Contains(string(codex), secondID) {
				t.Fatalf("Sub2API model surfaces diverged: plaza=%s codex=%s", plaza, codex)
			}
		}
	}

	resp, restored := doJSON(t, admin, http.MethodPut, cfg.AdminPath+"admin/api/v1/instances/ollama/models", map[string]any{"restore_default": true})
	if resp.StatusCode != http.StatusOK || restored["custom"] != false || len(a.catalogFor(model.ProductOllama)) < 2 {
		t.Fatalf("restore default Ollama catalog = %d %#v", resp.StatusCode, restored)
	}
}

func TestAdminInstanceModelSettingsRejectDuplicatePublicIDs(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	entry := map[string]any{"public_model_id": "duplicate", "display_name": "Duplicate", "provider": "local", "origin": "open", "capabilities": []string{"chat"}}
	resp, _ := doJSON(t, admin, http.MethodPut, cfg.AdminPath+"admin/api/v1/instances/ollama/models", map[string]any{"models": []any{entry, entry}})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate model id status = %d", resp.StatusCode)
	}
}
