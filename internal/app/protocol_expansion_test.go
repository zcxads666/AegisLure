package app

import (
	"net/http"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
)

func TestSGLangManagementEffectIsVisibleOnlyToSameSession(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	cfg.Scenario[model.ProductSGLang] = "no-key"
	profile := profiles.Build(cfg)[model.ProductSGLang]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	resp, schema := doJSON(t, client, http.MethodGet, "/openapi.json", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SGLang OpenAPI status = %d", resp.StatusCode)
	}
	paths, ok := schema["paths"].(map[string]any)
	if !ok || paths["/v1/responses"] == nil || paths["/flush_cache"] == nil || paths["/get_weights_by_name"] == nil {
		t.Fatalf("SGLang OpenAPI route set incomplete: %#v", schema)
	}
	resp, info := doJSON(t, client, http.MethodGet, "/server_info", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SGLang server_info status = %d", resp.StatusCode)
	}
	key, ok := info["api_key"].(string)
	if !ok || key == "" {
		t.Fatalf("SGLang honey key missing: %#v", info)
	}
	resp, action := doJSONWithHeaders(t, client, http.MethodPost, "/load_lora_adapter_from_tensors", map[string]string{"tensors": "bounded"}, map[string]string{"Authorization": "Bearer " + key})
	if resp.StatusCode != http.StatusOK || action["adapter_name"] != "adapter-canary" {
		t.Fatalf("SGLang LoRA action = %d %#v", resp.StatusCode, action)
	}
	resp, info = doJSON(t, client, http.MethodGet, "/server_info", nil)
	if resp.StatusCode != http.StatusOK || info["lora_adapters"] == nil {
		t.Fatalf("SGLang effect was not visible after action: %d %#v", resp.StatusCode, info)
	}
	events, err := st.Events(20, model.ProductSGLang, "")
	if err != nil {
		t.Fatal(err)
	}
	verified := false
	for _, event := range events {
		if event.RouteTemplate == "sglang.server_info" && event.EffectOutcome == "verified" {
			verified = true
		}
	}
	if !verified {
		t.Fatalf("SGLang follow-up verification was not recorded: %#v", events)
	}
	resp, completion := doJSON(t, client, http.MethodPost, "/v1/responses", map[string]any{"model": "Qwen/Qwen3.6-35B-A3B", "input": "hello"})
	if resp.StatusCode != http.StatusOK || completion["object"] != "response" {
		t.Fatalf("SGLang Responses compatibility = %d %#v", resp.StatusCode, completion)
	}
}

func TestLocalAIVirtualInstallTaskAndRBAC(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	profile := profiles.Build(cfg)[model.ProductLocalAI]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	resp, available := doJSON(t, client, http.MethodGet, "/models/available", nil)
	if resp.StatusCode != http.StatusOK || available["models"] == nil {
		t.Fatalf("LocalAI gallery status = %d %#v", resp.StatusCode, available)
	}
	resp, applied := doJSON(t, client, http.MethodPost, "/models/apply", map[string]string{"url": "http://127.0.0.1/model.tar", "model": "Qwen/Qwen3.6-35B-A3B"})
	if resp.StatusCode != http.StatusOK || applied["status"] != "ready" {
		t.Fatalf("LocalAI apply status = %d %#v", resp.StatusCode, applied)
	}
	jobID, _ := applied["id"].(string)
	resp, task := doJSON(t, client, http.MethodGet, "/models/jobs/"+jobID, nil)
	if resp.StatusCode != http.StatusOK || task["status"] != "ready" {
		t.Fatalf("LocalAI task status = %d %#v", resp.StatusCode, task)
	}
	resp, installed := doJSON(t, client, http.MethodGet, "/models/installed", nil)
	if resp.StatusCode != http.StatusOK || len(installed["models"].([]any)) != 1 {
		t.Fatalf("LocalAI installed list = %d %#v", resp.StatusCode, installed)
	}
	resp, _ = doJSON(t, client, http.MethodPost, "/models/delete", map[string]string{"model": "Qwen/Qwen3.6-35B-A3B"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LocalAI delete status = %d", resp.StatusCode)
	}
	resp, installed = doJSON(t, client, http.MethodGet, "/models/installed", nil)
	if resp.StatusCode != http.StatusOK || len(installed["models"].([]any)) != 0 {
		t.Fatalf("LocalAI installed list after delete = %d %#v", resp.StatusCode, installed)
	}
	resp = client.do(t, http.MethodPost, "/v1/audio/speech", strings.NewReader(`{"input":"hello"}`), "application/json")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "audio/mpeg") {
		t.Fatalf("LocalAI speech = %d %#v", resp.StatusCode, resp.Header)
	}
	_ = resp.Body.Close()

	cfg.Scenario[model.ProductLocalAI] = "current-rbac"
	rbac := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductLocalAI]), cookies: map[string]string{}}
	resp, _ = doJSON(t, rbac, http.MethodPost, "/models/apply", map[string]string{"model": "Qwen/Qwen3.6-35B-A3B"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("LocalAI current-RBAC apply without key = %d", resp.StatusCode)
	}
}
