package app

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
)

func TestVLLMChatCompletionAndSSEUpdateOneModelRuntime(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	cfg.Scenario[model.ProductVLLM] = "no-key"
	profile := profiles.Build(cfg)[model.ProductVLLM]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	modelName := profile.Persona.VLLM.MetricsModelName()

	_, beforeBody := doRawJSON(t, client, http.MethodGet, "/metrics", nil, nil)
	beforeSuccess := metricCounter(t, beforeBody, `vllm:request_success_total{finished_reason="stop",model_name="`+modelName+`"}`)

	request := map[string]any{
		"model":       modelName,
		"messages":    []any{map[string]string{"role": "user", "content": "hello"}},
		"stream":      false,
		"temperature": 0.2,
		"max_tokens":  16,
	}
	resp, body := doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", request, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Server") != "uvicorn" {
		t.Fatalf("vLLM non-stream headers/status = %d %#v body=%s", resp.StatusCode, resp.Header, body)
	}
	var completion map[string]any
	if err := json.Unmarshal(body, &completion); err != nil {
		t.Fatal(err)
	}
	if completion["object"] != "chat.completion" || completion["model"] != modelName || completion["id"] == "" {
		t.Fatalf("invalid non-stream completion: %#v", completion)
	}
	usage, ok := completion["usage"].(map[string]any)
	if !ok || usage["prompt_tokens"].(float64) <= 0 || usage["completion_tokens"].(float64) <= 0 {
		t.Fatalf("completion usage missing: %#v", completion["usage"])
	}

	_, afterBody := doRawJSON(t, client, http.MethodGet, "/metrics", nil, nil)
	afterSuccess := metricCounter(t, afterBody, `vllm:request_success_total{finished_reason="stop",model_name="`+modelName+`"}`)
	if afterSuccess <= beforeSuccess || strings.Contains(string(afterBody), `model_name="openai/gpt-oss-20b"`) || strings.Contains(string(afterBody), `model_name="meta-llama/`) {
		t.Fatalf("metrics did not track one-model runtime: before=%d after=%d body=%s", beforeSuccess, afterSuccess, afterBody)
	}

	resp, body = doRawJSON(t, client, http.MethodPost, "/v1/chat/completions", map[string]any{
		"model":    modelName,
		"messages": []any{map[string]string{"role": "user", "content": "stream this"}},
		"stream":   true,
	}, nil)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") || resp.Header.Get("Cache-Control") != "no-cache" || resp.Header.Get("Connection") != "keep-alive" {
		t.Fatalf("vLLM SSE headers/status = %d %#v body=%s", resp.StatusCode, resp.Header, body)
	}
	frames, done := parseSSE(t, body)
	if !done || len(frames) < 3 {
		t.Fatalf("SSE did not finish with enough chunks: done=%v frames=%d body=%s", done, len(frames), body)
	}
	firstChoice := choiceMap(t, frames[0])
	firstDelta, _ := firstChoice["delta"].(map[string]any)
	if firstDelta["role"] != "assistant" {
		t.Fatalf("first SSE chunk did not declare role: %#v", frames[0])
	}
	lastChoice := choiceMap(t, frames[len(frames)-1])
	if lastChoice["finish_reason"] != "stop" {
		t.Fatalf("final SSE chunk did not finish: %#v", frames[len(frames)-1])
	}
	for _, frame := range frames {
		if frame["model"] != modelName {
			t.Fatalf("SSE model drifted from /v1/models: %#v", frame)
		}
	}
}

func TestOllamaNativeStreamingAndPSLifecycle(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	profile := profiles.Build(cfg)[model.ProductOllama]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	modelName := "qwen3.6:35b-a3b"

	resp, body := doRawJSON(t, client, http.MethodPost, "/api/generate", map[string]any{"model": modelName, "prompt": "reply with ok", "stream": false}, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Server") == "uvicorn" || resp.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("Ollama generate headers/status = %d %#v body=%s", resp.StatusCode, resp.Header, body)
	}
	var generated map[string]any
	if err := json.Unmarshal(body, &generated); err != nil {
		t.Fatal(err)
	}
	if generated["model"] != modelName || generated["response"] != "OK" || generated["done"] != true || generated["done_reason"] != "stop" {
		t.Fatalf("invalid Ollama generate response: %#v", generated)
	}

	resp, psBody := doRawJSON(t, client, http.MethodGet, "/api/ps", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Ollama ps status = %d", resp.StatusCode)
	}
	var ps struct {
		Models []profiles.OllamaModel `json:"models"`
	}
	if err := json.Unmarshal(psBody, &ps); err != nil || len(ps.Models) != 1 || ps.Models[0].Name != modelName {
		t.Fatalf("Ollama ps did not reflect generate: %s %#v", psBody, ps)
	}
	_, tagsBody := doRawJSON(t, client, http.MethodGet, "/api/tags", nil, nil)
	var tags struct {
		Models []profiles.OllamaModel `json:"models"`
	}
	if err := json.Unmarshal(tagsBody, &tags); err != nil || len(tags.Models) == 0 || ps.Models[0].Digest != tags.Models[0].Digest || ps.Models[0].Details.Family != "qwen35moe" {
		t.Fatalf("Ollama ps metadata disagrees with tags: tags=%s ps=%s", tagsBody, psBody)
	}

	resp, body = doRawJSON(t, client, http.MethodPost, "/api/chat", map[string]any{"model": modelName, "messages": []any{map[string]string{"role": "user", "content": "hello"}}, "stream": true}, nil)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/x-ndjson") || resp.Header.Get("Server") == "uvicorn" {
		t.Fatalf("Ollama chat stream headers/status = %d %#v body=%s", resp.StatusCode, resp.Header, body)
	}
	lines := nonEmptyLines(body)
	if len(lines) < 2 {
		t.Fatalf("Ollama chat stream was too short: %s", body)
	}
	for index, line := range lines {
		var chunk map[string]any
		if err := json.Unmarshal([]byte(line), &chunk); err != nil {
			t.Fatalf("invalid Ollama JSONL chunk: %v: %s", err, line)
		}
		if _, hasChoices := chunk["choices"]; hasChoices || strings.Contains(line, "[DONE]") || chunk["model"] != modelName {
			t.Fatalf("Ollama stream borrowed OpenAI shape at %d: %s", index, line)
		}
		if index == len(lines)-1 && chunk["done"] != true {
			t.Fatalf("Ollama stream did not end with done=true: %s", line)
		}
	}

	resp, _ = doRawJSON(t, client, http.MethodPost, "/api/generate", map[string]any{"model": modelName, "prompt": "unload", "stream": false, "keep_alive": 0}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Ollama unload status = %d", resp.StatusCode)
	}
	_, psBody = doRawJSON(t, client, http.MethodGet, "/api/ps", nil, nil)
	if string(psBody) != "{\"models\":[]}\n" {
		t.Fatalf("Ollama ps did not expire explicit keep_alive=0: %s", psBody)
	}
}

func TestVLLMDocsDisabledByDefaultAndValidWhenEnabled(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	profile := profiles.Build(cfg)[model.ProductVLLM]
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	for _, endpoint := range []string{"/docs", "/openapi.json"} {
		resp, body := doRawJSON(t, client, http.MethodGet, endpoint, nil, nil)
		if resp.StatusCode != http.StatusNotFound || string(body) != "{\"detail\":\"Not Found\"}\n" || resp.Header.Get("Server") != "uvicorn" {
			t.Fatalf("disabled vLLM %s mismatch: %d %#v %s", endpoint, resp.StatusCode, resp.Header, body)
		}
	}

	cfg.VLLMDocsEnabled = true
	profile = profiles.Build(cfg)[model.ProductVLLM]
	client = &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	resp, body := doRawJSON(t, client, http.MethodGet, "/openapi.json", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enabled vLLM OpenAPI status = %d body=%s", resp.StatusCode, body)
	}
	var schema map[string]any
	if err := json.Unmarshal(body, &schema); err != nil {
		t.Fatal(err)
	}
	paths, ok := schema["paths"].(map[string]any)
	if !ok || len(paths) < 5 || schema["openapi"] == "" {
		t.Fatalf("enabled vLLM OpenAPI is incomplete: %#v", schema)
	}
	resp, body = doRawJSON(t, client, http.MethodGet, "/docs", nil, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "/openapi.json") || !strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("enabled vLLM docs mismatch: %d %#v %s", resp.StatusCode, resp.Header, body)
	}
}

func TestPersonaValidationAndHeaderIsolation(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	cfg.Scenario[model.ProductVLLM] = "no-key"
	ollama := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductOllama]), cookies: map[string]string{}}
	vllm := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductVLLM]), cookies: map[string]string{}}

	badOllama := []struct {
		body any
		want int
	}{
		{map[string]any{"model": "qwen3.6:35b-a3b", "messages": []any{}, "stream": false}, http.StatusBadRequest},
		{map[string]any{"model": "qwen3.6:35b-a3b", "prompt": "x", "stream": "false"}, http.StatusBadRequest},
	}
	for _, check := range badOllama {
		resp, body := doRawJSON(t, ollama, http.MethodPost, "/api/chat", check.body, nil)
		if resp.StatusCode != check.want || !strings.Contains(string(body), `"error"`) || resp.Header.Get("Server") == "uvicorn" {
			t.Fatalf("Ollama validation mismatch: %d %#v %s", resp.StatusCode, resp.Header, body)
		}
	}
	resp, body := doRawJSON(t, vllm, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "Qwen/Qwen3.6-35B-A3B", "messages": []any{}}, nil)
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(body), `"detail"`) || resp.Header.Get("Server") != "uvicorn" || resp.Header.Get("Referrer-Policy") != "" {
		t.Fatalf("vLLM validation/header mismatch: %d %#v %s", resp.StatusCode, resp.Header, body)
	}
	resp, body = doRawJSON(t, vllm, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "not-a-served-model", "messages": []any{map[string]string{"role": "user", "content": "hello"}}}, nil)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(string(body), `"detail"`) {
		t.Fatalf("vLLM unknown model mismatch: %d %s", resp.StatusCode, body)
	}
}

func TestPersonaConfigurationAndErrorMatrix(t *testing.T) {
	a, cfg, _ := newTestApp(t, true)
	cfg.VLLMVersion = "0.11.0"
	cfg.Scenario[model.ProductVLLM] = "no-key"
	profilesByName := profiles.Build(cfg)
	vllmProfile := profilesByName[model.ProductVLLM]
	ollamaProfile := profilesByName[model.ProductOllama]
	if vllmProfile.Persona.VLLM.Version != "0.17.0" || len(vllmProfile.Persona.VLLM.ServedModelNames) != 1 || vllmProfile.Persona.VLLM.Model != "Qwen/Qwen3.6-35B-A3B" {
		t.Fatalf("vLLM profile is not coherent: %#v", vllmProfile.Persona.VLLM)
	}
	cfg.VLLMServedNames = []string{"qwen3.6:compat", "openai/gpt-oss-20b", "gpt-oss:20b"}
	withAliases := profiles.Build(cfg)[model.ProductVLLM].Persona.VLLM
	if len(withAliases.ServedModelNames) != 2 || withAliases.ServedModelNames[1] != "qwen3.6:compat" {
		t.Fatalf("vLLM aliases should remain aliases of one base model: %#v", withAliases.ServedModelNames)
	}
	ollamaModels := profiles.OllamaModelsForProfile(cfg.InstanceKey, ollamaProfile.Persona.Ollama)
	vllmCards := profiles.VLLMModelCardsForProfile(cfg.InstanceKey, vllmProfile.Persona.VLLM)
	modified, err := time.Parse(time.RFC3339Nano, ollamaModels[0].ModifiedAt)
	if err != nil || len(vllmCards) != 1 || modified.Unix() != vllmCards[0].Created {
		t.Fatalf("model timestamps drifted: modified=%q cards=%#v err=%v", ollamaModels[0].ModifiedAt, vllmCards, err)
	}
	if ollamaModels[0].Details.Family != "qwen35moe" || len(ollamaModels[0].Details.Families) != 1 || ollamaModels[0].Details.Families[0] != "qwen35moe" {
		t.Fatalf("Qwen Ollama metadata is inconsistent: %#v", ollamaModels[0].Details)
	}

	ollama := &inProcessClient{handler: a.publicHandler(ollamaProfile), cookies: map[string]string{}}
	vllm := &inProcessClient{handler: a.publicHandler(vllmProfile), cookies: map[string]string{}}
	tests := []struct {
		name        string
		client      *inProcessClient
		method      string
		path        string
		body        string
		contentType string
		wantStatus  int
		marker      string
	}{
		{name: "ollama invalid json", client: ollama, method: http.MethodPost, path: "/api/generate", body: "not-json", contentType: "application/json", wantStatus: http.StatusBadRequest, marker: `"error"`},
		{name: "ollama content type", client: ollama, method: http.MethodPost, path: "/api/generate", body: `{ "model": "qwen3.6:35b-a3b", "prompt": "x" }`, contentType: "text/plain", wantStatus: http.StatusBadRequest, marker: `"error"`},
		{name: "ollama empty model", client: ollama, method: http.MethodPost, path: "/api/chat", body: `{ "model": "", "messages": [{"role":"user","content":"x"}] }`, contentType: "application/json", wantStatus: http.StatusBadRequest, marker: `"error"`},
		{name: "ollama stream type", client: ollama, method: http.MethodPost, path: "/api/chat", body: `{ "model": "qwen3.6:35b-a3b", "messages": [{"role":"user","content":"x"}], "stream": "false" }`, contentType: "application/json", wantStatus: http.StatusBadRequest, marker: `"error"`},
		{name: "ollama negative keep alive", client: ollama, method: http.MethodPost, path: "/api/generate", body: `{ "model": "qwen3.6:35b-a3b", "prompt": "x", "keep_alive": "-1s" }`, contentType: "application/json", wantStatus: http.StatusBadRequest, marker: `"error"`},
		{name: "ollama unknown model", client: ollama, method: http.MethodPost, path: "/api/generate", body: `{ "model": "not-installed", "prompt": "x", "stream": false }`, contentType: "application/json", wantStatus: http.StatusNotFound, marker: `"error"`},
		{name: "vllm invalid json", client: vllm, method: http.MethodPost, path: "/v1/chat/completions", body: "not-json", contentType: "application/json", wantStatus: http.StatusUnprocessableEntity, marker: `"detail"`},
		{name: "vllm content type", client: vllm, method: http.MethodPost, path: "/v1/chat/completions", body: `{ "model": "Qwen/Qwen3.6-35B-A3B", "messages": [{"role":"user","content":"x"}] }`, contentType: "text/plain", wantStatus: http.StatusUnsupportedMediaType, marker: `"detail"`},
		{name: "vllm missing model", client: vllm, method: http.MethodPost, path: "/v1/chat/completions", body: `{ "messages": [{"role":"user","content":"x"}] }`, contentType: "application/json", wantStatus: http.StatusUnprocessableEntity, marker: `"detail"`},
		{name: "vllm empty messages", client: vllm, method: http.MethodPost, path: "/v1/chat/completions", body: `{ "model": "Qwen/Qwen3.6-35B-A3B", "messages": [] }`, contentType: "application/json", wantStatus: http.StatusUnprocessableEntity, marker: `"detail"`},
		{name: "vllm stream type", client: vllm, method: http.MethodPost, path: "/v1/chat/completions", body: `{ "model": "Qwen/Qwen3.6-35B-A3B", "messages": [{"role":"user","content":"x"}], "stream": "false" }`, contentType: "application/json", wantStatus: http.StatusUnprocessableEntity, marker: `"detail"`},
		{name: "vllm unknown model", client: vllm, method: http.MethodPost, path: "/v1/chat/completions", body: `{ "model": "not-served", "messages": [{"role":"user","content":"x"}] }`, contentType: "application/json", wantStatus: http.StatusNotFound, marker: `"detail"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp := test.client.do(t, test.method, test.path, strings.NewReader(test.body), test.contentType)
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != test.wantStatus || !strings.Contains(string(body), test.marker) {
				t.Fatalf("status/body mismatch: got=%d want=%d headers=%#v body=%s", resp.StatusCode, test.wantStatus, resp.Header, body)
			}
			if test.client == ollama && resp.Header.Get("Server") == "uvicorn" {
				t.Fatalf("Ollama error exposed vLLM Server header: %#v", resp.Header)
			}
			if test.client == vllm && resp.Header.Get("Server") != "uvicorn" {
				t.Fatalf("vLLM error lost uvicorn Server header: %#v", resp.Header)
			}
		})
	}
	resp := ollama.do(t, http.MethodGet, "/api/generate", nil, "")
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
		t.Fatalf("Ollama method error mismatch: %d allow=%q", resp.StatusCode, resp.Header.Get("Allow"))
	}
	_ = resp.Body.Close()
	resp = vllm.do(t, http.MethodGet, "/v1/chat/completions", nil, "")
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
		t.Fatalf("vLLM method error mismatch: %d allow=%q", resp.StatusCode, resp.Header.Get("Allow"))
	}
	_ = resp.Body.Close()
}

func metricCounter(t *testing.T, body []byte, prefix string) int64 {
	t.Helper()
	for _, line := range nonEmptyLines(body) {
		if strings.HasPrefix(line, prefix) {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				t.Fatalf("invalid metric line: %s", line)
			}
			value, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				t.Fatalf("invalid metric value: %v: %s", err, line)
			}
			return value
		}
	}
	t.Fatalf("metric %q not found in %s", prefix, body)
	return 0
}

func parseSSE(t *testing.T, body []byte) ([]map[string]any, bool) {
	t.Helper()
	var frames []map[string]any
	done := false
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if data == "[DONE]" {
			done = true
			continue
		}
		var frame map[string]any
		if err := json.Unmarshal([]byte(data), &frame); err != nil {
			t.Fatalf("invalid SSE JSON: %v: %s", err, data)
		}
		frames = append(frames, frame)
	}
	return frames, done
}

func choiceMap(t *testing.T, frame map[string]any) map[string]any {
	t.Helper()
	choices, ok := frame["choices"].([]any)
	if !ok || len(choices) == 0 {
		t.Fatalf("SSE frame has no choice: %#v", frame)
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		t.Fatalf("SSE choice has wrong shape: %#v", frame)
	}
	return choice
}

func nonEmptyLines(body []byte) []string {
	var result []string
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}
