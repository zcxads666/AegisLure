package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
)

// writeOllamaOpenAIResponse renders the compatibility surface Ollama exposes
// for OpenAI clients. It deliberately does not use the vLLM renderer: Ollama
// uses local model names and keeps its own response identity separate.
func (a *App) writeOllamaOpenAIResponse(w *captureWriter, body []byte, route string, stream bool, obs *Observation, publicModel string) {
	text := personaResponseText(body, model.ProductOllama)
	inputTokens := maxInt(8, len(body)/4)
	outputTokens := maxInt(6, len(text)/4)
	setInvocationMeasurements(obs, inputTokens, outputTokens, "synthetic_accepted")
	addLivenessMetadata(body, obs)

	if route == "openai.embeddings" {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"object": "list",
			"data": []any{map[string]any{
				"object":    "embedding",
				"embedding": []float64{0.0123, -0.0456, 0.0789},
				"index":     0,
			}},
			"model": publicModel,
			"usage": map[string]int{"prompt_tokens": inputTokens, "total_tokens": inputTokens},
		})
		return
	}

	if stream {
		writeOpenAIStream(w, route, "chatcmpl-"+obs.InvocationID, publicModel, text, false)
		obs.ExecutionOutcome = "synthetic_stream_completed"
		return
	}

	created := time.Now().Unix()
	if route == "openai.completions" {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"id":      "cmpl-" + obs.InvocationID,
			"object":  "text_completion",
			"created": created,
			"model":   publicModel,
			"choices": []any{map[string]any{"text": text, "index": 0, "finish_reason": "stop"}},
			"usage":   map[string]int{"prompt_tokens": inputTokens, "completion_tokens": outputTokens, "total_tokens": inputTokens + outputTokens},
		})
		return
	}
	if route == "openai.responses" {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"id":          "resp_" + obs.InvocationID,
			"object":      "response",
			"created_at":  created,
			"model":       publicModel,
			"status":      "completed",
			"output_text": text,
			"output":      []any{map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": text}}}},
			"usage":       map[string]int{"input_tokens": inputTokens, "output_tokens": outputTokens, "total_tokens": inputTokens + outputTokens},
		})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"id":      "chatcmpl-" + obs.InvocationID,
		"object":  "chat.completion",
		"created": created,
		"model":   publicModel,
		"choices": []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": text}, "finish_reason": "stop"}},
		"usage":   map[string]int{"prompt_tokens": inputTokens, "completion_tokens": outputTokens, "total_tokens": inputTokens + outputTokens},
	})
}

// writeVLLMResponse renders one OpenAI-compatible vLLM response. The caller
// has already resolved aliases to vLLM's first served model name, so the same
// name appears in the response and the metrics label.
func (a *App) writeVLLMResponse(w *captureWriter, body []byte, route string, stream bool, obs *Observation, modelName string) {
	text := personaResponseText(body, model.ProductVLLM)
	inputTokens := maxInt(8, len(body)/4)
	outputTokens := maxInt(6, len(text)/4)
	setInvocationMeasurements(obs, inputTokens, outputTokens, "synthetic_accepted")
	addLivenessMetadata(body, obs)

	if route == "openai.embeddings" {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"object": "list",
			"data": []any{map[string]any{
				"object":    "embedding",
				"embedding": []float64{0.0211, -0.0332, 0.0644},
				"index":     0,
			}},
			"model": modelName,
			"usage": map[string]int{"prompt_tokens": inputTokens, "total_tokens": inputTokens},
		})
		return
	}

	if stream {
		writeOpenAIStream(w, route, "chatcmpl-"+obs.InvocationID, modelName, text, true)
		obs.ExecutionOutcome = "synthetic_stream_completed"
		return
	}

	created := time.Now().Unix()
	if route == "openai.completions" {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"id":      "cmpl-" + obs.InvocationID,
			"object":  "text_completion",
			"created": created,
			"model":   modelName,
			"choices": []any{map[string]any{"index": 0, "text": text, "logprobs": nil, "finish_reason": "stop"}},
			"usage":   map[string]int{"prompt_tokens": inputTokens, "completion_tokens": outputTokens, "total_tokens": inputTokens + outputTokens},
		})
		return
	}
	if route == "openai.responses" {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"id":         "resp_" + obs.InvocationID,
			"object":     "response",
			"created_at": created,
			"model":      modelName,
			"status":     "completed",
			"output":     []any{map[string]any{"type": "message", "id": "msg_" + obs.InvocationID, "status": "completed", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}}}},
			"usage":      map[string]int{"input_tokens": inputTokens, "output_tokens": outputTokens, "total_tokens": inputTokens + outputTokens},
		})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"id":                 "chatcmpl-" + obs.InvocationID,
		"object":             "chat.completion",
		"created":            created,
		"model":              modelName,
		"system_fingerprint": "fp_" + strings.ToLower(obs.InvocationID),
		"choices":            []any{map[string]any{"index": 0, "message": map[string]string{"role": "assistant", "content": text}, "logprobs": nil, "finish_reason": "stop"}},
		"usage":              map[string]int{"prompt_tokens": inputTokens, "completion_tokens": outputTokens, "total_tokens": inputTokens + outputTokens},
	})
}

func setInvocationMeasurements(obs *Observation, inputTokens, outputTokens int, outcome string) {
	obs.ExecutionOutcome = outcome
	obs.SimulatedInputTokens = inputTokens
	obs.SimulatedOutputTokens = outputTokens
	obs.SimulatedCost = int64(inputTokens + outputTokens)
	obs.ResponseObserved = true
}

func addLivenessMetadata(body []byte, obs *Observation) {
	if ruleID := livenessRuleID(body); ruleID != "" {
		obs.MatchedRuleIDs = append(obs.MatchedRuleIDs, ruleID)
		if obs.Metadata == nil {
			obs.Metadata = map[string]string{}
		}
		obs.Metadata["matched_liveness_rule"] = ruleID
	}
}

func writeOpenAIStream(w *captureWriter, route, id, modelName, text string, includeSystemFingerprint bool) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	created := time.Now().Unix()
	fingerprint := ""
	if includeSystemFingerprint {
		fingerprint = "fp_" + strings.ToLower(id)
	}
	if route == "openai.completions" {
		for _, chunk := range textChunks(text) {
			payload := map[string]any{
				"id": id, "object": "text_completion", "created": created, "model": modelName,
				"choices": []any{map[string]any{"index": 0, "text": chunk, "finish_reason": nil}},
			}
			writeSSE(w, payload)
		}
		writeSSE(w, map[string]any{
			"id": id, "object": "text_completion", "created": created, "model": modelName,
			"choices": []any{map[string]any{"index": 0, "text": "", "finish_reason": "stop"}},
		})
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		w.Flush()
		return
	}
	if route == "openai.responses" {
		for _, chunk := range textChunks(text) {
			writeSSE(w, map[string]any{"id": id, "object": "response.output_text.delta", "created": created, "model": modelName, "delta": chunk})
		}
		writeSSE(w, map[string]any{"id": id, "object": "response.completed", "created": created, "model": modelName})
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		w.Flush()
		return
	}
	first := map[string]any{
		"id": id, "object": "chat.completion.chunk", "created": created, "model": modelName,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]string{"role": "assistant"}, "finish_reason": nil}},
	}
	if fingerprint != "" {
		first["system_fingerprint"] = fingerprint
	}
	writeSSE(w, first)
	for _, chunk := range textChunks(text) {
		payload := map[string]any{
			"id": id, "object": "chat.completion.chunk", "created": created, "model": modelName,
			"choices": []any{map[string]any{"index": 0, "delta": map[string]string{"content": chunk}, "finish_reason": nil}},
		}
		if fingerprint != "" {
			payload["system_fingerprint"] = fingerprint
		}
		writeSSE(w, payload)
	}
	final := map[string]any{
		"id": id, "object": "chat.completion.chunk", "created": created, "model": modelName,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]string{}, "finish_reason": "stop"}},
	}
	if fingerprint != "" {
		final["system_fingerprint"] = fingerprint
	}
	writeSSE(w, final)
	_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	w.Flush()
}

func writeSSE(w *captureWriter, payload map[string]any) {
	encoded, _ := json.Marshal(payload)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", encoded)
	w.Flush()
}

func textChunks(text string) []string {
	if text == "" {
		return []string{""}
	}
	if len([]rune(text)) <= 12 {
		return []string{text}
	}
	runes := []rune(text)
	middle := len(runes) / 2
	return []string{string(runes[:middle]), string(runes[middle:])}
}

// writeOllamaStream uses Ollama's native JSON Lines protocol. Chat streams
// carry message objects; generate streams carry response strings. There is no
// OpenAI data: [DONE] sentinel on this surface.
func (a *App) writeOllamaStream(w *captureWriter, route, modelName, text string, promptTokens, outputTokens int, obs *Observation, doneReason string) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	created := time.Now().UTC().Format(time.RFC3339Nano)
	if doneReason == "" {
		doneReason = "stop"
	}
	for _, chunk := range textChunks(text) {
		payload := map[string]any{"model": modelName, "created_at": created, "done": false}
		if route == "ollama.chat" {
			payload["message"] = map[string]string{"role": "assistant", "content": chunk}
		} else {
			payload["response"] = chunk
		}
		_ = json.NewEncoder(w).Encode(payload)
		w.Flush()
	}
	final := map[string]any{
		"model":                modelName,
		"created_at":           created,
		"done":                 true,
		"done_reason":          doneReason,
		"total_duration":       int64(28_000_000),
		"load_duration":        int64(4_000_000),
		"prompt_eval_count":    promptTokens,
		"prompt_eval_duration": int64(3_000_000),
		"eval_count":           outputTokens,
		"eval_duration":        int64(21_000_000),
	}
	if route == "ollama.chat" {
		final["message"] = map[string]string{"role": "assistant", "content": ""}
	} else {
		final["response"] = ""
	}
	_ = json.NewEncoder(w).Encode(final)
	w.Flush()
	obs.ExecutionOutcome = "synthetic_stream_completed"
}

func livenessRuleID(body []byte) string {
	lower := strings.ToLower(string(body))
	switch {
	case strings.Contains(lower, "reply with ok"), strings.Contains(lower, "respond with ok"):
		return "reply-ok-v1"
	case strings.Contains(lower, "what model"):
		return "model-probe-v1"
	default:
		return ""
	}
}

func (a *App) vllmMetrics(profile profiles.Profile) string {
	persona := profile.Persona.VLLM
	modelName := persona.MetricsModelName()
	state, _ := a.vllmRuntimeSnapshot(modelName)
	label := prometheusLabel(modelName)
	var b strings.Builder
	b.WriteString("# HELP vllm:num_requests_running Number of requests currently running.\n")
	b.WriteString("# TYPE vllm:num_requests_running gauge\n")
	fmt.Fprintf(&b, "vllm:num_requests_running{model_name=%s} %d\n", label, state.RequestsRunning)
	b.WriteString("# HELP vllm:num_requests_waiting Number of requests waiting to be processed.\n")
	b.WriteString("# TYPE vllm:num_requests_waiting gauge\n")
	fmt.Fprintf(&b, "vllm:num_requests_waiting{model_name=%s} %d\n", label, state.RequestsWaiting)
	b.WriteString("# HELP vllm:kv_cache_usage_perc Fraction of KV cache currently in use.\n")
	b.WriteString("# TYPE vllm:kv_cache_usage_perc gauge\n")
	fmt.Fprintf(&b, "vllm:kv_cache_usage_perc{model_name=%s} %.6f\n", label, state.KVCacheUsage)
	b.WriteString("# HELP vllm:prompt_tokens_total Number of prompt tokens processed.\n")
	b.WriteString("# TYPE vllm:prompt_tokens_total counter\n")
	fmt.Fprintf(&b, "vllm:prompt_tokens_total{model_name=%s} %d\n", label, state.PromptTokensTotal)
	b.WriteString("# HELP vllm:generation_tokens_total Number of generated tokens.\n")
	b.WriteString("# TYPE vllm:generation_tokens_total counter\n")
	fmt.Fprintf(&b, "vllm:generation_tokens_total{model_name=%s} %d\n", label, state.GenerationTokensTotal)
	b.WriteString("# HELP vllm:request_success_total Number of requests completed successfully.\n")
	b.WriteString("# TYPE vllm:request_success_total counter\n")
	fmt.Fprintf(&b, "vllm:request_success_total{finished_reason=\"stop\",model_name=%s} %d\n", label, state.RequestSuccessTotal)
	b.WriteString("# HELP vllm:request_error_total Number of requests that failed before completion.\n")
	b.WriteString("# TYPE vllm:request_error_total counter\n")
	fmt.Fprintf(&b, "vllm:request_error_total{model_name=%s} %d\n", label, state.RequestErrorTotal)
	// This is a process-level cache configuration metric in vLLM, so it has no
	// model_name label. Keep it stable for the lifetime of this persona.
	b.WriteString("# HELP vllm:cache_config_info Current cache configuration.\n")
	b.WriteString("# TYPE vllm:cache_config_info gauge\n")
	b.WriteString("vllm:cache_config_info{block_size=\"16\",cache_dtype=\"auto\",enable_prefix_caching=\"false\",gpu_memory_utilization=\"0.90\"} 1\n")
	return b.String()
}

func prometheusLabel(value string) string {
	return strconv.Quote(value)
}
