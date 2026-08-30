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
// uses the local model name and its response IDs/metadata are kept separate.
func (a *App) writeOllamaOpenAIResponse(w *captureWriter, body []byte, route string, stream bool, obs *Observation, publicModel string) {
	text := personaResponseText(body, model.ProductOllama)
	inputTokens := maxInt(8, len(body)/4)
	outputTokens := maxInt(6, len(text)/4)
	obs.ExecutionOutcome = "synthetic_accepted"
	obs.SimulatedInputTokens = inputTokens
	obs.SimulatedOutputTokens = outputTokens
	obs.SimulatedCost = int64(inputTokens + outputTokens)
	if ruleID := livenessRuleID(body); ruleID != "" {
		obs.MatchedRuleIDs = append(obs.MatchedRuleIDs, ruleID)
		if obs.Metadata == nil {
			obs.Metadata = map[string]string{}
		}
		obs.Metadata["matched_liveness_rule"] = ruleID
	}

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
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		chunks := []string{"The request was ", "processed successfully."}
		for index, chunk := range chunks {
			payload := map[string]any{
				"id":      "chatcmpl-" + obs.InvocationID,
				"object":  "chat.completion.chunk",
				"created": time.Now().Unix(),
				"model":   publicModel,
				"choices": []any{map[string]any{
					"index": 0,
					"delta": map[string]string{"content": chunk},
				}},
			}
			if index == len(chunks)-1 {
				payload["choices"] = []any{map[string]any{
					"index":         0,
					"delta":         map[string]string{},
					"finish_reason": "stop",
				}}
			}
			encoded, _ := json.Marshal(payload)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", encoded)
			if flusher, ok := any(w).(http.Flusher); ok {
				flusher.Flush()
			}
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
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

// writeVLLMResponse renders the OpenAI-compatible vLLM surface. Model IDs
// remain the served Hugging Face-style IDs and the model permission metadata
// is kept out of invocation responses.
func (a *App) writeVLLMResponse(w *captureWriter, body []byte, route string, stream bool, obs *Observation, modelName string) {
	text := personaResponseText(body, model.ProductVLLM)
	inputTokens := maxInt(8, len(body)/4)
	outputTokens := maxInt(6, len(text)/4)
	obs.ExecutionOutcome = "synthetic_accepted"
	obs.SimulatedInputTokens = inputTokens
	obs.SimulatedOutputTokens = outputTokens
	obs.SimulatedCost = int64(inputTokens + outputTokens)
	if ruleID := livenessRuleID(body); ruleID != "" {
		obs.MatchedRuleIDs = append(obs.MatchedRuleIDs, ruleID)
		if obs.Metadata == nil {
			obs.Metadata = map[string]string{}
		}
		obs.Metadata["matched_liveness_rule"] = ruleID
	}

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
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		chunks := []string{"The request was ", "completed successfully."}
		for index, chunk := range chunks {
			payload := map[string]any{
				"id":                 "chatcmpl-" + obs.InvocationID,
				"object":             "chat.completion.chunk",
				"created":            time.Now().Unix(),
				"model":              modelName,
				"system_fingerprint": "fp_" + strings.ToLower(obs.InvocationID),
				"choices": []any{map[string]any{
					"index":         0,
					"delta":         map[string]string{"role": "assistant", "content": chunk},
					"finish_reason": nil,
				}},
			}
			if index == len(chunks)-1 {
				payload["choices"] = []any{map[string]any{
					"index":         0,
					"delta":         map[string]string{},
					"finish_reason": "stop",
				}}
			}
			encoded, _ := json.Marshal(payload)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", encoded)
			if flusher, ok := any(w).(http.Flusher); ok {
				flusher.Flush()
			}
		}
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
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

func livenessRuleID(body []byte) string {
	lower := strings.ToLower(string(body))
	switch {
	case strings.Contains(lower, "reply with ok"):
		return "reply-ok-v1"
	case strings.Contains(lower, "respond with ok"):
		return "reply-ok-v1"
	case strings.Contains(lower, "what model"):
		return "model-probe-v1"
	default:
		return ""
	}
}

func (a *App) vllmMetrics() string {
	models := profiles.VLLMModelCards(a.cfg.InstanceKey)
	var b strings.Builder
	b.WriteString("# HELP vllm:num_requests_running Number of requests currently running.\n")
	b.WriteString("# TYPE vllm:num_requests_running gauge\n")
	for _, item := range models {
		fmt.Fprintf(&b, "vllm:num_requests_running{model_name=%s} 0\n", prometheusLabel(item.ID))
	}
	b.WriteString("# HELP vllm:num_requests_waiting Number of requests waiting to be processed.\n")
	b.WriteString("# TYPE vllm:num_requests_waiting gauge\n")
	for _, item := range models {
		fmt.Fprintf(&b, "vllm:num_requests_waiting{model_name=%s} 0\n", prometheusLabel(item.ID))
	}
	b.WriteString("# HELP vllm:kv_cache_usage_perc Fraction of KV cache currently in use.\n")
	b.WriteString("# TYPE vllm:kv_cache_usage_perc gauge\n")
	for _, item := range models {
		fmt.Fprintf(&b, "vllm:kv_cache_usage_perc{model_name=%s} 0\n", prometheusLabel(item.ID))
	}
	b.WriteString("# HELP vllm:prompt_tokens_total Number of prompt tokens processed.\n")
	b.WriteString("# TYPE vllm:prompt_tokens_total counter\n")
	b.WriteString("# HELP vllm:generation_tokens_total Number of generated tokens.\n")
	b.WriteString("# TYPE vllm:generation_tokens_total counter\n")
	b.WriteString("# HELP vllm:request_success_total Number of requests completed successfully.\n")
	b.WriteString("# TYPE vllm:request_success_total counter\n")
	for _, item := range models {
		counters := a.personaCounters(model.ProductVLLM, item.ID)
		label := prometheusLabel(item.ID)
		fmt.Fprintf(&b, "vllm:prompt_tokens_total{model_name=%s} %d\n", label, counters.PromptTokens)
		fmt.Fprintf(&b, "vllm:generation_tokens_total{model_name=%s} %d\n", label, counters.GenerationTokens)
		fmt.Fprintf(&b, "vllm:request_success_total{finished_reason=\"stop\",model_name=%s} %d\n", label, counters.Successes)
	}
	b.WriteString("# HELP vllm:cache_config_info Current cache configuration.\n")
	b.WriteString("# TYPE vllm:cache_config_info gauge\n")
	b.WriteString("vllm:cache_config_info{block_size=\"16\",cache_dtype=\"auto\",enable_prefix_caching=\"false\",gpu_memory_utilization=\"0.90\"} 1\n")
	return b.String()
}

func prometheusLabel(value string) string {
	return strconv.Quote(value)
}
