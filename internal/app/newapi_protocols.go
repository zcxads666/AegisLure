package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
)

// newAPIModelListFormat follows the format selection in New API's relay
// router. The same /v1/models path can present OpenAI or Anthropic cards,
// while Gemini has its own /v1beta/models path.
func newAPIModelListFormat(r *http.Request) string {
	if r.URL.Path == "/v1beta/models" {
		return "gemini"
	}
	if (r.URL.Path == "/v1/models" || strings.HasPrefix(r.URL.Path, "/v1/models/")) && r.Header.Get("x-api-key") != "" && r.Header.Get("anthropic-version") != "" {
		return "anthropic"
	}
	if r.URL.Path == "/v1/models" && (r.Header.Get("x-goog-api-key") != "" || r.URL.Query().Get("key") != "") {
		return "gemini"
	}
	return "openai"
}

func newAPIRequestedModel(r *http.Request, body []byte, route string) string {
	switch route {
	case "gemini.generate", "gemini.stream":
		if value, ok := newAPIGeminiModelFromPath(r.URL.Path); ok {
			return value
		}
		return ""
	default:
		value, ok := decodeJSONObject(body)
		if !ok {
			return ""
		}
		return strings.TrimSpace(stringValue(value["model"]))
	}
}

func newAPIOpenAIModelFromPath(path string) (string, bool) {
	const prefix = "/v1/models/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	raw := strings.TrimPrefix(path, prefix)
	if raw == "" || strings.Contains(raw, "/") {
		return "", false
	}
	value, err := url.PathUnescape(raw)
	if err != nil || value == "" || strings.ContainsAny(value, "/\\\r\n") || len([]rune(value)) > 256 {
		return "", false
	}
	return value, true
}

func newAPIGeminiModelFromPath(path string) (string, bool) {
	const prefix = "/v1beta/models/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	raw := strings.TrimPrefix(path, prefix)
	for _, action := range []string{":streamGenerateContent", ":generateContent"} {
		if strings.HasSuffix(raw, action) {
			raw = strings.TrimSuffix(raw, action)
			break
		}
	}
	if raw == "" || strings.Contains(raw, "/") {
		return "", false
	}
	value, err := url.PathUnescape(raw)
	if err != nil || value == "" || strings.ContainsAny(value, "/\\\r\n") || len([]rune(value)) > 256 {
		return "", false
	}
	return value, true
}

func (a *App) newAPIHoneyAuth(r *http.Request, route string) (model.HoneyToken, string) {
	value := ""
	if route == "gemini.generate" || route == "gemini.stream" {
		value = strings.TrimSpace(r.Header.Get("x-goog-api-key"))
		if value == "" {
			value = strings.TrimSpace(r.URL.Query().Get("key"))
		}
	}
	if value == "" {
		value = a.bearer(r)
	}
	if value == "" {
		return model.HoneyToken{}, "missing"
	}
	hash := security.Fingerprint(a.cfg.InstanceKey, value)
	token, ok := a.store.FindToken(hash)
	if !ok {
		return model.HoneyToken{}, "invalid"
	}
	return token, "valid_honey_key"
}

func (a *App) writeNewAPIProtocolError(w *captureWriter, route string, status int, message, errorType string) {
	if errorType == "" {
		errorType = "invalid_request_error"
	}
	switch route {
	case "anthropic.messages":
		a.writeJSON(w, status, map[string]any{"type": "error", "error": map[string]string{"type": errorType, "message": message}})
	case "gemini.generate", "gemini.stream":
		statusName := "INVALID_ARGUMENT"
		switch status {
		case http.StatusUnauthorized:
			statusName = "UNAUTHENTICATED"
		case http.StatusForbidden:
			statusName = "PERMISSION_DENIED"
		case http.StatusNotFound:
			statusName = "NOT_FOUND"
		case http.StatusPaymentRequired:
			statusName = "RESOURCE_EXHAUSTED"
		}
		a.writeJSON(w, status, map[string]any{"error": map[string]any{"code": status, "message": message, "status": statusName}})
	default:
		a.writeJSON(w, status, map[string]any{"error": map[string]string{"message": message, "type": errorType}})
	}
}

func validateNewAPIAnthropicInvocation(r *http.Request, body []byte) string {
	if strings.TrimSpace(r.Header.Get("anthropic-version")) == "" || !jsonContentTypeOK(r) {
		return "invalid_request"
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return "invalid_request"
	}
	modelName, ok := value["model"].(string)
	if !ok || strings.TrimSpace(modelName) == "" || len([]rune(modelName)) > 256 {
		return "invalid_request"
	}
	rawMessages, ok := value["messages"]
	if !ok {
		return "invalid_request"
	}
	messages, ok := rawMessages.([]any)
	if !ok || len(messages) == 0 || len(messages) > 128 {
		return "invalid_request"
	}
	for _, rawMessage := range messages {
		message, ok := rawMessage.(map[string]any)
		if !ok {
			return "invalid_request"
		}
		role, ok := message["role"].(string)
		if !ok || (role != "user" && role != "assistant") {
			return "invalid_request"
		}
		content, ok := message["content"]
		if !ok || !stringValueOrParts(content) {
			return "invalid_request"
		}
	}
	rawMaxTokens, ok := value["max_tokens"]
	if !ok {
		return "invalid_request"
	}
	if newAPIIntegerOverflow(rawMaxTokens, 1_000_000) {
		return "quota_overflow"
	}
	if maxTokens, ok := boundedNewAPIInteger(rawMaxTokens, 1_000_000); !ok || maxTokens < 1 {
		return "invalid_request"
	}
	if rawStream, exists := value["stream"]; exists {
		if _, ok := rawStream.(bool); !ok {
			return "invalid_request"
		}
	}
	if rawTemperature, exists := value["temperature"]; exists && !numberValue(rawTemperature) {
		return "invalid_request"
	}
	return ""
}

func validateNewAPIGeminiInvocation(r *http.Request, body []byte) string {
	if !jsonContentTypeOK(r) {
		return "invalid_request"
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return "invalid_request"
	}
	rawContents, ok := value["contents"]
	if !ok {
		return "invalid_request"
	}
	contents, ok := rawContents.([]any)
	if !ok || len(contents) == 0 || len(contents) > 128 {
		return "invalid_request"
	}
	for _, rawContent := range contents {
		content, ok := rawContent.(map[string]any)
		if !ok {
			return "invalid_request"
		}
		rawParts, ok := content["parts"]
		if !ok {
			return "invalid_request"
		}
		parts, ok := rawParts.([]any)
		if !ok || len(parts) == 0 || len(parts) > 128 {
			return "invalid_request"
		}
		for _, rawPart := range parts {
			part, ok := rawPart.(map[string]any)
			if !ok || len(part) == 0 {
				return "invalid_request"
			}
			if text, exists := part["text"]; exists {
				if _, ok := text.(string); !ok {
					return "invalid_request"
				}
			}
		}
	}
	if rawConfig, exists := value["generationConfig"]; exists {
		config, ok := rawConfig.(map[string]any)
		if !ok {
			return "invalid_request"
		}
		if rawMaxTokens, exists := config["maxOutputTokens"]; exists {
			if newAPIIntegerOverflow(rawMaxTokens, 1_000_000) {
				return "quota_overflow"
			}
			if maxTokens, ok := boundedNewAPIInteger(rawMaxTokens, 1_000_000); !ok || maxTokens < 1 {
				return "invalid_request"
			}
		}
	}
	return ""
}

func prepareNewAPIResponse(body []byte, obs *Observation) string {
	text := syntheticText(body, model.ProductNewAPI)
	annotateSyntheticResponse(obs, text)
	inputTokens := maxInt(8, len(body)/4)
	outputTokens := maxInt(6, len(text)/4)
	setInvocationMeasurements(obs, inputTokens, outputTokens, "synthetic_accepted")
	addLivenessMetadata(body, obs)
	return text
}

func (a *App) writeAnthropicResponse(w *captureWriter, body []byte, stream bool, obs *Observation, modelName string) {
	text := prepareNewAPIResponse(body, obs)
	inputTokens, outputTokens := obs.SimulatedInputTokens, obs.SimulatedOutputTokens
	messageID := "msg_" + obs.InvocationID
	if !stream {
		a.writeJSON(w, http.StatusOK, map[string]any{
			"id":            messageID,
			"type":          "message",
			"role":          "assistant",
			"content":       []any{map[string]any{"type": "text", "text": text}},
			"model":         modelName,
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
			"usage":         map[string]int{"input_tokens": inputTokens, "output_tokens": outputTokens},
		})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	writeNewAPINamedSSE(w, "message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": messageID, "type": "message", "role": "assistant", "model": modelName,
			"content": []any{}, "stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]int{"input_tokens": inputTokens, "output_tokens": 0},
		},
	})
	writeNewAPINamedSSE(w, "content_block_start", map[string]any{
		"type": "content_block_start", "index": 0, "content_block": map[string]string{"type": "text", "text": ""},
	})
	writeNewAPINamedSSE(w, "ping", map[string]string{"type": "ping"})
	for _, chunk := range textChunks(text) {
		writeNewAPINamedSSE(w, "content_block_delta", map[string]any{
			"type": "content_block_delta", "index": 0, "delta": map[string]string{"type": "text_delta", "text": chunk},
		})
	}
	writeNewAPINamedSSE(w, "content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	writeNewAPINamedSSE(w, "message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]int{"output_tokens": outputTokens},
	})
	writeNewAPINamedSSE(w, "message_stop", map[string]string{"type": "message_stop"})
	obs.ExecutionOutcome = "synthetic_stream_completed"
}

func (a *App) writeGeminiResponse(w *captureWriter, body []byte, stream bool, obs *Observation, modelName string) {
	text := prepareNewAPIResponse(body, obs)
	inputTokens, outputTokens := obs.SimulatedInputTokens, obs.SimulatedOutputTokens
	if !stream {
		a.writeJSON(w, http.StatusOK, newGeminiResponse(modelName, text, inputTokens, outputTokens, true))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	chunks := textChunks(text)
	for index, chunk := range chunks {
		writeSSE(w, newGeminiResponse(modelName, chunk, inputTokens, outputTokens, index == len(chunks)-1))
	}
	obs.ExecutionOutcome = "synthetic_stream_completed"
}

func newGeminiResponse(modelName, text string, inputTokens, outputTokens int, final bool) map[string]any {
	candidate := map[string]any{
		"content": map[string]any{"role": "model", "parts": []any{map[string]string{"text": text}}},
		"index":   0,
	}
	if final {
		candidate["finishReason"] = "STOP"
	}
	return map[string]any{
		"candidates": []any{candidate},
		"usageMetadata": map[string]int{
			"promptTokenCount":     inputTokens,
			"candidatesTokenCount": outputTokens,
			"totalTokenCount":      inputTokens + outputTokens,
		},
		"modelVersion": modelName,
	}
}

func writeNewAPINamedSSE(w *captureWriter, event string, payload any) {
	encoded, _ := json.Marshal(payload)
	_, _ = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, encoded)
	w.Flush()
}

func newAPIAnthropicModelList(seed string, catalog []profiles.CatalogEntry) map[string]any {
	cards := profiles.OpenAIModelCardsForCatalog(seed, catalog, "new-api")
	data := make([]map[string]any, 0, len(cards))
	firstID, lastID := "", ""
	for _, card := range cards {
		if firstID == "" {
			firstID = card.ID
		}
		lastID = card.ID
		entry, _ := profiles.ResolveModel(model.ProductNewAPI, card.ID)
		displayName := entry.DisplayName
		if displayName == "" {
			displayName = card.ID
		}
		data = append(data, map[string]any{
			"id": card.ID, "created_at": time.Unix(card.Created, 0).UTC().Format(time.RFC3339), "display_name": displayName, "type": "model",
		})
	}
	return map[string]any{"data": data, "first_id": firstID, "has_more": false, "last_id": lastID}
}

func newAPIGeminiModelList(catalog []profiles.CatalogEntry) map[string]any {
	data := make([]map[string]any, 0, len(catalog))
	for _, entry := range catalog {
		if entry.ID == "" {
			continue
		}
		displayName := entry.DisplayName
		if displayName == "" {
			displayName = entry.ID
		}
		data = append(data, map[string]any{"name": entry.ID, "displayName": displayName, "supportedGenerationMethods": []string{"generateContent"}})
	}
	return map[string]any{"models": data, "nextPageToken": nil}
}
