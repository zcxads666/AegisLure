package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type vLLMValidationError struct {
	Status int
	Detail any
}

type ollamaValidationError struct {
	Status  int
	Message string
}

func jsonContentTypeOK(r *http.Request) bool {
	value := strings.TrimSpace(r.Header.Get("Content-Type"))
	if value == "" {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(strings.SplitN(value, ";", 2)[0]), "application/json")
}

func vllmFieldError(path []string, typ, message string) *vLLMValidationError {
	location := append([]string{"body"}, path...)
	return &vLLMValidationError{
		Status: http.StatusUnprocessableEntity,
		Detail: []any{map[string]any{
			"type": typ,
			"loc":  location,
			"msg":  message,
		}},
	}
}

func vllmJSONError() *vLLMValidationError {
	return &vLLMValidationError{
		Status: http.StatusUnprocessableEntity,
		Detail: []any{map[string]any{
			"type": "json_invalid",
			"loc":  []string{"body"},
			"msg":  "JSON decode error",
		}},
	}
}

func validateVLLMRequest(r *http.Request, body []byte, route string) (map[string]any, *vLLMValidationError) {
	if !jsonContentTypeOK(r) {
		return nil, &vLLMValidationError{Status: http.StatusUnsupportedMediaType, Detail: "Unsupported Media Type"}
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return nil, vllmJSONError()
	}
	modelName, ok := value["model"].(string)
	if !ok || strings.TrimSpace(modelName) == "" {
		return nil, vllmFieldError([]string{"model"}, "missing", "Field required")
	}
	if len([]rune(modelName)) > 256 {
		return nil, vllmFieldError([]string{"model"}, "string_too_long", "String should have at most 256 characters")
	}
	if raw, exists := value["stream"]; exists {
		if _, ok := raw.(bool); !ok {
			return nil, vllmFieldError([]string{"stream"}, "bool_type", "Input should be a valid boolean")
		}
	}
	if raw, exists := value["temperature"]; exists && !numberValue(raw) {
		return nil, vllmFieldError([]string{"temperature"}, "float_type", "Input should be a valid number")
	}
	for _, field := range []string{"max_tokens", "max_completion_tokens", "n"} {
		if raw, exists := value[field]; exists {
			number, ok := integerValue(raw)
			if !ok || number < 1 {
				return nil, vllmFieldError([]string{field}, "int_type", "Input should be a valid integer")
			}
		}
	}
	switch route {
	case "openai.chat.completions":
		if err := validateChatMessages(value); err != nil {
			return nil, err
		}
	case "openai.completions", "vllm.invocations":
		if raw, exists := value["prompt"]; exists {
			if !stringOrStringArray(raw) {
				return nil, vllmFieldError([]string{"prompt"}, "string_type", "Input should be a valid string or list of strings")
			}
		} else if route == "openai.completions" {
			return nil, vllmFieldError([]string{"prompt"}, "missing", "Field required")
		}
	case "openai.embeddings":
		if raw, exists := value["input"]; !exists {
			return nil, vllmFieldError([]string{"input"}, "missing", "Field required")
		} else if !stringOrStringArray(raw) {
			return nil, vllmFieldError([]string{"input"}, "string_type", "Input should be a valid string or list of strings")
		}
	case "openai.responses":
		if raw, exists := value["input"]; !exists {
			return nil, vllmFieldError([]string{"input"}, "missing", "Field required")
		} else if !stringOrStringArray(raw) && !messagesLikeArray(raw) {
			return nil, vllmFieldError([]string{"input"}, "string_type", "Input should be a valid input value")
		}
	}
	return value, nil
}

func validateChatMessages(value map[string]any) *vLLMValidationError {
	raw, exists := value["messages"]
	if !exists {
		return vllmFieldError([]string{"messages"}, "missing", "Field required")
	}
	messages, ok := raw.([]any)
	if !ok {
		return vllmFieldError([]string{"messages"}, "list_type", "Input should be a valid list")
	}
	if len(messages) == 0 {
		return vllmFieldError([]string{"messages"}, "too_short", "List should have at least 1 item after validation")
	}
	for index, rawMessage := range messages {
		message, ok := rawMessage.(map[string]any)
		if !ok {
			return vllmFieldError([]string{"messages", strconv.Itoa(index)}, "dict_type", "Input should be a valid dictionary")
		}
		role, ok := message["role"].(string)
		if !ok || strings.TrimSpace(role) == "" {
			return vllmFieldError([]string{"messages", strconv.Itoa(index), "role"}, "missing", "Field required")
		}
		if content, exists := message["content"]; exists && !stringValueOrParts(content) {
			return vllmFieldError([]string{"messages", strconv.Itoa(index), "content"}, "string_type", "Input should be a valid string or list")
		}
	}
	return nil
}

func stringOrStringArray(value any) bool {
	if _, ok := value.(string); ok {
		return true
	}
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if _, ok := item.(string); !ok {
			return false
		}
	}
	return true
}

func stringValueOrParts(value any) bool {
	if _, ok := value.(string); ok {
		return true
	}
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		part, ok := item.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := part["type"].(string); !ok {
			return false
		}
	}
	return true
}

func messagesLikeArray(value any) bool {
	items, ok := value.([]any)
	if !ok {
		return false
	}
	for _, item := range items {
		if _, ok := item.(map[string]any); !ok {
			return false
		}
	}
	return true
}

func numberValue(value any) bool {
	switch value.(type) {
	case float64, float32, int, int64, json.Number:
		return true
	default:
		return false
	}
}

func integerValue(value any) (int64, bool) {
	switch number := value.(type) {
	case float64:
		return int64(number), number == float64(int64(number))
	case float32:
		return int64(number), number == float32(int64(number))
	case int:
		return int64(number), true
	case int64:
		return number, true
	case json.Number:
		result, err := number.Int64()
		return result, err == nil
	default:
		return 0, false
	}
}

type ollamaRequest struct {
	Value     map[string]any
	Model     string
	Stream    bool
	KeepAlive time.Duration
	Unload    bool
}

func validateOllamaRequest(r *http.Request, body []byte, route string, defaultKeepAlive time.Duration) (ollamaRequest, *ollamaValidationError) {
	if !jsonContentTypeOK(r) {
		return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "invalid request"}
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "invalid request"}
	}
	modelName, ok := value["model"].(string)
	if !ok || strings.TrimSpace(modelName) == "" {
		return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "model is required"}
	}
	if len([]rune(modelName)) > 256 {
		return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "model name is too long"}
	}
	stream := true
	if raw, exists := value["stream"]; exists {
		var streamOK bool
		stream, streamOK = raw.(bool)
		if !streamOK {
			return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "stream must be a boolean"}
		}
	}
	keepAlive := defaultKeepAlive
	if raw, exists := value["keep_alive"]; exists {
		parsed, err := parseKeepAliveValue(raw)
		if err != nil {
			return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "keep_alive must be a duration"}
		}
		keepAlive = parsed
	}
	if route == "ollama.generate" {
		if raw, exists := value["prompt"]; exists {
			if _, ok := raw.(string); !ok {
				return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "prompt must be a string"}
			}
		}
	}
	if route == "ollama.chat" {
		raw, exists := value["messages"]
		if !exists {
			return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "messages is required"}
		}
		messages, ok := raw.([]any)
		if !ok || len(messages) == 0 {
			return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "messages must be a non-empty array"}
		}
		for _, rawMessage := range messages {
			message, ok := rawMessage.(map[string]any)
			if !ok {
				return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "messages must contain objects"}
			}
			if role, ok := message["role"].(string); !ok || strings.TrimSpace(role) == "" {
				return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "message role is required"}
			}
			if content, exists := message["content"]; exists && !stringValueOrParts(content) {
				return ollamaRequest{}, &ollamaValidationError{Status: http.StatusBadRequest, Message: "message content must be a string or array"}
			}
		}
	}
	return ollamaRequest{Value: value, Model: modelName, Stream: stream, KeepAlive: keepAlive, Unload: keepAlive == 0}, nil
}

func validateOllamaOpenAIRequest(r *http.Request, body []byte, route string) (map[string]any, *ollamaValidationError) {
	if !jsonContentTypeOK(r) {
		return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "invalid request"}
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "invalid request"}
	}
	modelName, ok := value["model"].(string)
	if !ok || strings.TrimSpace(modelName) == "" {
		return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "model is required"}
	}
	if len([]rune(modelName)) > 256 {
		return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "model name is too long"}
	}
	if raw, exists := value["stream"]; exists {
		if _, ok := raw.(bool); !ok {
			return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "stream must be a boolean"}
		}
	}
	switch route {
	case "openai.chat.completions":
		if err := validateOllamaChatMessages(value); err != nil {
			return nil, err
		}
	case "openai.completions":
		if raw, exists := value["prompt"]; !exists {
			return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "prompt is required"}
		} else if !stringOrStringArray(raw) {
			return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "prompt must be a string or array"}
		}
	case "openai.embeddings":
		if raw, exists := value["input"]; !exists || !stringOrStringArray(raw) {
			return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "input is required"}
		}
	case "openai.responses":
		if raw, exists := value["input"]; !exists || (!stringOrStringArray(raw) && !messagesLikeArray(raw)) {
			return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "input is required"}
		}
	}
	return value, nil
}

func validateOllamaTaskRequest(r *http.Request, body []byte, route string) (map[string]any, *ollamaValidationError) {
	if !jsonContentTypeOK(r) {
		return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "invalid request"}
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "invalid request"}
	}
	modelName, ok := value["model"].(string)
	if !ok || strings.TrimSpace(modelName) == "" {
		return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "model is required"}
	}
	if len([]rune(modelName)) > 256 {
		return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "model name is too long"}
	}
	if raw, exists := value["stream"]; exists {
		if _, ok := raw.(bool); !ok {
			return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "stream must be a boolean"}
		}
	}
	if route == "ollama.copy" {
		if name, ok := value["destination"].(string); !ok || strings.TrimSpace(name) == "" {
			return nil, &ollamaValidationError{Status: http.StatusBadRequest, Message: "destination is required"}
		}
	}
	return value, nil
}

func validateOllamaChatMessages(value map[string]any) *ollamaValidationError {
	raw, exists := value["messages"]
	if !exists {
		return &ollamaValidationError{Status: http.StatusBadRequest, Message: "messages is required"}
	}
	messages, ok := raw.([]any)
	if !ok || len(messages) == 0 {
		return &ollamaValidationError{Status: http.StatusBadRequest, Message: "messages must be a non-empty array"}
	}
	for _, rawMessage := range messages {
		message, ok := rawMessage.(map[string]any)
		if !ok {
			return &ollamaValidationError{Status: http.StatusBadRequest, Message: "messages must contain objects"}
		}
		if role, ok := message["role"].(string); !ok || strings.TrimSpace(role) == "" {
			return &ollamaValidationError{Status: http.StatusBadRequest, Message: "message role is required"}
		}
		if content, exists := message["content"]; exists && !stringValueOrParts(content) {
			return &ollamaValidationError{Status: http.StatusBadRequest, Message: "message content must be a string or array"}
		}
	}
	return nil
}

func streamValue(value map[string]any) bool {
	stream, ok := value["stream"].(bool)
	return ok && stream
}

func parseKeepAliveValue(value any) (time.Duration, error) {
	switch raw := value.(type) {
	case string:
		value := strings.TrimSpace(raw)
		if value == "0" {
			return 0, nil
		}
		duration, err := time.ParseDuration(value)
		if err != nil || duration < 0 {
			return 0, fmt.Errorf("invalid duration")
		}
		return duration, nil
	case float64:
		if raw < 0 {
			return 0, fmt.Errorf("negative duration")
		}
		duration := time.Duration(raw * float64(time.Second))
		if duration < 0 {
			return 0, fmt.Errorf("duration overflow")
		}
		return duration, nil
	case json.Number:
		seconds, err := raw.Float64()
		if err != nil || seconds < 0 {
			return 0, fmt.Errorf("invalid duration")
		}
		duration := time.Duration(seconds * float64(time.Second))
		if duration < 0 {
			return 0, fmt.Errorf("duration overflow")
		}
		return duration, nil
	default:
		return 0, fmt.Errorf("invalid duration")
	}
}
