package app

import "github.com/zcxads666/AegisLure/internal/profiles"

// vllmDocsHTML is only reachable when the persona explicitly enables docs.
// The default profile mirrors --disable-fastapi-docs and never exposes this
// surface.
const vllmDocsHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>vLLM OpenAI-Compatible Server</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({url: '/openapi.json', dom_id: '#swagger-ui', deepLinking: true, persistAuthorization: false});
  </script>
</body>
</html>`

func vllmOpenAPISchema(profile profiles.Profile) map[string]any {
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{
			"title":   "vLLM OpenAI-Compatible Server",
			"version": profile.Persona.VLLM.Version,
		},
		"servers": []any{map[string]string{"url": "/"}},
		"paths": map[string]any{
			"/health": map[string]any{
				"get": map[string]any{
					"operationId": "health",
					"responses":   map[string]any{"200": responseDescription("Service is healthy")},
				},
			},
			"/version": map[string]any{
				"get": map[string]any{
					"operationId": "version",
					"responses": map[string]any{
						"200": responseWithSchema("Server version", refSchema("#/components/schemas/VersionResponse"), "application/json"),
					},
				},
			},
			"/metrics": map[string]any{
				"get": map[string]any{
					"operationId": "metrics",
					"responses": map[string]any{
						"200": responseWithSchema("Prometheus metrics", stringSchema(), "text/plain"),
					},
				},
			},
			"/v1/models": map[string]any{
				"get": map[string]any{
					"operationId": "listModels",
					"responses": map[string]any{
						"200": responseWithSchema("Available served models", refSchema("#/components/schemas/ModelList"), "application/json"),
					},
				},
			},
			"/v1/chat/completions": openAPIJSONOperation("createChatCompletion", "#/components/schemas/ChatCompletionRequest", "#/components/schemas/ChatCompletionResponse"),
			"/v1/completions":      openAPIJSONOperation("createCompletion", "#/components/schemas/CompletionRequest", "#/components/schemas/CompletionResponse"),
			"/v1/embeddings":       openAPIJSONOperation("createEmbedding", "#/components/schemas/EmbeddingRequest", "#/components/schemas/EmbeddingResponse"),
			"/v1/responses":        openAPIJSONOperation("createResponse", "#/components/schemas/ResponseRequest", "#/components/schemas/ResponseResponse"),
			"/invocations":         openAPIJSONOperation("invoke", "#/components/schemas/InvocationRequest", "#/components/schemas/ChatCompletionResponse"),
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"VersionResponse":        map[string]any{"type": "object", "required": []string{"version"}, "properties": map[string]any{"version": stringSchema()}},
				"ModelList":              map[string]any{"type": "object", "required": []string{"object", "data"}, "properties": map[string]any{"object": map[string]any{"type": "string", "enum": []string{"list"}}, "data": map[string]any{"type": "array", "items": refSchema("#/components/schemas/ModelCard")}}},
				"ModelCard":              map[string]any{"type": "object", "required": []string{"id", "object", "created", "owned_by"}, "properties": map[string]any{"id": stringSchema(), "object": map[string]any{"type": "string", "enum": []string{"model"}}, "created": int64Schema(), "owned_by": stringSchema(), "root": stringSchema()}},
				"ContentPart":            map[string]any{"type": "object", "required": []string{"type"}, "properties": map[string]any{"type": stringSchema(), "text": stringSchema()}, "additionalProperties": true},
				"ChatMessage":            map[string]any{"type": "object", "required": []string{"role"}, "properties": map[string]any{"role": stringSchema(), "content": stringOrContentPartsSchema(), "name": stringSchema()}},
				"ChatCompletionRequest":  map[string]any{"type": "object", "required": []string{"model", "messages"}, "properties": map[string]any{"model": stringSchema(), "messages": map[string]any{"type": "array", "minItems": 1, "items": refSchema("#/components/schemas/ChatMessage")}, "stream": boolSchema(), "temperature": numberSchema(), "max_tokens": integerSchema(1), "max_completion_tokens": integerSchema(1), "n": integerSchema(1)}},
				"CompletionRequest":      map[string]any{"type": "object", "required": []string{"model", "prompt"}, "properties": map[string]any{"model": stringSchema(), "prompt": stringOrStringArraySchema(), "stream": boolSchema(), "max_tokens": integerSchema(1)}},
				"EmbeddingRequest":       map[string]any{"type": "object", "required": []string{"model", "input"}, "properties": map[string]any{"model": stringSchema(), "input": stringOrStringArraySchema()}},
				"ResponseRequest":        map[string]any{"type": "object", "required": []string{"model", "input"}, "properties": map[string]any{"model": stringSchema(), "input": stringOrResponseInputArraySchema(), "stream": boolSchema()}},
				"InvocationRequest":      map[string]any{"type": "object", "required": []string{"model"}, "properties": map[string]any{"model": stringSchema(), "prompt": stringOrStringArraySchema(), "stream": boolSchema()}},
				"ChatCompletionResponse": map[string]any{"type": "object", "required": []string{"id", "object", "created", "model", "choices", "usage"}, "properties": map[string]any{"id": stringSchema(), "object": stringSchema(), "created": int64Schema(), "model": stringSchema(), "system_fingerprint": stringSchema(), "choices": map[string]any{"type": "array", "items": refSchema("#/components/schemas/Choice")}, "usage": refSchema("#/components/schemas/Usage")}},
				"Choice":                 map[string]any{"type": "object", "properties": map[string]any{"index": integerSchema(0), "message": refSchema("#/components/schemas/ChatMessage"), "delta": refSchema("#/components/schemas/ChatMessage"), "text": stringSchema(), "finish_reason": nullableStringSchema()}},
				"Usage":                  map[string]any{"type": "object", "required": []string{"prompt_tokens", "completion_tokens", "total_tokens"}, "properties": map[string]any{"prompt_tokens": integerSchema(0), "completion_tokens": integerSchema(0), "total_tokens": integerSchema(0)}},
				"CompletionResponse":     map[string]any{"type": "object", "required": []string{"id", "object", "created", "model", "choices", "usage"}, "properties": map[string]any{"id": stringSchema(), "object": stringSchema(), "created": int64Schema(), "model": stringSchema(), "choices": map[string]any{"type": "array", "items": refSchema("#/components/schemas/CompletionChoice")}, "usage": refSchema("#/components/schemas/Usage")}},
				"CompletionChoice":       map[string]any{"type": "object", "required": []string{"index", "text", "finish_reason"}, "properties": map[string]any{"index": integerSchema(0), "text": stringSchema(), "finish_reason": nullableStringSchema()}},
				"EmbeddingData":          map[string]any{"type": "object", "required": []string{"object", "embedding", "index"}, "properties": map[string]any{"object": stringSchema(), "embedding": map[string]any{"type": "array", "items": numberSchema()}, "index": integerSchema(0)}},
				"EmbeddingResponse":      map[string]any{"type": "object", "required": []string{"object", "data", "model"}, "properties": map[string]any{"object": stringSchema(), "data": map[string]any{"type": "array", "items": refSchema("#/components/schemas/EmbeddingData")}, "model": stringSchema(), "usage": refSchema("#/components/schemas/Usage")}},
				"ResponseResponse":       map[string]any{"type": "object", "required": []string{"id", "object", "model", "status"}, "properties": map[string]any{"id": stringSchema(), "object": stringSchema(), "model": stringSchema(), "status": stringSchema(), "output": map[string]any{"type": "array"}, "usage": map[string]any{"type": "object"}}},
				"ErrorResponse":          map[string]any{"type": "object", "required": []string{"detail"}, "properties": map[string]any{"detail": map[string]any{}}},
			},
		},
	}
}

func openAPIJSONOperation(operationID, requestRef, responseRef string) map[string]any {
	return map[string]any{
		"post": map[string]any{
			"operationId": operationID,
			"requestBody": map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": refSchema(requestRef)}}},
			"responses": map[string]any{
				"200": responseWithSchema("Successful response", refSchema(responseRef), "application/json", "text/event-stream"),
				"401": responseWithSchema("Authentication required", refSchema("#/components/schemas/ErrorResponse"), "application/json"),
				"404": responseWithSchema("Model not found", refSchema("#/components/schemas/ErrorResponse"), "application/json"),
				"422": responseWithSchema("Validation error", refSchema("#/components/schemas/ErrorResponse"), "application/json"),
			},
		},
	}
}

func responseDescription(description string) map[string]any {
	return map[string]any{"description": description}
}

func responseWithSchema(description string, schema map[string]any, contentTypes ...string) map[string]any {
	content := make(map[string]any, len(contentTypes))
	for _, contentType := range contentTypes {
		content[contentType] = map[string]any{"schema": schema}
	}
	return map[string]any{"description": description, "content": content}
}

func stringSchema() map[string]any {
	return map[string]any{"type": "string"}
}

func boolSchema() map[string]any {
	return map[string]any{"type": "boolean"}
}

func numberSchema() map[string]any {
	return map[string]any{"type": "number"}
}

func integerSchema(minimum int) map[string]any {
	return map[string]any{"type": "integer", "minimum": minimum}
}

func int64Schema() map[string]any {
	return map[string]any{"type": "integer", "format": "int64"}
}

func nullableStringSchema() map[string]any {
	return map[string]any{"type": []string{"string", "null"}}
}

func refSchema(ref string) map[string]any {
	return map[string]any{"$ref": ref}
}

func stringOrStringArraySchema() map[string]any {
	return map[string]any{"anyOf": []any{stringSchema(), map[string]any{"type": "array", "items": stringSchema()}}}
}

func stringOrContentPartsSchema() map[string]any {
	return map[string]any{"anyOf": []any{stringSchema(), map[string]any{"type": "array", "items": refSchema("#/components/schemas/ContentPart")}}}
}

func stringOrResponseInputArraySchema() map[string]any {
	return map[string]any{"anyOf": []any{stringSchema(), map[string]any{"type": "array", "items": map[string]any{}}}}
}
