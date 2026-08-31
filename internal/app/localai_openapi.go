package app

import "github.com/zcxads666/AegisLure/internal/profiles"

func localAIOpenAPISchema(profile profiles.Profile) map[string]any {
	get := func() map[string]any {
		return map[string]any{"get": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "Successful response"}}}}
	}
	post := func() map[string]any {
		return map[string]any{"post": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "Successful response"}}}}
	}
	paths := map[string]any{
		"/":                        get(),
		"/readyz":                  get(),
		"/healthz":                 get(),
		"/metrics":                 get(),
		"/swagger":                 get(),
		"/openapi.json":            get(),
		"/models/available":        get(),
		"/models/apply":            post(),
		"/models/installed":        get(),
		"/models/delete":           post(),
		"/models/jobs/{id}":        get(),
		"/v1/models":               get(),
		"/v1/chat/completions":     post(),
		"/v1/completions":          post(),
		"/v1/responses":            post(),
		"/v1/embeddings":           post(),
		"/v1/audio/transcriptions": post(),
		"/v1/audio/speech":         post(),
		"/v1/images/generations":   post(),
	}
	return map[string]any{"openapi": "3.0.0", "info": map[string]string{"title": "LocalAI", "version": profile.DisplayVersion}, "paths": paths}
}
