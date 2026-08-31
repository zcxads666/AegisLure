package app

import "github.com/zcxads666/AegisLure/internal/profiles"

func sglangOpenAPISchema(profile profiles.Profile) map[string]any {
	get := func() map[string]any {
		return map[string]any{"get": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "Successful response"}}}}
	}
	post := func() map[string]any {
		return map[string]any{"post": map[string]any{"responses": map[string]any{"200": map[string]any{"description": "Successful response"}}}}
	}
	paths := map[string]any{
		"/health":                         get(),
		"/get_model_info":                 get(),
		"/metrics":                        get(),
		"/docs":                           get(),
		"/redoc":                          get(),
		"/openapi.json":                   get(),
		"/server_info":                    get(),
		"/generate":                       post(),
		"/load_lora_adapter_from_tensors": post(),
		"/update_weights_from_disk":       post(),
		"/flush_cache":                    post(),
		"/get_weights_by_name":            post(),
		"/v1/models":                      get(),
		"/v1/chat/completions":            post(),
		"/v1/completions":                 post(),
		"/v1/embeddings":                  post(),
		"/v1/responses":                   post(),
	}
	return map[string]any{"openapi": "3.1.0", "info": map[string]string{"title": "SGLang OpenAI Compatible API", "version": profile.DisplayVersion}, "paths": paths}
}
