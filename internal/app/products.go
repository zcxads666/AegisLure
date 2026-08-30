package app

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/detect"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
)

func (a *App) handleProduct(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	switch profile.Product {
	case model.ProductNewAPI:
		a.handleNewAPI(w, r, profile, session, body, obs)
	case model.ProductVLLM:
		a.handleVLLM(w, r, profile, session, body, obs)
	case model.ProductOllama:
		a.handleOllama(w, r, profile, session, body, obs)
	case model.ProductSGLang:
		a.handleSGLang(w, r, profile, session, body, obs)
	case model.ProductLocalAI:
		a.handleLocalAI(w, r, profile, session, body, obs)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": "profile not found"})
	}
}

func (a *App) handleNewAPI(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	switch obs.RouteTemplate {
	case "newapi.home":
		a.writeHTML(w, http.StatusOK, "AI Gateway", `<h1>AI Gateway</h1><p>Unified AI model access and usage console.</p><p><a href="/login">Log in</a> · <a href="/register">Create an account</a> · <a href="/v1/models">View models</a></p><hr><small>Frontend design and development by New API contributors. This service is derived from <a href="https://github.com/QuantumNous/new-api">New API</a>.</small>`)
	case "newapi.login":
		a.writeHTML(w, http.StatusOK, "Log in", `<h1>Log in</h1><form method="post" action="/api/user/login"><input name="username" placeholder="Username" autocomplete="username"><br><input name="password" type="password" placeholder="Password" autocomplete="current-password"><br><button>Log in</button></form><p><a href="/register">Register</a></p>`)
	case "newapi.register":
		a.writeHTML(w, http.StatusOK, "Create account", `<h1>Create account</h1><form method="post" action="/api/user/register"><input name="username" placeholder="Username" autocomplete="username"><br><input name="email" type="email" placeholder="Email" autocomplete="email"><br><input name="password" type="password" placeholder="Password" autocomplete="new-password"><br><button>Create account</button></form><p>OAuth providers, when enabled by the deployment owner, redirect to their official authorization pages.</p>`)
	case "newapi.user.register":
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w)
			return
		}
		value := requestValues(r, body)
		username := strings.TrimSpace(value["username"])
		if username == "" || len(username) > 128 {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid registration request"})
			return
		}
		password := value["password"]
		userID := "hu_" + security.MustRandomToken(10)
		user := model.HoneyUser{ID: userID, InstanceID: a.cfg.InstanceID, UsernameFP: security.Fingerprint(a.cfg.InstanceKey, username), UsernameHint: security.RedactPreview(username, 3), EmailDomain: emailDomain(value["email"]), PasswordFP: security.Fingerprint(a.cfg.InstanceKey, password), VirtualQuota: 0, CreatedAt: time.Now().UTC(), LastSeen: time.Now().UTC()}
		if err := a.store.CreateHoneyUser(user); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "registration unavailable"})
			return
		}
		a.setSessionUser(session.ID, user.ID)
		obs.ExtraScore += 25
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_batch_registration_or_account_creation")
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"id": user.ID, "username": username, "quota": user.VirtualQuota}})
	case "newapi.user.login":
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w)
			return
		}
		value := requestValues(r, body)
		user, ok := a.store.FindHoneyUser(security.Fingerprint(a.cfg.InstanceKey, strings.TrimSpace(value["username"])))
		if !ok || user.PasswordFP != security.Fingerprint(a.cfg.InstanceKey, value["password"]) {
			a.writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "invalid username or password"})
			return
		}
		_ = a.store.TouchHoneyUser(user.ID, func(u *model.HoneyUser) { u.LastSeen = time.Now().UTC() })
		a.setSessionUser(session.ID, user.ID)
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"id": user.ID, "username": user.UsernameHint}})
	case "newapi.checkin":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		now := time.Now().UTC()
		day := now.Format("2006-01-02")
		if user.CheckinDay == day {
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "already_checked_in": true, "quota": user.VirtualQuota})
			return
		}
		if err := a.store.TouchHoneyUser(user.ID, func(u *model.HoneyUser) { u.CheckedInAt = now; u.CheckinDay = day }); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false})
			return
		}
		balance, err := a.store.AddQuota(user.ID, 1000)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false})
			return
		}
		obs.ExtraScore += 20
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_virtual_checkin")
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "quota_added": 1000, "quota": balance})
	case "newapi.token.create":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		value, err := security.RandomToken(24)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false})
			return
		}
		raw := "sk-proj-" + value
		token := model.HoneyToken{ID: "ht_" + security.MustRandomToken(8), HoneyUserID: user.ID, Hash: security.Fingerprint(a.cfg.InstanceKey, raw), PrefixHint: raw[:12], CreatedAt: time.Now().UTC()}
		if err := a.store.AddToken(token); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false})
			return
		}
		obs.ExtraScore += 20
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_honey_token_created")
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"id": token.ID, "key": raw, "warning": "The key is shown once and is valid only in this service."}})
	case "newapi.user.status":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"id": user.ID, "quota": user.VirtualQuota}})
	case "newapi.usage.logs":
		if _, ok := a.requireHoneyUser(w, session); !ok {
			return
		}
		obs.EffectOutcome = "verified"
		obs.ExtraScore += 15
		obs.ExtraReasons = append(obs.ExtraReasons, "post_call_effect_verification")
		events, _ := a.store.Events(50, model.ProductNewAPI, "")
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": publicUsageEvents(events, session.ID)})
	case "openai.models":
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": profiles.Catalog(model.ProductNewAPI)})
	case "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings":
		a.newAPIInvoke(w, r, body, session, obs)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"message": "Not found", "type": "invalid_request_error"}})
	}
}

func (a *App) newAPIInvoke(w *captureWriter, r *http.Request, body []byte, session Session, obs *Observation) {
	token, auth := a.honeyAuth(r)
	if auth == "valid_honey_key" {
		obs.CredentialFingerprint = token.Hash
	}
	if auth != "valid_honey_key" {
		a.startInvocation(obs, auth, false)
		a.writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"message": "Incorrect API key provided", "type": "invalid_request_error", "code": "invalid_api_key"}})
		return
	}
	if session.UserID != "" && token.HoneyUserID != session.UserID {
		obs.AuthOutcome = "invalid"
		a.startInvocation(obs, "invalid", false)
		a.writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"message": "API key is not available to this session", "type": "invalid_request_error"}})
		return
	}
	modelName := a.validModelName(model.ProductNewAPI, a.requestModel(body))
	if entry, ok := profiles.ResolveModel(model.ProductNewAPI, a.requestModel(body)); ok {
		obs.ModelID, obs.ModelResolved = entry.ID, true
	} else if a.requestModel(body) == "" {
		obs.ModelID, obs.ModelResolved = modelName, true
	} else {
		obs.ModelID = modelName
	}
	obs.ExtraScore += 25
	obs.ExtraReasons = append(obs.ExtraReasons, "newapi_synthetic_compute_use")
	a.startInvocation(obs, auth, true)
	cost := int64(maxInt(1, len(body)/4))
	if _, err := a.store.ConsumeQuota(token.HoneyUserID, token.ID, obs.InvocationID, cost); err != nil {
		obs.ExecutionOutcome = "rejected_before_dispatch"
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_virtual_quota_exhausted")
		a.writeJSON(w, http.StatusPaymentRequired, map[string]any{"error": map[string]string{"message": "insufficient quota", "type": "insufficient_quota"}})
		return
	}
	a.writeOpenAIResponseForRoute(w, body, model.ProductNewAPI, obs.RouteTemplate, streamRequested(r, body), obs, modelName)
}

func (a *App) handleVLLM(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	w.Header().Set("Server", "uvicorn")
	if isVLLMReadRoute(obs.RouteTemplate) && r.Method != http.MethodGet {
		a.writeMethodNotAllowed(w, model.ProductVLLM)
		return
	}
	switch obs.RouteTemplate {
	case "vllm.root":
		a.writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Not Found"})
	case "vllm.health":
		if len(a.store.ActiveEffects(session.ID, model.ProductVLLM, time.Now().UTC())) > 0 {
			_ = a.store.MarkEffectsVerified(session.ID, model.ProductVLLM, "virtual_worker_degraded", time.Now().UTC())
			obs.EffectOutcome = "verified"
			obs.ExtraScore += 15
			obs.ExtraReasons = append(obs.ExtraReasons, "post_call_effect_verification")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("Service Unavailable"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	case "vllm.version":
		a.writeJSON(w, http.StatusOK, map[string]string{"version": profile.DisplayVersion})
	case "vllm.metrics":
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(a.vllmMetrics()))
	case "openai.models":
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": profiles.VLLMModelCards(a.cfg.InstanceKey)})
	case "vllm.invocations", "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings":
		a.vllmInvoke(w, r, profile, session, body, obs)
	case "vllm.tokenize":
		a.writeJSON(w, http.StatusOK, map[string]any{"tokens": []int{101, 2026, 8080, 102}, "count": 4})
	case "vllm.detokenize":
		a.writeJSON(w, http.StatusOK, map[string]any{"prompt": "The request was decoded."})
	case "vllm.docs":
		a.writeHTML(w, http.StatusOK, "vLLM OpenAI-Compatible Server", `<h1>vLLM OpenAI-Compatible Server</h1><p>Interactive API documentation.</p><p><a href="/openapi.json">OpenAPI schema</a></p>`)
	case "vllm.openapi":
		a.writeJSON(w, http.StatusOK, map[string]any{
			"openapi": "3.1.0",
			"info":    map[string]string{"title": "vLLM OpenAI-Compatible Server", "version": profile.DisplayVersion},
			"paths": map[string]any{
				"/health":              map[string]any{},
				"/version":             map[string]any{},
				"/v1/models":           map[string]any{},
				"/v1/chat/completions": map[string]any{},
				"/v1/completions":      map[string]any{},
				"/v1/embeddings":       map[string]any{},
				"/invocations":         map[string]any{},
				"/tokenize":            map[string]any{},
				"/detokenize":          map[string]any{},
			},
		})
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]any{"detail": "Not Found"})
	}
}

func (a *App) vllmInvoke(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	if _, ok := decodeJSONObject(body); !ok {
		a.startInvocation(obs, "invalid", false)
		a.writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"detail": []any{map[string]any{"type": "json_invalid", "loc": []string{"body"}, "msg": "JSON decode error"}}})
		return
	}
	token, auth := a.honeyAuth(r)
	if auth == "valid_honey_key" {
		obs.CredentialFingerprint = token.Hash
	}
	if obs.RouteTemplate == "vllm.invocations" && profile.Scenario == "legacy-gap" && auth == "missing" {
		modelName, resolved := a.vllmModelName(a.requestModel(body))
		if !resolved {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"detail": "The requested model does not exist."})
			return
		}
		obs.ModelID, obs.ModelResolved = modelName, true
		a.startInvocation(obs, "bypass_simulated", true)
		obs.ExtraScore += 20
		obs.ExtraReasons = append(obs.ExtraReasons, "vllm_invocations_auth_gap")
		a.maybeDegradeVLLM(session, body, obs)
		a.notePersonaInvocation(model.ProductVLLM, modelName, maxInt(8, len(body)/4), maxInt(6, len(personaResponseText(body, model.ProductVLLM))/4))
		a.writeVLLMResponse(w, body, obs.RouteTemplate, streamRequested(r, body), obs, modelName)
		return
	}
	if profile.Scenario != "no-key" && auth != "valid_honey_key" {
		a.startInvocation(obs, auth, false)
		a.writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"message": "Unauthorized", "type": "authentication_error"}})
		return
	}
	modelName, resolved := a.vllmModelName(a.requestModel(body))
	if !resolved {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"detail": "The requested model does not exist."})
		return
	}
	obs.ModelID, obs.ModelResolved = modelName, true
	a.startInvocation(obs, auth, true)
	obs.ExtraScore += 25
	obs.ExtraReasons = append(obs.ExtraReasons, "vllm_synthetic_compute_use")
	a.maybeDegradeVLLM(session, body, obs)
	a.notePersonaInvocation(model.ProductVLLM, modelName, maxInt(8, len(body)/4), maxInt(6, len(personaResponseText(body, model.ProductVLLM))/4))
	a.writeVLLMResponse(w, body, obs.RouteTemplate, streamRequested(r, body), obs, modelName)
}

func (a *App) vllmModelName(requested string) (string, bool) {
	if requested == "" {
		catalog := profiles.VLLMModelCards(a.cfg.InstanceKey)
		if len(catalog) == 0 {
			return "", false
		}
		return catalog[0].ID, true
	}
	if entry, ok := profiles.ResolveModel(model.ProductVLLM, requested); ok {
		return entry.ID, true
	}
	return "", false
}

func isVLLMReadRoute(route string) bool {
	switch route {
	case "vllm.root", "vllm.health", "vllm.version", "vllm.metrics", "openai.models", "vllm.docs", "vllm.openapi":
		return true
	default:
		return false
	}
}

func (a *App) maybeDegradeVLLM(session Session, body []byte, obs *Observation) {
	result := detect.Analyze(model.ProductVLLM, obs.RouteTemplate, string(body))
	if result.Score < 60 {
		return
	}
	_ = a.store.AddEffect(model.VirtualEffect{ID: "ve_" + security.MustRandomToken(8), OwnerScope: "session", OwnerKey: session.ID, Product: model.ProductVLLM, EffectType: "virtual_worker_degraded", State: map[string]string{"simulated_worker_crash": "true"}, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(60 * time.Second).UTC()})
	obs.EffectOutcome = "applied"
	obs.ExtraReasons = append(obs.ExtraReasons, "simulated_worker_degraded")
}

func (a *App) handleOllama(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	if isOllamaReadRoute(obs.RouteTemplate) && r.Method != http.MethodGet {
		a.writeMethodNotAllowed(w, model.ProductOllama)
		return
	}
	switch obs.RouteTemplate {
	case "ollama.home":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Ollama is running"))
	case "ollama.version":
		a.writeJSON(w, http.StatusOK, map[string]string{"version": profile.DisplayVersion})
	case "ollama.tags":
		a.writeJSON(w, http.StatusOK, map[string]any{"models": profiles.OllamaModels(a.cfg.InstanceKey)})
	case "ollama.ps":
		activeNames := map[string]time.Time{}
		for _, active := range a.activePersonaModels(model.ProductOllama, session.ID) {
			activeNames[active.Name] = active.ExpiresAt
		}
		for _, effect := range a.store.ActiveEffects(session.ID, model.ProductOllama, time.Now().UTC()) {
			if effect.EffectType == "model_virtually_loaded" {
				if name := effect.State["model"]; name != "" {
					if _, exists := activeNames[name]; !exists {
						activeNames[name] = effect.ExpiresAt
					}
				}
			}
		}
		models := []map[string]any{}
		for name, expiresAt := range activeNames {
			if item, ok := profiles.FindOllamaModel(a.cfg.InstanceKey, name); ok {
				models = append(models, map[string]any{"name": item.Name, "model": item.Model, "size": item.Size, "digest": item.Digest, "details": item.Details, "expires_at": expiresAt.Format(time.RFC3339Nano), "size_vram": item.Size / 2})
			}
		}
		if len(models) > 0 {
			obs.EffectOutcome = "verified"
			obs.ExtraScore += 15
			obs.ExtraReasons = append(obs.ExtraReasons, "post_call_effect_verification")
			_ = a.store.MarkEffectsVerified(session.ID, model.ProductOllama, "model_virtually_loaded", time.Now().UTC())
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"models": models})
	case "ollama.show":
		requested := a.requestModel(body)
		if requested == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "model is required"})
			return
		}
		item, ok := profiles.FindOllamaModel(a.cfg.InstanceKey, requested)
		if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model not found"})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"modelfile": "FROM " + item.Name, "parameters": "", "template": "{{ .Response }}", "details": item.Details, "model_info": map[string]any{"general.architecture": item.Details.Family, "general.parameter_count": item.Details.ParameterSize}})
	case "ollama.generate", "ollama.chat":
		a.ollamaInvoke(w, body, session, obs, r)
	case "ollama.embeddings":
		item, ok := profiles.FindOllamaModel(a.cfg.InstanceKey, a.requestModel(body))
		if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model not found"})
			return
		}
		obs.ModelID = item.Model
		obs.ModelResolved = true
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 20
		obs.SimulatedInputTokens = maxInt(8, len(body)/4)
		obs.SimulatedOutputTokens = 0
		obs.SimulatedCost = int64(obs.SimulatedInputTokens)
		a.notePersonaInvocation(model.ProductOllama, item.Model, obs.SimulatedInputTokens, 0)
		a.markPersonaModel(model.ProductOllama, session.ID, item.Name, 90*time.Second)
		a.writeJSON(w, http.StatusOK, map[string]any{"model": item.Name, "embedding": []float64{0.0123, -0.0456, 0.0789}, "embeddings": [][]float64{{0.0123, -0.0456, 0.0789}}})
	case "openai.models":
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": profiles.OllamaOpenAIModels(a.cfg.InstanceKey)})
	case "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings":
		a.ollamaOpenAIInvoke(w, body, session, obs, r)
	case "ollama.pull", "ollama.push", "ollama.create", "ollama.copy", "ollama.delete", "ollama.blob":
		a.ollamaTask(w, body, obs)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": "route not found"})
	}
}

func isOllamaReadRoute(route string) bool {
	switch route {
	case "ollama.home", "ollama.version", "ollama.tags", "ollama.ps", "openai.models":
		return true
	default:
		return false
	}
}

func (a *App) ollamaInvoke(w *captureWriter, body []byte, session Session, obs *Observation, r *http.Request) {
	if _, ok := decodeJSONObject(body); !ok {
		a.startInvocation(obs, "invalid", false)
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	item, ok := profiles.FindOllamaModel(a.cfg.InstanceKey, a.requestModel(body))
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model not found"})
		return
	}
	modelName := item.Model
	publicModelName := item.Name
	obs.ModelID, obs.ModelResolved = modelName, true
	a.startInvocation(obs, "not_required", true)
	obs.ExtraScore += 25
	obs.ExtraReasons = append(obs.ExtraReasons, "ollama_open_deployment_synthetic_use")
	_ = a.store.AddEffect(model.VirtualEffect{ID: "ve_" + security.MustRandomToken(8), OwnerScope: "session", OwnerKey: session.ID, Product: model.ProductOllama, EffectType: "model_virtually_loaded", State: map[string]string{"model": publicModelName}, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(90 * time.Second).UTC()})
	a.markPersonaModel(model.ProductOllama, session.ID, publicModelName, 90*time.Second)
	responseText := personaResponseText(body, model.ProductOllama)
	inputTokens, outputTokens := maxInt(8, len(body)/4), maxInt(6, len(responseText)/4)
	obs.SimulatedInputTokens, obs.SimulatedOutputTokens = inputTokens, outputTokens
	obs.SimulatedCost = int64(inputTokens + outputTokens)
	a.notePersonaInvocation(model.ProductOllama, modelName, inputTokens, outputTokens)
	value := a.jsonBody(body)
	if stringValue(value["stream"]) == "true" || streamRequested(r, body) {
		a.writeOllamaStream(w, body, publicModelName, obs)
		return
	}
	obs.ExecutionOutcome = "synthetic_accepted"
	if obs.RouteTemplate == "ollama.generate" {
		a.writeJSON(w, http.StatusOK, map[string]any{"model": publicModelName, "created_at": time.Now().UTC().Format(time.RFC3339Nano), "response": responseText, "done": true, "total_duration": 28000000, "prompt_eval_count": inputTokens, "eval_count": outputTokens})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"model": publicModelName, "created_at": time.Now().UTC().Format(time.RFC3339Nano), "message": map[string]string{"role": "assistant", "content": responseText}, "done": true, "total_duration": 28000000, "prompt_eval_count": inputTokens, "eval_count": outputTokens})
}

func (a *App) ollamaOpenAIInvoke(w *captureWriter, body []byte, session Session, obs *Observation, r *http.Request) {
	if _, ok := decodeJSONObject(body); !ok {
		a.startInvocation(obs, "invalid", false)
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	item, ok := profiles.FindOllamaModel(a.cfg.InstanceKey, a.requestModel(body))
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model not found"})
		return
	}
	modelName := item.Model
	obs.ModelID, obs.ModelResolved = modelName, true
	a.startInvocation(obs, "not_required", true)
	obs.ExtraScore += 25
	obs.ExtraReasons = append(obs.ExtraReasons, "ollama_openai_compat_synthetic_use")
	_ = a.store.AddEffect(model.VirtualEffect{ID: "ve_" + security.MustRandomToken(8), OwnerScope: "session", OwnerKey: session.ID, Product: model.ProductOllama, EffectType: "model_virtually_loaded", State: map[string]string{"model": item.Name}, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(90 * time.Second).UTC()})
	a.markPersonaModel(model.ProductOllama, session.ID, item.Name, 90*time.Second)
	a.writeOllamaOpenAIResponse(w, body, obs.RouteTemplate, streamRequested(r, body), obs, item.Name)
}

func (a *App) ollamaTask(w *captureWriter, body []byte, obs *Observation) {
	if obs.RouteTemplate == "ollama.blob" {
		// Blob probes are intentionally bounded and never persisted as files.
		obs.ExtraScore += 15
		a.startInvocation(obs, "not_required", true)
		obs.ExtraReasons = append(obs.ExtraReasons, "ollama_bounded_blob_probe")
		digest := ""
		if models := profiles.OllamaModels(a.cfg.InstanceKey); len(models) > 0 {
			digest = models[0].Digest
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"status": "success", "digest": digest, "size": 256})
		return
	}
	a.startInvocation(obs, "not_required", true)
	obs.ExtraScore += 35
	obs.ExtraReasons = append(obs.ExtraReasons, "ollama_model_lifecycle_probe")
	value := a.jsonBody(body)
	name := a.validModelName(model.ProductOllama, stringValue(value["model"]))
	item, _ := profiles.FindOllamaModel(a.cfg.InstanceKey, name)
	if obs.RouteTemplate == "ollama.pull" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, status := range []string{"pulling manifest", "pulling layers", "verifying sha256 digest", "success"} {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "digest": item.Digest, "completed": status == "success"})
		}
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"status": "success", "task_id": "task_" + obs.InvocationID, "model": item.Name, "digest": item.Digest, "progress": []string{"pulling manifest", "pulling layers", "verifying sha256 digest", "success"}})
}

func (a *App) handleSGLang(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	switch obs.RouteTemplate {
	case "sglang.health":
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	case "sglang.model_info":
		a.writeJSON(w, http.StatusOK, map[string]any{"model_path": "/models/Qwen/Qwen3.6-35B-A3B", "served_model_name": "Qwen/Qwen3.6-35B-A3B", "tp_size": 1, "pp_size": 1})
	case "sglang.metrics":
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("sglang:request_success_total 42\nsglang:cache_hit_rate 0.61\n"))
	case "sglang.docs", "sglang.redoc":
		a.writeHTML(w, http.StatusOK, "SGLang API", `<h1>SGLang API</h1><p>Interactive API documentation.</p><p>OpenAPI schema: <a href="/openapi.json">/openapi.json</a></p>`)
	case "sglang.openapi":
		a.writeJSON(w, http.StatusOK, map[string]any{"openapi": "3.1.0", "info": map[string]string{"title": "SGLang OpenAI Compatible API", "version": profile.DisplayVersion}, "paths": map[string]any{"/generate": map[string]any{}, "/v1/chat/completions": map[string]any{}, "/server_info": map[string]any{}, "/load_lora_adapter_from_tensors": map[string]any{}}})
	case "sglang.server_info":
		a.writeJSON(w, http.StatusOK, map[string]any{"model_path": "/models/Qwen/Qwen3.6-35B-A3B", "api_key": a.derivedHoneyKey(model.ProductSGLang), "ssl_keyfile": "/run/secrets/server.key", "rank": 0, "world_size": 1})
	case "openai.models":
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": profiles.Catalog(model.ProductSGLang)})
	case "sglang.generate", "openai.chat.completions", "openai.completions", "openai.embeddings":
		a.sglangInvoke(w, r, profile, body, obs)
	case "sglang.lora.load", "sglang.weights.update":
		a.sglangAdminAction(w, r, session, body, obs)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]any{"detail": "Not Found"})
	}
}

func (a *App) sglangInvoke(w *captureWriter, r *http.Request, profile profiles.Profile, body []byte, obs *Observation) {
	if profile.Scenario == "api-key" {
		_, auth := a.honeyAuth(r)
		if auth != "valid_honey_key" {
			a.startInvocation(obs, auth, false)
			a.writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "Not authenticated"})
			return
		}
	}
	a.startInvocation(obs, "not_required", true)
	obs.ExtraScore += 25
	obs.ExtraReasons = append(obs.ExtraReasons, "sglang_synthetic_compute_use")
	modelName := a.validModelName(model.ProductSGLang, a.requestModel(body))
	obs.ModelID = modelName
	obs.ModelResolved = a.requestModel(body) == ""
	if entry, ok := profiles.ResolveModel(model.ProductSGLang, a.requestModel(body)); ok {
		obs.ModelID, obs.ModelResolved = entry.ID, true
	}
	a.writeOpenAIResponseForRoute(w, body, model.ProductSGLang, obs.RouteTemplate, streamRequested(r, body), obs, modelName)
}

func (a *App) sglangAdminAction(w *captureWriter, r *http.Request, session Session, body []byte, obs *Observation) {
	key := a.bearer(r)
	if key == "" {
		a.writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "Not authenticated"})
		return
	}
	if key != a.derivedHoneyKey(model.ProductSGLang) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"detail": "Invalid admin key"})
		return
	}
	obs.CredentialFingerprint = security.Fingerprint(a.cfg.InstanceKey, key)
	a.startInvocation(obs, "leaked_key_reused", true)
	obs.ExtraScore += 55
	obs.ExtraReasons = append(obs.ExtraReasons, "sglang_server_info_honey_key_reused")
	_ = a.store.AddEffect(model.VirtualEffect{ID: "ve_" + security.MustRandomToken(8), OwnerScope: "session", OwnerKey: session.ID, Product: model.ProductSGLang, EffectType: "weight_export_canary_created", State: map[string]string{"canary": "weight_canary_" + obs.InvocationID}, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(15 * time.Minute).UTC()})
	a.writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "task_id": "lora_" + obs.InvocationID, "weight_id": "weight_" + obs.InvocationID})
}

func (a *App) handleLocalAI(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	switch obs.RouteTemplate {
	case "localai.home":
		a.writeHTML(w, http.StatusOK, "LocalAI", `<h1>LocalAI</h1><p>LocalAI is running.</p><p><a href="/swagger">Swagger</a> · <a href="/models/available">Model gallery</a> · <a href="/v1/models">Models</a></p>`)
	case "localai.health":
		a.writeJSON(w, http.StatusOK, map[string]any{"status": " ok ", "ready": true})
	case "localai.metrics":
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("localai_requests_total 18\nlocalai_models_loaded 1\n"))
	case "localai.docs":
		a.writeJSON(w, http.StatusOK, map[string]any{"openapi": "3.0.0", "info": map[string]string{"title": "LocalAI", "version": profile.DisplayVersion}, "paths": map[string]any{"/v1/chat/completions": map[string]any{}, "/models/apply": map[string]any{}, "/v1/audio/transcriptions": map[string]any{}}})
	case "localai.models.available":
		a.writeJSON(w, http.StatusOK, map[string]any{"models": profiles.Catalog(model.ProductLocalAI), "source": "model-gallery"})
	case "localai.models.installed":
		a.writeJSON(w, http.StatusOK, map[string]any{"models": []any{}})
	case "localai.models.apply":
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 50
		obs.ExtraReasons = append(obs.ExtraReasons, "localai_model_install_probe")
		a.writeJSON(w, http.StatusOK, map[string]any{"id": "job_" + obs.InvocationID, "status": "ready", "steps": []string{"resolving source", "downloading manifest", "validating archive", "installing backend", "ready"}})
	case "localai.models.delete":
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 45
		obs.ExtraReasons = append(obs.ExtraReasons, "localai_model_delete_probe")
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": true})
	case "localai.audio.transcriptions":
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 25
		a.writeJSON(w, http.StatusOK, map[string]string{"text": "Transcription completed."})
	case "openai.models":
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": profiles.Catalog(model.ProductLocalAI)})
	case "openai.chat.completions", "openai.completions", "openai.embeddings":
		if profile.Scenario == "current-rbac" {
			_, auth := a.honeyAuth(r)
			if auth != "valid_honey_key" {
				a.startInvocation(obs, auth, false)
				a.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
				return
			}
		}
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 25
		obs.ExtraReasons = append(obs.ExtraReasons, "localai_synthetic_compute_use")
		modelName := a.validModelName(model.ProductLocalAI, a.requestModel(body))
		obs.ModelID = modelName
		obs.ModelResolved = a.requestModel(body) == ""
		if entry, ok := profiles.ResolveModel(model.ProductLocalAI, a.requestModel(body)); ok {
			obs.ModelID, obs.ModelResolved = entry.ID, true
		}
		a.writeOpenAIResponseForRoute(w, body, model.ProductLocalAI, obs.RouteTemplate, streamRequested(r, body), obs, modelName)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func requestValues(r *http.Request, body []byte) map[string]string {
	result := map[string]string{}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return result
		}
		for key := range values {
			result[key] = values.Get(key)
		}
		return result
	}
	if raw, ok := decodeJSONObject(body); ok {
		for key, value := range raw {
			if text, ok := value.(string); ok {
				result[key] = text
			}
		}
	}
	return result
}

func emailDomain(email string) string {
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) == 2 && len(parts[1]) <= 255 {
		return parts[1]
	}
	return ""
}

func publicUsageEvents(events []model.Event, sessionID string) []map[string]any {
	result := make([]map[string]any, 0, len(events))
	for _, event := range events {
		if sessionID != "" && event.SessionID != sessionID {
			continue
		}
		result = append(result, map[string]any{
			"id":                event.EventID,
			"created_at":        event.ObservedAt,
			"request_id":        event.InvocationID,
			"model":             event.ModelID,
			"status":            event.Status,
			"prompt_tokens":     event.SimulatedInputTokens,
			"completion_tokens": event.SimulatedOutputTokens,
			"total_tokens":      event.SimulatedInputTokens + event.SimulatedOutputTokens,
			"cost":              event.SimulatedCost,
		})
	}
	return result
}

func (a *App) requireHoneyUser(w http.ResponseWriter, session Session) (model.HoneyUser, bool) {
	if session.UserID == "" {
		a.writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "login required"})
		return model.HoneyUser{}, false
	}
	user, ok := a.store.GetHoneyUser(session.UserID)
	if !ok {
		a.writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "login required"})
		return model.HoneyUser{}, false
	}
	return user, true
}

func (a *App) methodNotAllowed(w *captureWriter) {
	w.Header().Set("Allow", "POST")
	a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func (a *App) writeMethodNotAllowed(w *captureWriter, product string) {
	w.Header().Set("Allow", "POST")
	if product == model.ProductVLLM {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"detail": "Method Not Allowed"})
		return
	}
	if product == model.ProductOllama {
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	a.methodNotAllowed(w)
}

func streamRequested(r *http.Request, body []byte) bool {
	if r.URL.Query().Get("stream") == "true" {
		return true
	}
	if value, ok := decodeJSONObject(body); ok {
		if stream, ok := value["stream"].(bool); ok {
			return stream
		}
	}
	return false
}

func (a *App) validCatalogEntry(product, requested string) profiles.CatalogEntry {
	if entry, ok := profiles.ResolveModel(product, requested); ok {
		return entry
	}
	catalog := profiles.Catalog(product)
	return catalog[0]
}

func (a *App) validModelName(product, requested string) string {
	return a.validCatalogEntry(product, requested).ID
}

func (a *App) derivedHoneyKey(product string) string {
	return "sk-" + security.Fingerprint(a.cfg.InstanceKey, "server-info:"+product)[:40]
}
