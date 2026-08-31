package app

import (
	"sort"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

// VLLMRuntimeState is the small in-memory state exposed through the metrics
// renderer. It intentionally contains counters only; no request body or
// attacker-controlled text is retained here.
type VLLMRuntimeState struct {
	RequestsRunning       int64
	RequestsWaiting       int64
	PromptTokensTotal     uint64
	GenerationTokensTotal uint64
	RequestSuccessTotal   uint64
	RequestErrorTotal     uint64
	LastRequestAt         time.Time
	KVCacheUsage          float64
}

// OllamaActiveModel is the state needed to make /api/ps agree with a recent
// /api/generate or /api/chat call.
type OllamaActiveModel struct {
	Name       string
	LastUsedAt time.Time
	ExpiresAt  time.Time
}

// OllamaRuntimeState tracks model residency without loading a real model.
// Maps are protected by App.personaMu.
type OllamaRuntimeState struct {
	ActiveModels map[string]OllamaActiveModel
	LastUsedAt   map[string]time.Time
	ExpiresAt    map[string]time.Time
}

type personaModelCounters struct {
	PromptTokens     uint64
	GenerationTokens uint64
	Successes        uint64
	Errors           uint64
}

type personaRuntimeState struct {
	StartedAt    time.Time
	RequestCount uint64
	VLLM         VLLMRuntimeState
	Models       map[string]personaModelCounters
	Ollama       OllamaRuntimeState
}

func newPersonaRuntimeState() *personaRuntimeState {
	return &personaRuntimeState{
		StartedAt: time.Now().UTC(),
		Models:    make(map[string]personaModelCounters),
		Ollama: OllamaRuntimeState{
			ActiveModels: make(map[string]OllamaActiveModel),
			LastUsedAt:   make(map[string]time.Time),
			ExpiresAt:    make(map[string]time.Time),
		},
	}
}

func (a *App) personaStateLocked(product string) *personaRuntimeState {
	state := a.personaRuntime[product]
	if state == nil {
		state = newPersonaRuntimeState()
		a.personaRuntime[product] = state
	}
	return state
}

func (a *App) beginPersonaRequest(product, modelName string) {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaStateLocked(product)
	if product == model.ProductVLLM {
		state.VLLM.RequestsRunning++
	}
	_ = modelName
}

func (a *App) finishPersonaRequest(product, modelName string, promptTokens, generationTokens int, success bool) {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaStateLocked(product)
	counters := state.Models[modelName]
	if promptTokens > 0 {
		counters.PromptTokens += uint64(promptTokens)
	}
	if generationTokens > 0 {
		counters.GenerationTokens += uint64(generationTokens)
	}
	if success {
		counters.Successes++
	} else {
		counters.Errors++
	}
	state.Models[modelName] = counters
	state.RequestCount++
	if product != model.ProductVLLM {
		return
	}
	if state.VLLM.RequestsRunning > 0 {
		state.VLLM.RequestsRunning--
	}
	if success {
		state.VLLM.PromptTokensTotal += uint64(maxInt(0, promptTokens))
		state.VLLM.GenerationTokensTotal += uint64(maxInt(0, generationTokens))
		state.VLLM.RequestSuccessTotal++
	} else {
		state.VLLM.RequestErrorTotal++
	}
	state.VLLM.LastRequestAt = time.Now().UTC()
	usedTokens := state.VLLM.PromptTokensTotal + state.VLLM.GenerationTokensTotal
	state.VLLM.KVCacheUsage = float64(usedTokens) / 100000.0
	if state.VLLM.KVCacheUsage > 0.99 {
		state.VLLM.KVCacheUsage = 0.99
	}
}

func (a *App) notePersonaInvocation(product, modelName string, promptTokens, generationTokens int) {
	// Ollama and the legacy non-vLLM personas use this direct completion hook.
	// vLLM calls use begin/finish so the running gauge has a real request
	// lifetime.
	a.finishPersonaRequest(product, modelName, promptTokens, generationTokens, true)
}

func (a *App) notePersonaError(product, modelName string) {
	a.finishPersonaRequest(product, modelName, 0, 0, false)
}

func (a *App) vllmRuntimeSnapshot(modelName string) (VLLMRuntimeState, personaModelCounters) {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaRuntime["vllm"]
	if state == nil {
		return VLLMRuntimeState{}, personaModelCounters{}
	}
	return state.VLLM, state.Models[modelName]
}

func (a *App) markPersonaModel(product, _ string, modelName string, ttl time.Duration) {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaStateLocked(product)
	now := time.Now().UTC()
	if ttl <= 0 {
		delete(state.Ollama.ActiveModels, modelName)
		delete(state.Ollama.ExpiresAt, modelName)
		return
	}
	expiresAt := now.Add(ttl)
	state.Ollama.ActiveModels[modelName] = OllamaActiveModel{Name: modelName, LastUsedAt: now, ExpiresAt: expiresAt}
	state.Ollama.LastUsedAt[modelName] = now
	state.Ollama.ExpiresAt[modelName] = expiresAt
}

func (a *App) unmarkPersonaModel(product, _ string, modelName string) {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaRuntime[product]
	if state == nil {
		return
	}
	delete(state.Ollama.ActiveModels, modelName)
	delete(state.Ollama.ExpiresAt, modelName)
}

func (a *App) personaModelIsActive(product, _ string, modelName string) bool {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaRuntime[product]
	if state == nil {
		return false
	}
	active, ok := state.Ollama.ActiveModels[modelName]
	if !ok {
		return false
	}
	if time.Now().UTC().After(active.ExpiresAt) {
		delete(state.Ollama.ActiveModels, modelName)
		delete(state.Ollama.ExpiresAt, modelName)
		return false
	}
	return true
}

func (a *App) activePersonaModels(product, _ string) []OllamaActiveModel {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaRuntime[product]
	if state == nil {
		return nil
	}
	now := time.Now().UTC()
	result := make([]OllamaActiveModel, 0, len(state.Ollama.ActiveModels))
	for name, active := range state.Ollama.ActiveModels {
		if now.After(active.ExpiresAt) {
			delete(state.Ollama.ActiveModels, name)
			delete(state.Ollama.ExpiresAt, name)
			continue
		}
		result = append(result, active)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func (a *App) personaCounters(product, modelName string) personaModelCounters {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaRuntime[product]
	if state == nil {
		return personaModelCounters{}
	}
	return state.Models[modelName]
}
