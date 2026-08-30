package app

import "time"

type personaModelCounters struct {
	PromptTokens     uint64
	GenerationTokens uint64
	Successes        uint64
}

type personaActiveModel struct {
	Name      string
	ExpiresAt time.Time
}

type personaRuntimeState struct {
	StartedAt    time.Time
	RequestCount uint64
	Models       map[string]personaModelCounters
	Active       map[string]map[string]personaActiveModel
}

func newPersonaRuntimeState() *personaRuntimeState {
	return &personaRuntimeState{StartedAt: time.Now().UTC(), Models: make(map[string]personaModelCounters), Active: make(map[string]map[string]personaActiveModel)}
}

func (a *App) notePersonaInvocation(product, modelName string, promptTokens, generationTokens int) {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaRuntime[product]
	if state == nil {
		state = newPersonaRuntimeState()
		a.personaRuntime[product] = state
	}
	counters := state.Models[modelName]
	counters.PromptTokens += uint64(maxInt(0, promptTokens))
	counters.GenerationTokens += uint64(maxInt(0, generationTokens))
	counters.Successes++
	state.Models[modelName] = counters
	state.RequestCount++
}

func (a *App) markPersonaModel(product, sessionID, modelName string, ttl time.Duration) {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaRuntime[product]
	if state == nil {
		state = newPersonaRuntimeState()
		a.personaRuntime[product] = state
	}
	models := state.Active[sessionID]
	if models == nil {
		models = make(map[string]personaActiveModel)
		state.Active[sessionID] = models
	}
	models[modelName] = personaActiveModel{Name: modelName, ExpiresAt: time.Now().UTC().Add(ttl)}
}

func (a *App) personaModelIsActive(product, sessionID, modelName string) bool {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaRuntime[product]
	if state == nil {
		return false
	}
	models := state.Active[sessionID]
	active, ok := models[modelName]
	if !ok {
		return false
	}
	if time.Now().UTC().After(active.ExpiresAt) {
		delete(models, modelName)
		return false
	}
	return true
}

func (a *App) activePersonaModels(product, sessionID string) []personaActiveModel {
	a.personaMu.Lock()
	defer a.personaMu.Unlock()
	state := a.personaRuntime[product]
	if state == nil {
		return nil
	}
	models := state.Active[sessionID]
	now := time.Now().UTC()
	result := make([]personaActiveModel, 0, len(models))
	for name, active := range models {
		if now.After(active.ExpiresAt) {
			delete(models, name)
			continue
		}
		result = append(result, active)
	}
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
