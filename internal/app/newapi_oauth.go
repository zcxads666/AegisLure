package app

import (
	"net/http"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/oauth"
)

type newAPIOAuthSimulationRequest struct {
	Provider string `json:"provider"`
	Intent   string `json:"intent"`
	Surface  string `json:"surface"`
}

func (a *App) oauthChannelPolicy(provider oauth.Provider) (model.OAuthChannelPolicy, bool) {
	if a.store == nil {
		return model.OAuthChannelPolicy{}, false
	}
	return a.store.GetOAuthChannelPolicy(string(provider))
}

func (a *App) oauthChannelEnabled(provider oauth.Provider) bool {
	policy, ok := a.oauthChannelPolicy(provider)
	return ok && policy.Enabled
}

func fakeNewAPIOAuthClientID(provider string, enabled bool) string {
	if !enabled {
		return ""
	}
	switch provider {
	case "github":
		return "new-api-github"
	case "discord":
		return "new-api-discord"
	case "linuxdo":
		return "new-api-linuxdo"
	default:
		return ""
	}
}

func (a *App) newAPIOAuthStatus() map[string]any {
	status := map[string]any{
		"oauth_register_enabled": false,
		"github_oauth":           false,
		"github_client_id":       "",
		"discord_oauth":          false,
		"discord_client_id":      "",
		"linuxdo_oauth":          false,
		"linuxdo_client_id":      "",
	}
	for _, policy := range a.store.ListOAuthChannelPolicies() {
		enabled := policy.Enabled
		if enabled {
			status["oauth_register_enabled"] = true
		}
		switch policy.Provider {
		case "github":
			status["github_oauth"] = enabled
			status["github_client_id"] = fakeNewAPIOAuthClientID(policy.Provider, enabled)
		case "discord":
			status["discord_oauth"] = enabled
			status["discord_client_id"] = fakeNewAPIOAuthClientID(policy.Provider, enabled)
		case "linuxdo":
			status["linuxdo_oauth"] = enabled
			status["linuxdo_client_id"] = fakeNewAPIOAuthClientID(policy.Provider, enabled)
		}
	}
	return status
}

func markNewAPIOAuthObservation(obs *Observation, provider, intent, surface, channelState, outcome string) {
	obs.EventType = "newapi.oauth.simulation"
	obs.AuthOutcome = "rejected"
	obs.ExecutionOutcome = "rejected_before_dispatch"
	obs.InvocationLevel = string(model.L1)
	obs.IntentClass = "normal_use"
	zero := 0
	obs.ScoreOverride = &zero
	if obs.Metadata == nil {
		obs.Metadata = make(map[string]string)
	}
	obs.Metadata["event_type"] = "newapi.oauth.simulation"
	if provider != "" {
		obs.Metadata["oauth_provider"] = provider
	}
	if intent != "" {
		obs.Metadata["oauth_intent"] = intent
	}
	if surface != "" {
		obs.Metadata["oauth_surface"] = surface
	}
	obs.Metadata["oauth_channel_state"] = channelState
	obs.Metadata["oauth_outcome"] = outcome
	obs.Metadata["oauth_network"] = "none"
	obs.Metadata["oauth_credentials"] = "not_collected"
}

func (a *App) writeNewAPIOAuthNotFound(w *captureWriter) {
	// Keep direct OAuth-shaped paths on the same generic New API error
	// contract as the regular broker route.
	a.writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"message": "Not found", "type": "invalid_request_error"}})
}

func (a *App) writeNewAPIOAuthRejected(w *captureWriter, status int) {
	a.writeJSON(w, status, map[string]any{
		"success": false,
		"message": "OAuth login could not be completed",
		"code":    "OAUTH_UNAVAILABLE",
	})
}

func (a *App) handleNewAPIOAuthSimulation(w *captureWriter, r *http.Request, body []byte, obs *Observation) {
	var request newAPIOAuthSimulationRequest
	if err := decodeStrictValue(body, &request); err != nil {
		markNewAPIOAuthObservation(obs, "", "", "", "unknown", "invalid_request")
		a.writeNewAPIOAuthRejected(w, http.StatusBadRequest)
		return
	}
	provider, ok := oauth.ParseProvider(request.Provider)
	if !ok {
		markNewAPIOAuthObservation(obs, "", "", "", "unknown", "invalid_request")
		a.writeNewAPIOAuthRejected(w, http.StatusBadRequest)
		return
	}
	intent := strings.ToLower(strings.TrimSpace(request.Intent))
	if intent == "" {
		intent = "login"
	}
	if intent != "login" && intent != "register" && intent != "bind" {
		markNewAPIOAuthObservation(obs, string(provider), "", "", "unknown", "invalid_request")
		a.writeNewAPIOAuthRejected(w, http.StatusBadRequest)
		return
	}
	surface := strings.ToLower(strings.TrimSpace(request.Surface))
	if surface == "" {
		surface = "register"
	}
	if surface != "register" && surface != "login" {
		markNewAPIOAuthObservation(obs, string(provider), intent, "", "unknown", "invalid_request")
		a.writeNewAPIOAuthRejected(w, http.StatusBadRequest)
		return
	}
	if !a.allowRate("newapi-oauth-simulation-ip:"+requestSourceIP(r), 30, time.Minute) {
		markNewAPIOAuthObservation(obs, string(provider), intent, surface, "rate_limited", "rate_limited")
		obs.ExtraScore += 10
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_oauth_simulation_rate_limited")
		a.writeNewAPIOAuthRejected(w, http.StatusTooManyRequests)
		return
	}
	if !a.oauthChannelEnabled(provider) {
		markNewAPIOAuthObservation(obs, string(provider), intent, surface, "disabled", "disabled")
		a.writeNewAPIOAuthNotFound(w)
		return
	}
	markNewAPIOAuthObservation(obs, string(provider), intent, surface, "enabled", "rejected")
	a.writeNewAPIOAuthRejected(w, http.StatusUnauthorized)
}
