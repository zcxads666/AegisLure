package app

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
)

const (
	sub2APIDefaultQuota     int64 = 1_000_000
	sub2APIRedeemQuota      int64 = 100_000
	sub2APIMaxKeyModels           = 64
	sub2APIMaxKeyAllowIPs         = 64
	sub2APIGatewayErrorType       = "invalid_request_error"
)

func (a *App) handleSub2API(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	if obs.Metadata == nil {
		obs.Metadata = make(map[string]string)
	}
	obs.Metadata["persona"] = "sub2api"
	obs.Metadata["outbound_network"] = "none"
	obs.Metadata["raw_request_redacted"] = "true"
	if session.UserID != "" {
		// Session IDs are transport-local. Keep a bounded internal account link as
		// well so a dashboard can aggregate calls made by another client using the
		// same synthetic account.
		obs.Metadata["honey_user_id"] = session.UserID
	}
	obs.RawRequest = redactSub2APIRawRequest(obs.RawRequest, body)

	switch obs.RouteTemplate {
	case "sub2api.spa":
		a.writeSub2APIIndex(w, r, profile)
	case "sub2api.asset":
		a.writeSub2APIAsset(w, r)
	case "sub2api.logo":
		a.writeSub2APILogo(w, r)
	case "sub2api.health":
		obs.EventType = "sub2api.health.checked"
		a.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	case "sub2api.setup.status":
		obs.EventType = "sub2api.setup.status"
		sub2APISuccess(a, w, http.StatusOK, map[string]any{"needs_setup": false, "step": "completed"})
	case "sub2api.event.logging":
		obs.EventType = "sub2api.event_logging.batch"
		sub2APISuccess(a, w, http.StatusOK, map[string]any{"accepted": true, "count": 0})
	case "sub2api.settings.public":
		obs.EventType = "sub2api.settings.public"
		a.sub2APIPublicSettings(w, profile)
	case "sub2api.model.plaza":
		a.handleSub2APIModelPlaza(w, session, obs)
	case "sub2api.auth.register", "sub2api.auth.login", "sub2api.auth.login.2fa", "sub2api.auth.refresh", "sub2api.auth.logout", "sub2api.auth.me", "sub2api.auth.revoke_sessions", "sub2api.auth.bind_token", "sub2api.auth.auxiliary":
		a.handleSub2APIAuth(w, r, profile, session, body, obs)
	case "sub2api.auth.oauth":
		a.handleSub2APIOAuth(w, r, profile, session, obs)
	case "sub2api.user.profile", "sub2api.user.update", "sub2api.user.password", "sub2api.key.list", "sub2api.key.get", "sub2api.key.create", "sub2api.key.update", "sub2api.key.delete", "sub2api.groups.available", "sub2api.channels.available", "sub2api.usage.list", "sub2api.usage.stats", "sub2api.usage.dashboard.stats", "sub2api.usage.dashboard.trend", "sub2api.usage.dashboard.models", "sub2api.usage.dashboard.snapshot", "sub2api.usage.detail", "sub2api.redeem", "sub2api.redeem.history", "sub2api.subscriptions", "sub2api.models":
		a.handleSub2APIPanel(w, r, profile, session, body, obs)
	case "sub2api.gateway.models", "sub2api.gateway.codex.models", "sub2api.gateway.model", "sub2api.gateway.billing", "sub2api.gateway.messages", "sub2api.gateway.count_tokens", "sub2api.gateway.chat", "sub2api.gateway.responses", "sub2api.gateway.embeddings", "sub2api.gateway.completions", "sub2api.gateway.alpha_search", "sub2api.gateway.usage", "sub2api.gateway.live":
		a.handleSub2APIGateway(w, r, profile, session, body, obs)
	default:
		sub2APIError(w, http.StatusNotFound, "Not Found")
	}
}

func (a *App) handleSub2APIModelPlaza(w *captureWriter, session Session, obs *Observation) {
	obs.EventType = "sub2api.model.plaza.viewed"
	audience := "guest"
	if session.UserID != "" {
		audience = "user"
	}
	catalog := a.catalogForSession(model.ProductSub2API, audience, session)
	sub2APISuccess(a, w, http.StatusOK, sub2APIModelPlaza(catalog))
}

func sub2APISuccess(a *App, w http.ResponseWriter, status int, data any) {
	a.writeJSON(w, status, map[string]any{"code": 0, "message": "success", "data": data})
}

func sub2APIError(w http.ResponseWriter, status int, message string) {
	if message == "" {
		message = http.StatusText(status)
	}
	// This envelope follows backend/internal/pkg/response/response.go in the
	// local Sub2API reference checkout.
	if cw, ok := w.(*captureWriter); ok {
		cw.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	encoded := map[string]any{"code": status, "message": message}
	if cw, ok := w.(*captureWriter); ok {
		// writeJSON is the common boundary writer and keeps response accounting.
		appWriteJSON(cw, status, encoded)
		return
	}
	_ = encoded
}

// appWriteJSON is only used by sub2APIError to avoid threading App through a
// small protocol helper. All normal calls use App.writeJSON directly.
func appWriteJSON(w *captureWriter, status int, value any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(status)
	data, _ := json.Marshal(value)
	_, _ = w.Write(data)
}

func (a *App) sub2APIPublicSettings(w *captureWriter, profile profiles.Profile) {
	policyEnabled := func(provider string) bool {
		policy, ok := a.store.GetSub2APIOAuthChannelPolicy(provider)
		return ok && policy.Enabled
	}
	persona := profile.Persona.Sub2API
	settings := map[string]any{
		"registration_enabled": true, "email_verify_enabled": false, "force_email_on_third_party_signup": false,
		"registration_email_suffix_whitelist": []string{}, "registration_email_domain_quota_enabled": false,
		"promo_code_enabled": true, "password_reset_enabled": true, "invitation_code_enabled": false,
		"totp_enabled": false, "passkey_enabled": false, "login_agreement_enabled": false,
		"login_agreement_mode": "", "login_agreement_updated_at": "", "login_agreement_revision": "", "login_agreement_documents": []any{},
		"turnstile_enabled": false, "turnstile_site_key": "", "tencent_captcha_enabled": false, "tencent_captcha_app_id": "", "tencent_captcha_region": "",
		"aliyun_captcha_enabled": false, "aliyun_captcha_scene_id": "", "aliyun_captcha_prefix": "", "aliyun_captcha_region": "",
		"site_name": persona.SiteName, "site_logo": "", "site_subtitle": persona.SiteSubtitle, "api_base_url": "", "contact_info": "", "doc_url": "", "home_content": "",
		"compact_home_enabled": false, "hide_ccs_import_button": false, "purchase_subscription_enabled": false, "purchase_subscription_url": "",
		"table_default_page_size": 20, "table_page_size_options": []int{10, 20, 50, 100}, "custom_menu_items": []any{}, "custom_endpoints": []any{},
		"dingtalk_oauth_enabled": policyEnabled("dingtalk"), "linuxdo_oauth_enabled": policyEnabled("linuxdo"), "wechat_oauth_enabled": policyEnabled("wechat"),
		"wechat_oauth_open_enabled": policyEnabled("wechat"), "wechat_oauth_mp_enabled": false, "wechat_oauth_mobile_enabled": false,
		"oidc_oauth_enabled": policyEnabled("oidc"), "oidc_oauth_provider_name": "OIDC", "github_oauth_enabled": policyEnabled("github"), "google_oauth_enabled": policyEnabled("google"),
		"backend_mode_enabled": false, "payment_enabled": false, "version": persona.Version, "server_timezone": model.InteractionChainTimezone, "server_utc_offset": "+08:00",
		"balance_low_notify_enabled": false, "account_quota_notify_enabled": false, "balance_low_notify_threshold": 0, "balance_low_notify_recharge_url": "",
		"channel_monitor_enabled": false, "channel_monitor_mode": "", "channel_monitor_default_interval_seconds": 0, "channel_monitor_hide_throughput": false, "channel_monitor_show_quota": false,
		"available_channels_enabled": true, "model_plaza_enabled": true, "model_plaza_require_auth": false, "plugin_management_enabled": false,
		"affiliate_enabled": false, "risk_control_enabled": true, "allow_user_view_error_requests": false,
	}
	sub2APISuccess(a, w, http.StatusOK, settings)
}

func (a *App) handleSub2APIAuth(w *captureWriter, r *http.Request, _ profiles.Profile, session Session, body []byte, obs *Observation) {
	values := requestValues(r, body)
	switch obs.RouteTemplate {
	case "sub2api.auth.register":
		a.sub2APIRegister(w, r, session, values, obs)
	case "sub2api.auth.login":
		a.sub2APILogin(w, r, session, values, obs)
	case "sub2api.auth.login.2fa":
		if user, ok := a.sub2APIRequireUser(w, session, obs); ok {
			obs.EventType = "sub2api.user.login.2fa.success"
			sub2APISuccess(a, w, http.StatusOK, a.sub2APIAuthBundle(user, session))
		}
	case "sub2api.auth.refresh":
		if user, ok := a.sub2APIRequireUser(w, session, obs); ok {
			obs.EventType = "sub2api.user.login.refresh"
			sub2APISuccess(a, w, http.StatusOK, a.sub2APIAuthBundle(user, session))
		}
	case "sub2api.auth.logout":
		obs.EventType = "sub2api.user.logout"
		a.clearSessionUser(session.ID)
		sub2APISuccess(a, w, http.StatusOK, map[string]any{"logged_out": true})
	case "sub2api.auth.revoke_sessions":
		if user, ok := a.sub2APIRequireUser(w, session, obs); ok {
			a.clearAllSessionUsers(user.ID)
			obs.EventType = "sub2api.user.sessions.revoked"
			sub2APISuccess(a, w, http.StatusOK, map[string]any{"revoked": true})
		}
	case "sub2api.auth.me":
		if user, ok := a.sub2APIRequireUser(w, session, obs); ok {
			obs.EventType = "sub2api.user.me"
			sub2APISuccess(a, w, http.StatusOK, a.sub2APIUserView(user))
		}
	case "sub2api.auth.bind_token":
		if _, ok := a.sub2APIRequireUser(w, session, obs); ok {
			obs.EventType = "sub2api.auth.bind_token.accepted"
			// The upstream endpoint prepares a browser-only binding token. Keep
			// the protocol shape local and synthetic; no provider token is read.
			sub2APISuccess(a, w, http.StatusOK, map[string]any{"accepted": true})
		}
	case "sub2api.auth.auxiliary":
		obs.EventType = "sub2api.auth.auxiliary"
		// Verification, reset, and bind-token requests are accepted as local
		// protocol shapes only. No mail, provider, token, or network action is
		// performed.
		sub2APISuccess(a, w, http.StatusOK, map[string]any{"accepted": true})
	default:
		sub2APIError(w, http.StatusNotFound, "Not Found")
	}
}

func (a *App) sub2APIRegister(w *captureWriter, r *http.Request, session Session, values map[string]string, obs *Observation) {
	email, emailOK := normalizeHoneyEmail(values["email"])
	password := values["password"]
	// The official Sub2API registration contract accepts passwords from six
	// characters onward (frontend validation and backend binding both use 6).
	if email == "" || !emailOK || password == "" || len([]rune(password)) < 6 || len([]rune(password)) > 1024 {
		obs.EventType = "sub2api.user.register.failed"
		obs.AuthOutcome = "invalid"
		obs.ExtraScore += 20
		obs.ExtraReasons = append(obs.ExtraReasons, "sub2api_registration_shape_probe")
		sub2APIError(w, http.StatusBadRequest, "invalid registration request")
		return
	}
	if !a.allowRate("sub2api-register-ip:"+requestSourceIP(r), 8, time.Minute) {
		obs.EventType = "sub2api.user.register.failed"
		obs.ExtraScore += 20
		sub2APIError(w, http.StatusTooManyRequests, "registration temporarily unavailable")
		return
	}
	setSub2APICredentialMetadata(obs, a.cfg.InstanceKey, email, password)
	usernameFP := security.Fingerprint(a.cfg.InstanceKey, email)
	if _, exists := a.store.FindHoneyUser(usernameFP); exists {
		obs.EventType = "sub2api.user.register.failed"
		obs.AuthOutcome = "invalid"
		obs.ExtraScore += 25
		obs.ExtraReasons = append(obs.ExtraReasons, "sub2api_registration_duplicate_attempt")
		sub2APIError(w, http.StatusBadRequest, "invalid registration request")
		return
	}
	lengthBucket, passwordClasses, weakClass := passwordProfile(password)
	now := time.Now().UTC()
	user := model.HoneyUser{
		ID: "hu_" + security.MustRandomToken(10), InstanceID: a.cfg.InstanceID, UsernameFP: usernameFP,
		UsernameHint: "user@" + emailDomain(email), EmailLocalFP: emailLocalFingerprint(a.cfg.InstanceKey, email), EmailDomain: emailDomain(email),
		PasswordFP: security.Fingerprint(a.cfg.InstanceKey, password), PasswordLengthBucket: lengthBucket, PasswordClasses: passwordClasses,
		PasswordWeakClass: weakClass, VirtualQuota: sub2APIDefaultQuota, CreatedAt: now, LastSeen: now,
	}
	if err := a.store.CreateHoneyUser(user); err != nil {
		obs.EventType = "sub2api.user.register.failed"
		obs.AuthOutcome = "invalid"
		sub2APIError(w, http.StatusBadRequest, "invalid registration request")
		return
	}
	a.setSessionUser(session.ID, user.ID)
	obs.EventType = "sub2api.user.register.success"
	obs.AuthOutcome = "session_authenticated"
	sub2APISuccess(a, w, http.StatusOK, a.sub2APIAuthBundle(user, session))
}

func (a *App) sub2APILogin(w *captureWriter, r *http.Request, session Session, values map[string]string, obs *Observation) {
	email, emailOK := normalizeHoneyEmail(values["email"])
	password := values["password"]
	if email == "" || !emailOK || password == "" || len([]rune(password)) > 1024 {
		obs.EventType = "sub2api.user.login.failed"
		obs.AuthOutcome = "invalid"
		obs.ExtraScore += 15
		sub2APIError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	setSub2APICredentialMetadata(obs, a.cfg.InstanceKey, email, password)
	user, found := a.store.FindHoneyUser(security.Fingerprint(a.cfg.InstanceKey, email))
	if !found || user.PasswordFP != security.Fingerprint(a.cfg.InstanceKey, password) {
		obs.EventType = "sub2api.user.login.failed"
		obs.AuthOutcome = "invalid"
		obs.ExtraScore += 20
		sub2APIError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	_ = a.store.TouchHoneyUser(user.ID, func(current *model.HoneyUser) { current.LastSeen = time.Now().UTC() })
	a.setSessionUser(session.ID, user.ID)
	user, _ = a.store.GetHoneyUser(user.ID)
	obs.EventType = "sub2api.user.login.success"
	obs.AuthOutcome = "session_authenticated"
	sub2APISuccess(a, w, http.StatusOK, a.sub2APIAuthBundle(user, session))
}

func setSub2APICredentialMetadata(obs *Observation, key, email, password string) {
	if obs.Metadata == nil {
		obs.Metadata = make(map[string]string)
	}
	obs.Metadata["credential_email_fp"] = security.Fingerprint(key, email)
	obs.Metadata["credential_password_fp"] = security.Fingerprint(key, password)
	obs.Metadata["credential_raw_retained"] = "false"
}

func (a *App) sub2APIAuthBundle(user model.HoneyUser, session Session) map[string]any {
	accessToken := a.issueSub2APIAccessToken(user.ID)
	return map[string]any{
		"access_token": accessToken, "refresh_token": security.MustRandomToken(32), "expires_in": 3600, "token_type": "Bearer",
		"user": a.sub2APIUserView(user), "session": map[string]any{"id": session.ID, "expires_in": 1800},
	}
}

func (a *App) issueSub2APIAccessToken(userID string) string {
	token := security.MustRandomToken(32)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sub2APIAccessTokens == nil {
		a.sub2APIAccessTokens = make(map[string]sub2APIAccessToken)
	}
	now := time.Now().UTC()
	for fingerprint, issued := range a.sub2APIAccessTokens {
		if !issued.ExpiresAt.After(now) {
			delete(a.sub2APIAccessTokens, fingerprint)
		}
	}
	if len(a.sub2APIAccessTokens) >= 4096 {
		for fingerprint := range a.sub2APIAccessTokens {
			delete(a.sub2APIAccessTokens, fingerprint)
			if len(a.sub2APIAccessTokens) < 3072 {
				break
			}
		}
	}
	a.sub2APIAccessTokens[security.Fingerprint(a.cfg.InstanceKey, token)] = sub2APIAccessToken{UserID: userID, ExpiresAt: now.Add(time.Hour)}
	return token
}

func (a *App) sub2APIAccessTokenUserIDLocked(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(value) < 7 || !strings.EqualFold(value[:7], "bearer ") {
		return ""
	}
	fingerprint := security.Fingerprint(a.cfg.InstanceKey, strings.TrimSpace(value[7:]))
	issued, ok := a.sub2APIAccessTokens[fingerprint]
	if !ok {
		return ""
	}
	if !issued.ExpiresAt.After(time.Now().UTC()) {
		delete(a.sub2APIAccessTokens, fingerprint)
		return ""
	}
	return issued.UserID
}

func (a *App) sub2APIUserView(user model.HoneyUser) map[string]any {
	updated := user.LastSeen
	if updated.IsZero() {
		updated = user.CreatedAt
	}
	return map[string]any{
		"id": newAPIPublicID(user.ID), "email": "user@" + user.EmailDomain, "username": user.UsernameHint, "role": "user", "balance": float64(user.VirtualQuota) / 1_000_000,
		"frozen_balance": 0, "concurrency": 0, "status": "active", "allowed_groups": []int64{1}, "last_active_at": updated, "created_at": user.CreatedAt, "updated_at": updated,
		"rpm_limit": 0,
	}
}

func (a *App) sub2APIRequireUser(w *captureWriter, session Session, obs *Observation) (model.HoneyUser, bool) {
	if session.UserID == "" {
		obs.AuthOutcome = "missing"
		obs.EventType = "sub2api.auth.session.failed"
		sub2APIError(w, http.StatusUnauthorized, "authentication required")
		return model.HoneyUser{}, false
	}
	user, ok := a.store.GetHoneyUser(session.UserID)
	if !ok {
		obs.AuthOutcome = "invalid"
		obs.EventType = "sub2api.auth.session.failed"
		sub2APIError(w, http.StatusUnauthorized, "authentication required")
		return model.HoneyUser{}, false
	}
	obs.AuthOutcome = "session_authenticated"
	return user, true
}

func (a *App) handleSub2APIOAuth(w *captureWriter, r *http.Request, _ profiles.Profile, _ Session, obs *Observation) {
	provider, action, ok := sub2APIOAuthPath(r.URL.Path)
	obs.EventType = "sub2api.auth.oauth"
	obs.Metadata["oauth_surface"] = "sub2api"
	obs.Metadata["oauth_network"] = "none"
	obs.Metadata["oauth_credentials"] = "not_collected"
	if !ok {
		obs.AuthOutcome = "invalid"
		obs.ExtraScore += 20
		sub2APIError(w, http.StatusNotFound, "Not Found")
		return
	}
	obs.Metadata["oauth_provider"] = provider
	obs.Metadata["oauth_intent"] = action
	if provider == "pending" {
		obs.AuthOutcome = "invalid"
		obs.ExtraScore += 15
		obs.Metadata["oauth_channel_state"] = "local_only"
		obs.Metadata["oauth_policy_mode"] = "pending_approval"
		obs.Metadata["oauth_outcome"] = "synthetic_pending_flow"
		sub2APIError(w, http.StatusUnauthorized, "OAuth completion is not configured")
		return
	}
	policy, policyOK := a.store.GetSub2APIOAuthChannelPolicy(provider)
	if !policyOK {
		obs.AuthOutcome = "invalid"
		obs.ExtraScore += 20
		sub2APIError(w, http.StatusNotFound, "Not Found")
		return
	}
	obs.Metadata["oauth_channel_state"] = policy.CrossSite
	obs.Metadata["oauth_policy_mode"] = policy.Mode
	if state := strings.TrimSpace(r.URL.Query().Get("state")); state != "" {
		obs.Metadata["oauth_state_fp"] = security.Fingerprint(a.cfg.InstanceKey, state)
	}
	if code := strings.TrimSpace(r.URL.Query().Get("code")); code != "" {
		obs.Metadata["oauth_code_fp"] = security.Fingerprint(a.cfg.InstanceKey, code)
	}
	if !policy.Enabled {
		obs.AuthOutcome = "invalid"
		obs.ExtraScore += 15
		obs.Metadata["oauth_outcome"] = "disabled"
		sub2APIError(w, http.StatusNotFound, "Not Found")
		return
	}
	// Enabled means the local UI flag is on. It never authorizes an outbound
	// redirect or accepts a provider token; this keeps the provider channel
	// auditable without turning the public listener into an OAuth proxy.
	obs.AuthOutcome = "invalid"
	obs.ExtraScore += 15
	obs.Metadata["oauth_outcome"] = "local_configuration_required"
	sub2APIError(w, http.StatusUnauthorized, "OAuth provider is not configured")
}

func sub2APIOAuthPath(path string) (provider, action string, ok bool) {
	relative := strings.Trim(strings.TrimPrefix(path, "/api/v1/auth/oauth/"), "/")
	parts := strings.Split(relative, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	if parts[0] == "pending" {
		action = strings.Join(parts[1:], "/")
		if containsString([]string{"exchange", "send-verify-code", "create-account", "bind-login"}, action) {
			return "pending", action, true
		}
		return "", "", false
	}
	if !containsString(model.Sub2APIOAuthProviders(), parts[0]) {
		return "", "", false
	}
	action = strings.Join(parts[1:], "/")
	switch action {
	case "start", "callback", "bind/start", "complete", "complete-registration", "bind-login", "create-account":
		return parts[0], action, true
	case "payment/start", "payment/callback":
		if parts[0] == "wechat" {
			return parts[0], action, true
		}
	default:
		return "", "", false
	}
	return "", "", false
}

func (a *App) handleSub2APIPanel(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	switch obs.RouteTemplate {
	case "sub2api.user.profile", "sub2api.user.update", "sub2api.user.password", "sub2api.key.list", "sub2api.key.get", "sub2api.key.create", "sub2api.key.update", "sub2api.key.delete", "sub2api.groups.available", "sub2api.channels.available", "sub2api.usage.list", "sub2api.usage.stats", "sub2api.usage.dashboard.stats", "sub2api.usage.dashboard.trend", "sub2api.usage.dashboard.models", "sub2api.usage.dashboard.snapshot", "sub2api.usage.detail", "sub2api.redeem", "sub2api.redeem.history", "sub2api.subscriptions":
		if _, ok := a.sub2APIRequireUser(w, session, obs); !ok {
			return
		}
	}
	switch obs.RouteTemplate {
	case "sub2api.user.profile":
		user, _ := a.store.GetHoneyUser(session.UserID)
		obs.EventType = "sub2api.user.profile.viewed"
		sub2APISuccess(a, w, http.StatusOK, a.sub2APIUserView(user))
	case "sub2api.user.update":
		user, _ := a.store.GetHoneyUser(session.UserID)
		obs.EventType = "sub2api.user.profile.updated"
		_ = a.store.TouchHoneyUser(user.ID, func(current *model.HoneyUser) { current.LastSeen = time.Now().UTC() })
		user, _ = a.store.GetHoneyUser(user.ID)
		sub2APISuccess(a, w, http.StatusOK, a.sub2APIUserView(user))
	case "sub2api.user.password":
		a.sub2APIChangePassword(w, body, session, obs)
	case "sub2api.key.list", "sub2api.key.get", "sub2api.key.create", "sub2api.key.update", "sub2api.key.delete":
		a.handleSub2APIKeys(w, r, body, session, obs)
	case "sub2api.groups.available":
		obs.EventType = "sub2api.groups.listed"
		sub2APISuccess(a, w, http.StatusOK, []any{map[string]any{"id": 1, "name": "default", "description": "Default API group", "platform": "openai", "rate_multiplier": 1, "status": "active", "subscription_type": "none", "rpm_limit": 0}})
	case "sub2api.channels.available":
		obs.EventType = "sub2api.channels.listed"
		catalog := a.catalogForSession(model.ProductSub2API, "user", session)
		sub2APISuccess(a, w, http.StatusOK, sub2APIAvailableChannels(catalog))
	case "sub2api.usage.list", "sub2api.usage.stats", "sub2api.usage.dashboard.stats", "sub2api.usage.dashboard.trend", "sub2api.usage.dashboard.models", "sub2api.usage.dashboard.snapshot", "sub2api.usage.detail":
		a.handleSub2APIUsage(w, r, session, session.UserID, obs)
	case "sub2api.redeem":
		a.handleSub2APIRedeem(w, r, body, profile, session, obs)
	case "sub2api.redeem.history":
		a.handleSub2APIRedeemHistory(w, session, obs)
	case "sub2api.subscriptions":
		obs.EventType = "sub2api.subscriptions.listed"
		sub2APISuccess(a, w, http.StatusOK, []any{})
	case "sub2api.models":
		obs.EventType = "sub2api.models.listed"
		catalog := a.catalogForSession(model.ProductSub2API, "user", session)
		sub2APISuccess(a, w, http.StatusOK, map[string]any{"object": "list", "data": profiles.OpenAIModelCardsForCatalog(a.cfg.InstanceKey, catalog, "sub2api")})
	default:
		sub2APIError(w, http.StatusNotFound, "Not Found")
	}
}

// sub2APIAvailableChannels exposes the same user-facing DTO shape as the
// official /api/v1/channels/available endpoint.
func sub2APIAvailableChannels(catalog []profiles.CatalogEntry) []map[string]any {
	return []map[string]any{
		sub2APIAvailableChannel(
			"OpenAI",
			[]string{"gpt-6-astra", "gpt-4o-mini"},
			catalog,
		),
		sub2APIAvailableChannel(
			"OpenAI Codex",
			[]string{"gpt-5.3-codex"},
			catalog,
		),
	}
}

func sub2APIAvailableChannel(name string, modelIDs []string, catalog []profiles.CatalogEntry) map[string]any {
	models := make([]any, 0, len(modelIDs))
	for _, modelID := range modelIDs {
		entry, ok := sub2APICatalogEntry(catalog, modelID)
		if !ok {
			continue
		}
		models = append(models, map[string]any{
			"name":     entry.ID,
			"platform": "openai",
			"pricing":  sub2APIModelPricing(entry.ID),
		})
	}
	return map[string]any{
		"name":        name,
		"description": "",
		"platforms": []any{map[string]any{
			"platform":         "openai",
			"groups":           []any{sub2APIDefaultGroup()},
			"supported_models": models,
		}},
	}
}

func sub2APIDefaultGroup() map[string]any {
	return map[string]any{
		"id":                   1,
		"name":                 "default",
		"platform":             "openai",
		"subscription_type":    "standard",
		"rate_multiplier":      1.0,
		"peak_rate_enabled":    false,
		"peak_start":           "",
		"peak_end":             "",
		"peak_rate_multiplier": 1.0,
		"is_exclusive":         false,
	}
}

func sub2APIModelPricing(modelID string) map[string]any {
	var inputPrice, outputPrice, cacheReadPrice float64
	switch modelID {
	case "gpt-4o-mini":
		inputPrice, outputPrice, cacheReadPrice = 1.5e-7, 6e-7, 7.5e-8
	case "gpt-5.3-codex":
		inputPrice, outputPrice, cacheReadPrice = 1.75e-6, 1.4e-5, 1.75e-7
	default:
		return nil
	}
	return map[string]any{
		"billing_mode":         "token",
		"input_price":          inputPrice,
		"output_price":         outputPrice,
		"cache_write_price":    nil,
		"cache_write_1h_price": nil,
		"cache_read_price":     cacheReadPrice,
		"image_input_price":    nil,
		"image_output_price":   nil,
		"per_request_price":    nil,
		"intervals":            []any{},
	}
}

func sub2APIOfficialModelPricing(modelID string) map[string]any {
	pricing := sub2APIModelPricing(modelID)
	if pricing == nil {
		return nil
	}
	result := map[string]any{
		"input_price":       pricing["input_price"],
		"output_price":      pricing["output_price"],
		"cache_write_price": pricing["cache_write_price"],
		"cache_read_price":  pricing["cache_read_price"],
	}
	if price := pricing["cache_write_1h_price"]; price != nil {
		result["cache_write_1h_price"] = price
	}
	return result
}

func sub2APIModelPlaza(catalog []profiles.CatalogEntry) map[string]any {
	models := make([]any, 0, 3)
	for _, modelID := range []string{"gpt-6-astra", "gpt-4o-mini", "gpt-5.3-codex"} {
		entry, ok := sub2APICatalogEntry(catalog, modelID)
		if !ok {
			continue
		}
		models = append(models, map[string]any{
			"name":             entry.ID,
			"platform":         "openai",
			"pricing":          sub2APIModelPricing(entry.ID),
			"official_pricing": sub2APIOfficialModelPricing(entry.ID),
		})
	}
	groups := make([]any, 0, 1)
	if len(models) > 0 {
		groups = append(groups, map[string]any{
			"id":                           1,
			"name":                         "default",
			"description":                  "",
			"platform":                     "openai",
			"subscription_type":            "standard",
			"rate_multiplier":              1.0,
			"peak_rate_enabled":            false,
			"peak_start":                   "",
			"peak_end":                     "",
			"peak_rate_multiplier":         1.0,
			"is_exclusive":                 false,
			"image_rate_independent":       false,
			"image_rate_multiplier":        1.0,
			"long_context_pricing_enabled": true,
			"models":                       models,
		})
	}
	return map[string]any{"description": "", "groups": groups}
}

func sub2APICatalogEntry(catalog []profiles.CatalogEntry, requested string) (profiles.CatalogEntry, bool) {
	requested = strings.TrimSpace(requested)
	for _, entry := range catalog {
		if entry.ID == requested {
			return entry, true
		}
		for _, alias := range entry.Aliases {
			if alias == requested {
				return entry, true
			}
		}
	}
	return profiles.CatalogEntry{}, false
}

// sub2APICodexModelsManifest returns the official Codex model-picker shape.
func sub2APICodexModelsManifest(catalog []profiles.CatalogEntry) map[string]any {
	models := make([]any, 0, len(catalog))
	for _, entry := range catalog {
		if entry.ID == "" || (entry.Provider != "openai" && entry.Provider != "openai-codex") {
			continue
		}
		models = append(models, sub2APICodexModelDescriptor(entry))
	}
	return map[string]any{"models": models}
}

func sub2APICodexModelDescriptor(entry profiles.CatalogEntry) map[string]any {
	defaultReasoning, reasoningLevels := sub2APICodexReasoning(entry)
	contextWindow := entry.VirtualContextTokens
	if contextWindow <= 0 {
		contextWindow = 272000
	}
	inputModalities := []string{"text"}
	if containsString(entry.Capabilities, "vision") {
		inputModalities = []string{"text", "image"}
	}
	return map[string]any{
		"slug":                       entry.ID,
		"display_name":               entry.DisplayName,
		"description":                "",
		"default_reasoning_level":    defaultReasoning,
		"supported_reasoning_levels": reasoningLevels,
		"shell_type":                 "unified_exec",
		"visibility":                 "list",
		"supported_in_api":           true,
		"priority":                   50,
		"additional_speed_tiers":     []string{},
		"service_tiers":              []any{},
		"default_service_tier":       nil,
		"availability_nux":           nil,
		"upgrade":                    nil,
		"model_messages": map[string]any{
			"instructions_template":  sub2APICodexInstructionsTemplate(entry.ID),
			"instructions_variables": []any{},
			"approvals":              nil,
			"collaboration_modes":    nil,
			"auto_review":            nil,
			"permissions":            nil,
			"multi_agent":            nil,
			"token_budget":           nil,
			"guardian_v2":            nil,
		},
		"include_skills_usage_instructions":    false,
		"include_plugin_usage_instructions":    false,
		"include_apps_usage_instructions":      false,
		"supports_reasoning_summary_parameter": true,
		"default_reasoning_summary":            "auto",
		"support_verbosity":                    false,
		"default_verbosity":                    nil,
		"apply_patch_tool_type":                nil,
		"web_search_tool_type":                 "text",
		"truncation_policy":                    map[string]any{"mode": "tokens", "limit": 10000},
		"supports_image_detail_original":       containsString(entry.Capabilities, "vision"),
		"supports_parallel_tool_calls":         containsString(entry.Capabilities, "tools"),
		"context_window":                       contextWindow,
		"max_context_window":                   contextWindow,
		"auto_compact_token_limit":             nil,
		"comp_hash":                            nil,
		"effective_context_window_percent":     95,
		"experimental_supported_tools":         []string{},
		"input_modalities":                     inputModalities,
		"supports_search_tool":                 false,
		"use_responses_lite":                   false,
		"node_repl_auto_review_required":       false,
		"node_repl_disabled":                   false,
		"auto_review_model_override":           nil,
		"model_specialty":                      nil,
		"tool_mode":                            nil,
		"multi_agent_version":                  nil,
	}
}

func sub2APICodexReasoning(entry profiles.CatalogEntry) (string, []map[string]any) {
	if !containsString(entry.Capabilities, "reasoning") && !containsString(entry.Capabilities, "code") {
		return "none", []map[string]any{{"effort": "none", "description": "Use the model's default behavior without configurable reasoning"}}
	}
	levels := []map[string]any{
		{"effort": "low", "description": "Fast responses with lighter reasoning"},
		{"effort": "medium", "description": "Balanced reasoning for most coding tasks"},
		{"effort": "high", "description": "Greater reasoning depth for coding and agent tasks"},
		{"effort": "xhigh", "description": "Extra-high reasoning depth for difficult tasks"},
	}
	return "medium", levels
}

func sub2APICodexInstructionsTemplate(modelID string) string {
	if strings.Contains(strings.ToLower(strings.TrimSpace(modelID)), "codex") {
		return "You are Codex, based on GPT-5."
	}
	return "You are Codex, a coding agent based on GPT-5."
}

func sub2APIAnnotateClientSurface(r *http.Request, obs *Observation) {
	if r == nil || obs == nil || obs.Metadata == nil {
		return
	}
	path := r.URL.Path
	codex := strings.HasPrefix(path, "/backend-api/codex/") ||
		(obs.RouteTemplate == "sub2api.gateway.models" && strings.TrimSpace(r.URL.Query().Get("client_version")) != "")
	if !codex {
		return
	}
	obs.Metadata["client_surface"] = "codex"
	transport := "responses"
	switch {
	case strings.HasSuffix(path, "/models"):
		transport = "models"
	case strings.Contains(path, "/alpha/search"):
		transport = "alpha_search"
	case strings.Contains(path, "/realtime/"):
		transport = "realtime"
	}
	obs.Metadata["codex_transport"] = transport
	if version := strings.TrimSpace(r.URL.Query().Get("client_version")); version != "" {
		obs.Metadata["codex_client_version"] = security.RedactPreview(version, 64)
	}
}

func annotateSub2APIRequestMetadata(obs *Observation, value map[string]any, requestedModel string) {
	if obs == nil {
		return
	}
	if obs.Metadata == nil {
		obs.Metadata = make(map[string]string)
	}
	if requestedModel = strings.TrimSpace(requestedModel); requestedModel != "" {
		obs.Metadata["model_requested"] = requestedModel
	}
	kind, content := sub2APIRequestContent(value)
	if kind == "" {
		return
	}
	obs.Metadata["request_content_kind"] = kind
	obs.Metadata["request_content_length"] = strconv.Itoa(len([]rune(content)))
	digest, _ := security.BodyDigest([]byte(content), 0)
	obs.Metadata["request_content_sha256"] = digest
	obs.Metadata["request_content_preview"] = security.RedactPreview(content, 2048)
}

func annotateSub2APIResolvedModel(obs *Observation, requestedModel string, entry profiles.CatalogEntry) {
	if obs == nil {
		return
	}
	if obs.Metadata == nil {
		obs.Metadata = make(map[string]string)
	}
	obs.Metadata["model_requested"] = strings.TrimSpace(requestedModel)
	obs.Metadata["model_resolved"] = entry.ID
	obs.Metadata["model_display_name"] = entry.DisplayName
	obs.Metadata["model_provider"] = entry.Provider
	if len(entry.Capabilities) > 0 {
		obs.Metadata["model_capabilities"] = strings.Join(entry.Capabilities, ",")
	}
}

func sub2APIRouteFamilyForRequest(r *http.Request, obs *Observation) string {
	if r != nil && obs != nil && obs.Metadata["client_surface"] == "codex" {
		switch obs.RouteTemplate {
		case "sub2api.gateway.responses":
			return "codex.responses"
		case "sub2api.gateway.alpha_search":
			return "codex.alpha_search"
		}
	}
	return sub2APIRouteFamily(obs.RouteTemplate)
}

func (a *App) sub2APIChangePassword(w *captureWriter, body []byte, session Session, obs *Observation) {
	values := requestValues(&http.Request{Header: http.Header{"Content-Type": []string{"application/json"}}}, body)
	oldPassword, newPassword := values["old_password"], values["new_password"]
	user, ok := a.store.GetHoneyUser(session.UserID)
	if !ok || oldPassword == "" || user.PasswordFP != security.Fingerprint(a.cfg.InstanceKey, oldPassword) || len([]rune(newPassword)) < 8 || len([]rune(newPassword)) > 1024 {
		obs.EventType = "sub2api.user.password.failed"
		obs.AuthOutcome = "invalid"
		sub2APIError(w, http.StatusBadRequest, "invalid password request")
		return
	}
	_ = a.store.TouchHoneyUser(user.ID, func(current *model.HoneyUser) {
		current.PasswordFP = security.Fingerprint(a.cfg.InstanceKey, newPassword)
		current.PasswordLengthBucket, current.PasswordClasses, current.PasswordWeakClass = passwordProfile(newPassword)
		current.LastSeen = time.Now().UTC()
	})
	obs.EventType = "sub2api.user.password.updated"
	sub2APISuccess(a, w, http.StatusOK, map[string]any{"updated": true})
}

type sub2APIKeyOptions struct {
	name       *string
	disabled   *bool
	models     []string
	modelsSet  bool
	quota      *int64
	unlimited  *bool
	expiresAt  time.Time
	expiresSet bool
	allowIPs   *string
}

func (a *App) handleSub2APIKeys(w *captureWriter, r *http.Request, body []byte, session Session, obs *Observation) {
	user, ok := a.store.GetHoneyUser(session.UserID)
	if !ok {
		sub2APIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if obs.RouteTemplate == "sub2api.key.list" {
		obs.EventType = "sub2api.key.listed"
		items := make([]map[string]any, 0)
		for _, token := range a.store.ListTokens(user.ID) {
			items = append(items, a.sub2APIKeyView(token, ""))
		}
		sub2APISuccess(a, w, http.StatusOK, map[string]any{"api_keys": items, "items": items, "total": len(items)})
		return
	}
	if obs.RouteTemplate == "sub2api.key.get" {
		token, found := a.sub2APIKeyForUser(user.ID, strings.TrimPrefix(r.URL.Path, "/api/v1/keys/"))
		if !found {
			sub2APIError(w, http.StatusNotFound, "API key not found")
			return
		}
		obs.EventType = "sub2api.key.viewed"
		sub2APISuccess(a, w, http.StatusOK, a.sub2APIKeyView(token, ""))
		return
	}
	if obs.RouteTemplate == "sub2api.key.create" {
		options, err := a.parseSub2APIKeyOptions(r, body, false)
		if err != nil {
			obs.EventType = "sub2api.key.create.failed"
			obs.ExtraScore += 15
			sub2APIError(w, http.StatusBadRequest, "invalid API key request")
			return
		}
		raw := "sk-sub2api-" + security.MustRandomToken(24)
		quota := sub2APIDefaultQuota
		if options.quota != nil {
			quota = *options.quota
		}
		unlimited := false
		if options.unlimited != nil {
			unlimited = *options.unlimited
		} else if options.quota != nil && *options.quota == 0 {
			unlimited = true
		}
		if unlimited {
			quota = 0
		}
		name := "Sub2API key"
		if options.name != nil && strings.TrimSpace(*options.name) != "" {
			name = *options.name
		}
		token := model.HoneyToken{ID: "ht_" + security.MustRandomToken(8), HoneyUserID: user.ID, Hash: security.Fingerprint(a.cfg.InstanceKey, raw), PrefixHint: raw[:12], Name: name, ModelAllowlist: append([]string(nil), options.models...), RemainQuota: quota, UnlimitedQuota: unlimited, ExpiredAt: options.expiresAt, CreatedAt: time.Now().UTC()}
		if options.disabled != nil && *options.disabled {
			token.DisabledAt = time.Now().UTC()
		}
		if options.allowIPs != nil {
			token.AllowIPs = *options.allowIPs
		}
		if err := a.store.AddToken(token); err != nil {
			sub2APIError(w, http.StatusConflict, "API key creation failed")
			return
		}
		obs.EventType = "sub2api.key.created"
		obs.Metadata["key_fingerprint"] = token.Hash
		obs.Metadata["key_raw_retained"] = "false"
		sub2APISuccess(a, w, http.StatusOK, a.sub2APIKeyView(token, raw))
		return
	}
	idValue := strings.TrimPrefix(r.URL.Path, "/api/v1/keys/")
	token, found := a.sub2APIKeyForUser(user.ID, idValue)
	if !found {
		sub2APIError(w, http.StatusNotFound, "API key not found")
		return
	}
	if obs.RouteTemplate == "sub2api.key.delete" {
		if err := a.store.DeleteToken(user.ID, token.ID); err != nil {
			sub2APIError(w, http.StatusNotFound, "API key not found")
			return
		}
		obs.EventType = "sub2api.key.deleted"
		sub2APISuccess(a, w, http.StatusOK, map[string]any{"deleted": true, "id": newAPIPublicID(token.ID)})
		return
	}
	options, err := a.parseSub2APIKeyOptions(r, body, true)
	if err != nil {
		obs.EventType = "sub2api.key.update.failed"
		sub2APIError(w, http.StatusBadRequest, "invalid API key request")
		return
	}
	if err := a.store.UpdateToken(user.ID, token.ID, options.name, options.disabled, func() []string {
		if options.modelsSet {
			return options.models
		}
		return nil
	}()); err != nil {
		sub2APIError(w, http.StatusNotFound, "API key not found")
		return
	}
	if err := a.store.TouchToken(token.ID, func(current *model.HoneyToken) {
		if options.quota != nil {
			current.RemainQuota = *options.quota
		}
		if options.unlimited != nil {
			current.UnlimitedQuota = *options.unlimited
			if *options.unlimited {
				current.RemainQuota = 0
			}
		}
		if options.expiresSet {
			current.ExpiredAt = options.expiresAt
		}
		if options.allowIPs != nil {
			current.AllowIPs = *options.allowIPs
		}
	}); err != nil {
		sub2APIError(w, http.StatusNotFound, "API key not found")
		return
	}
	token, _ = a.sub2APIKeyForUser(user.ID, token.ID)
	obs.EventType = "sub2api.key.updated"
	sub2APISuccess(a, w, http.StatusOK, a.sub2APIKeyView(token, ""))
}

func (a *App) parseSub2APIKeyOptions(r *http.Request, body []byte, update bool) (sub2APIKeyOptions, error) {
	value := sub2APIRequestObject(r, body)
	options := sub2APIKeyOptions{}
	if raw, exists := value["name"]; exists {
		name := strings.TrimSpace(stringValue(raw))
		if name == "" || len([]rune(name)) > 128 {
			return options, fmt.Errorf("invalid name")
		}
		options.name = &name
	} else if !update {
		name := "Sub2API key"
		options.name = &name
	}
	if raw, exists := value["disabled"]; exists {
		flag, ok := sub2APIBool(raw)
		if !ok {
			return options, fmt.Errorf("invalid disabled")
		}
		options.disabled = &flag
	}
	for _, key := range []string{"models", "model_limits", "model_allowlist"} {
		if raw, exists := value[key]; exists {
			models, ok := sub2APIStringList(raw)
			if !ok || len(models) > sub2APIMaxKeyModels {
				return options, fmt.Errorf("invalid models")
			}
			for _, item := range models {
				if item == "" || len([]rune(item)) > 256 {
					return options, fmt.Errorf("invalid model")
				}
			}
			options.models, options.modelsSet = models, true
			break
		}
	}
	if raw, exists := value["quota"]; exists {
		quota, ok := sub2APIInt64(raw)
		if !ok || quota < 0 {
			return options, fmt.Errorf("invalid quota")
		}
		options.quota = &quota
	} else if raw, exists := value["remain_quota"]; exists {
		quota, ok := sub2APIInt64(raw)
		if !ok || quota < 0 {
			return options, fmt.Errorf("invalid quota")
		}
		options.quota = &quota
	}
	if raw, exists := value["unlimited"]; exists {
		flag, ok := sub2APIBool(raw)
		if !ok {
			return options, fmt.Errorf("invalid unlimited")
		}
		options.unlimited = &flag
	} else if raw, exists := value["unlimited_quota"]; exists {
		flag, ok := sub2APIBool(raw)
		if !ok {
			return options, fmt.Errorf("invalid unlimited")
		}
		options.unlimited = &flag
	}
	if raw, exists := value["expires_at"]; exists {
		expires, ok := sub2APITime(raw)
		if !ok {
			return options, fmt.Errorf("invalid expiry")
		}
		options.expiresAt, options.expiresSet = expires, true
	} else if raw, exists := value["expired_time"]; exists {
		expires, ok := sub2APITime(raw)
		if !ok {
			return options, fmt.Errorf("invalid expiry")
		}
		options.expiresAt, options.expiresSet = expires, true
	}
	if raw, exists := value["ip_whitelist"]; exists {
		ips, ok := sub2APIStringList(raw)
		if !ok || !validSub2APIIPlist(ips) {
			return options, fmt.Errorf("invalid IP whitelist")
		}
		joined := strings.Join(ips, ",")
		options.allowIPs = &joined
	} else if raw, exists := value["allow_ips"]; exists {
		ips, ok := sub2APIStringList(raw)
		if !ok || !validSub2APIIPlist(ips) {
			return options, fmt.Errorf("invalid IP whitelist")
		}
		joined := strings.Join(ips, ",")
		options.allowIPs = &joined
	}
	return options, nil
}

func (a *App) sub2APIKeyForUser(userID, value string) (model.HoneyToken, bool) {
	value, err := url.PathUnescape(strings.TrimSpace(value))
	if err != nil || value == "" || strings.ContainsAny(value, "/\\\r\n") {
		return model.HoneyToken{}, false
	}
	tokens := a.store.ListTokens(userID)
	if strings.HasPrefix(value, "ht_") {
		return findHoneyToken(tokens, value)
	}
	publicID, err := strconv.ParseInt(value, 10, 64)
	if err != nil || publicID <= 0 {
		return model.HoneyToken{}, false
	}
	for _, token := range tokens {
		if newAPIPublicID(token.ID) == publicID {
			return token, true
		}
	}
	return model.HoneyToken{}, false
}

func (a *App) sub2APIKeyView(token model.HoneyToken, raw string) map[string]any {
	status := "active"
	if !token.DisabledAt.IsZero() {
		status = "disabled"
	} else if !token.ExpiredAt.IsZero() && !token.ExpiredAt.After(time.Now().UTC()) {
		status = "expired"
	} else if !token.UnlimitedQuota && token.RemainQuota <= 0 {
		status = "exhausted"
	}
	key := sub2APIMaskedKey(token.PrefixHint)
	if raw != "" {
		key = raw
	}
	var expiresAt any
	if !token.ExpiredAt.IsZero() {
		expiresAt = token.ExpiredAt
	}
	var lastUsedAt any
	if !token.LastUsedAt.IsZero() {
		lastUsedAt = token.LastUsedAt
	}
	return map[string]any{
		"id": newAPIPublicID(token.ID), "user_id": newAPIPublicID(token.HoneyUserID), "key": key, "name": token.Name, "status": status,
		"ip_whitelist": splitSub2APIIPlist(token.AllowIPs), "ip_blacklist": []string{}, "last_used_at": lastUsedAt, "last_used_ip": nil,
		"quota": token.RemainQuota, "quota_used": 0, "remain_quota": token.RemainQuota, "unlimited_quota": token.UnlimitedQuota, "expires_at": expiresAt,
		"created_at": token.CreatedAt, "updated_at": token.CreatedAt, "current_concurrency": 0, "rate_limit_5h": 0, "rate_limit_1d": 0, "rate_limit_7d": 0,
		"usage_5h": 0, "usage_1d": 0, "usage_7d": 0, "model_limits": append([]string(nil), token.ModelAllowlist...),
	}
}

func sub2APIMaskedKey(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "sk-..."
	}
	if !strings.HasSuffix(prefix, "...") {
		prefix += "..."
	}
	return prefix
}

func (a *App) handleSub2APIUsage(w *captureWriter, r *http.Request, session Session, userID string, obs *Observation) {
	events, err := a.store.Events(-1, model.ProductSub2API, "")
	if err != nil {
		sub2APIError(w, http.StatusInternalServerError, "usage query failed")
		return
	}
	usageEvents := sub2APIUsageEvents(events, session.ID, userID)
	obs.EventType = "sub2api.usage.listed"
	switch obs.RouteTemplate {
	case "sub2api.usage.stats":
		filtered, _, _, _, _ := sub2APIUsageWindow(r, usageEvents)
		filtered = sub2APIFilterUsageEvents(r, filtered)
		rows := publicUsageEvents(filtered, "", "")
		sub2APISuccess(a, w, http.StatusOK, sub2APIUsageStatsPayload(filtered, rows))
	case "sub2api.usage.dashboard.stats":
		rows := publicUsageEvents(usageEvents, "", "")
		sub2APISuccess(a, w, http.StatusOK, a.sub2APIDashboardStats(userID, usageEvents, rows))
	case "sub2api.usage.dashboard.trend":
		filtered, startDate, endDate, granularity, location := sub2APIUsageWindow(r, usageEvents)
		filtered = sub2APIFilterUsageEvents(r, filtered)
		sub2APISuccess(a, w, http.StatusOK, map[string]any{"trend": sub2APITrend(filtered, granularity, location), "start_date": startDate, "end_date": endDate, "granularity": granularity})
	case "sub2api.usage.dashboard.models":
		filtered, startDate, endDate, _, _ := sub2APIUsageWindow(r, usageEvents)
		filtered = sub2APIFilterUsageEvents(r, filtered)
		sub2APISuccess(a, w, http.StatusOK, map[string]any{"models": sub2APIModelStats(filtered), "start_date": startDate, "end_date": endDate})
	case "sub2api.usage.dashboard.snapshot":
		filtered, startDate, endDate, granularity, location := sub2APIUsageWindow(r, usageEvents)
		filtered = sub2APIFilterUsageEvents(r, filtered)
		payload := map[string]any{
			"generated_at": time.Now().UTC(),
			"start_date":   startDate,
			"end_date":     endDate,
			"granularity":  granularity,
		}
		if sub2APIQueryBool(r, "include_trend", true) {
			payload["trend"] = sub2APITrend(filtered, granularity, location)
		}
		if sub2APIQueryBool(r, "include_model_stats", true) {
			payload["models"] = sub2APIModelStats(filtered)
		}
		if sub2APIQueryBool(r, "include_group_stats", false) {
			payload["groups"] = sub2APIGroupStats(filtered)
		}
		sub2APISuccess(a, w, http.StatusOK, payload)
	default:
		filtered := usageEvents
		if sub2APIUsageHasRangeQuery(r) {
			filtered, _, _, _, _ = sub2APIUsageWindow(r, usageEvents)
		}
		filtered = sub2APIFilterUsageEvents(r, filtered)
		rows := publicUsageEvents(filtered, "", "")
		page, pageSize := sub2APIUsagePage(r, len(rows))
		start := (page - 1) * pageSize
		if start > len(rows) {
			start = len(rows)
		}
		end := start + pageSize
		if end > len(rows) {
			end = len(rows)
		}
		pageRows := rows[start:end]
		sub2APISuccess(a, w, http.StatusOK, map[string]any{"items": pageRows, "records": pageRows, "total": len(rows), "page": page, "page_size": pageSize})
	}
}

type sub2APIUsageAggregate struct {
	Requests            int64
	InputTokens         int64
	OutputTokens        int64
	CacheCreationTokens int64
	CacheReadTokens     int64
	TotalTokens         int64
	Cost                float64
	ActualCost          float64
	DurationMS          int64
}

func sub2APIUsageEvents(events []model.Event, sessionID, userID string) []model.Event {
	result := make([]model.Event, 0, len(events))
	for _, event := range events {
		if event.InvocationID == "" || event.SimulatedCost <= 0 || !event.ResponseObserved {
			continue
		}
		if userID != "" {
			if event.Metadata["honey_user_id"] != userID {
				continue
			}
		} else if sessionID != "" && event.SessionID != sessionID {
			continue
		}
		result = append(result, event)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].ObservedAt.Equal(result[j].ObservedAt) {
			return result[i].Sequence > result[j].Sequence
		}
		return result[i].ObservedAt.After(result[j].ObservedAt)
	})
	return result
}

func sub2APIUsageHasRangeQuery(r *http.Request) bool {
	if r == nil {
		return false
	}
	query := r.URL.Query()
	return strings.TrimSpace(query.Get("period")) != "" || strings.TrimSpace(query.Get("start_date")) != "" || strings.TrimSpace(query.Get("end_date")) != ""
}

func sub2APIUsagePage(r *http.Request, _ int) (int, int) {
	page, pageSize := 1, 20
	if r == nil {
		return page, pageSize
	}
	if parsed, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page"))); err == nil && parsed > 0 {
		page = parsed
	}
	if parsed, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page_size"))); err == nil && parsed > 0 && parsed <= 100 {
		pageSize = parsed
	}
	return page, pageSize
}

func sub2APIQueryBool(r *http.Request, key string, fallback bool) bool {
	if r == nil {
		return fallback
	}
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return parsed
}

func sub2APIFilterUsageEvents(r *http.Request, events []model.Event) []model.Event {
	if r == nil {
		return events
	}
	query := r.URL.Query()
	modelName := strings.TrimSpace(query.Get("model"))
	apiKeyID := strings.TrimSpace(query.Get("api_key_id"))
	groupID := strings.TrimSpace(query.Get("group_id"))
	streamRaw := strings.TrimSpace(query.Get("stream"))
	requestType := strings.ToLower(strings.TrimSpace(query.Get("request_type")))
	result := make([]model.Event, 0, len(events))
	for _, event := range events {
		if modelName != "" && event.ModelID != modelName {
			continue
		}
		if apiKeyID != "" && event.Metadata["api_key_id"] != apiKeyID {
			continue
		}
		if groupID != "" && groupID != event.Metadata["group_id"] {
			continue
		}
		stream := event.Metadata["stream"] == "true"
		if streamRaw != "" {
			requested, err := strconv.ParseBool(streamRaw)
			if err == nil && stream != requested {
				continue
			}
		}
		if requestType != "" && sub2APIUsageRequestType(event) != requestType {
			continue
		}
		result = append(result, event)
	}
	return result
}

func sub2APIUsageRequestType(event model.Event) string {
	if event.Metadata["stream"] == "true" {
		return "stream"
	}
	if event.RouteTemplate == "sub2api.gateway.live" {
		return "live"
	}
	return "sync"
}

func sub2APIUsageAPIKeyID(event model.Event) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(event.Metadata["api_key_id"]), 10, 64)
	if err != nil || value < 1 {
		return 0
	}
	return value
}

func sub2APIUsageUpstreamEndpoint(event model.Event) string {
	if value := strings.TrimSpace(event.Metadata["upstream_endpoint"]); value != "" {
		return value
	}
	return "sub2api.synthetic.local"
}

func sub2APIEndpointStats(events []model.Event, source string) []map[string]any {
	type endpointAggregate struct {
		Requests    int64
		TotalTokens int64
		Cost        float64
		ActualCost  float64
	}
	items := make(map[string]*endpointAggregate)
	for _, event := range events {
		name := strings.TrimSpace(event.RouteTemplate)
		if source == "upstream" {
			name = sub2APIUsageUpstreamEndpoint(event)
		} else if source == "path" {
			name += " -> " + sub2APIUsageUpstreamEndpoint(event)
		}
		if name == "" {
			name = "unknown"
		}
		item := items[name]
		if item == nil {
			item = &endpointAggregate{}
			items[name] = item
		}
		item.Requests++
		item.TotalTokens += int64(event.SimulatedInputTokens + event.SimulatedOutputTokens)
		item.Cost += float64(event.SimulatedCost)
		item.ActualCost += float64(event.SimulatedCost)
	}
	names := make([]string, 0, len(items))
	for name := range items {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]map[string]any, 0, len(names))
	for _, name := range names {
		item := items[name]
		result = append(result, map[string]any{"endpoint": name, "requests": item.Requests, "total_tokens": item.TotalTokens, "cost": item.Cost, "actual_cost": item.ActualCost})
	}
	return result
}

func sub2APIGroupStats(events []model.Event) []map[string]any {
	aggregate := sub2APIAggregate(events)
	if aggregate.Requests == 0 {
		return []map[string]any{}
	}
	return []map[string]any{{"group_id": int64(1), "group_name": "default", "requests": aggregate.Requests, "total_tokens": aggregate.TotalTokens, "cost": aggregate.Cost, "actual_cost": aggregate.ActualCost}}
}

func sub2APIAggregate(events []model.Event) sub2APIUsageAggregate {
	var result sub2APIUsageAggregate
	for _, event := range events {
		result.Requests++
		result.InputTokens += int64(event.SimulatedInputTokens)
		result.OutputTokens += int64(event.SimulatedOutputTokens)
		result.TotalTokens += int64(event.SimulatedInputTokens + event.SimulatedOutputTokens)
		result.Cost += float64(event.SimulatedCost)
		result.ActualCost += float64(event.SimulatedCost)
		result.DurationMS += event.DurationMS
	}
	return result
}

func sub2APIUsageStatsPayload(events []model.Event, rows []map[string]any) map[string]any {
	aggregate := sub2APIAggregate(events)
	return map[string]any{
		// Keep the original compatibility aliases alongside the official fields.
		"total": len(rows), "request_count": len(rows), "items": rows,
		"total_requests": aggregate.Requests, "total_input_tokens": aggregate.InputTokens,
		"total_output_tokens": aggregate.OutputTokens, "total_cache_tokens": aggregate.CacheCreationTokens + aggregate.CacheReadTokens,
		"total_cache_creation_tokens": aggregate.CacheCreationTokens, "total_cache_read_tokens": aggregate.CacheReadTokens,
		"total_tokens": aggregate.TotalTokens, "total_cost": aggregate.Cost, "total_actual_cost": aggregate.ActualCost,
		"average_duration_ms": sub2APIAverageDuration(aggregate), "models": sub2APIModelCount(events),
		"endpoints": sub2APIEndpointStats(events, "inbound"), "upstream_endpoints": sub2APIEndpointStats(events, "upstream"), "endpoint_paths": sub2APIEndpointStats(events, "path"),
	}
}

func (a *App) sub2APIDashboardStats(userID string, events []model.Event, rows []map[string]any) map[string]any {
	aggregate := sub2APIAggregate(events)
	today := sub2APITodayEvents(events, time.Now().UTC())
	todayAggregate := sub2APIAggregate(today)
	keys := a.store.ListTokens(userID)
	activeKeys := 0
	now := time.Now().UTC()
	for _, key := range keys {
		if key.DisabledAt.IsZero() && (key.ExpiredAt.IsZero() || key.ExpiredAt.After(now)) && (key.UnlimitedQuota || key.RemainQuota > 0) {
			activeKeys++
		}
	}
	rpm, tpm := sub2APIRollingRate(events, now)
	return map[string]any{
		"total_api_keys": len(keys), "active_api_keys": activeKeys,
		"total_requests": aggregate.Requests, "total_input_tokens": aggregate.InputTokens, "total_output_tokens": aggregate.OutputTokens,
		"total_cache_creation_tokens": aggregate.CacheCreationTokens, "total_cache_read_tokens": aggregate.CacheReadTokens,
		"total_tokens": aggregate.TotalTokens, "total_cost": aggregate.Cost, "total_actual_cost": aggregate.ActualCost,
		"today_requests": todayAggregate.Requests, "today_input_tokens": todayAggregate.InputTokens, "today_output_tokens": todayAggregate.OutputTokens,
		"today_cache_creation_tokens": todayAggregate.CacheCreationTokens, "today_cache_read_tokens": todayAggregate.CacheReadTokens,
		"today_tokens": todayAggregate.TotalTokens, "today_cost": todayAggregate.Cost, "today_actual_cost": todayAggregate.ActualCost,
		"average_duration_ms": sub2APIAverageDuration(aggregate), "rpm": rpm, "tpm": tpm,
		"by_platform": []map[string]any{{"platform": "sub2api", "total_requests": aggregate.Requests, "total_tokens": aggregate.TotalTokens, "total_actual_cost": aggregate.ActualCost, "today_requests": todayAggregate.Requests, "today_tokens": todayAggregate.TotalTokens, "today_actual_cost": todayAggregate.ActualCost}},
		"items":       rows,
	}
}

func sub2APIAverageDuration(aggregate sub2APIUsageAggregate) float64 {
	if aggregate.Requests == 0 {
		return 0
	}
	return float64(aggregate.DurationMS) / float64(aggregate.Requests)
}

func sub2APITodayEvents(events []model.Event, now time.Time) []model.Event {
	location := sub2APIUsageLocation("")
	day := now.In(location)
	start := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, location)
	end := start.AddDate(0, 0, 1)
	result := make([]model.Event, 0, len(events))
	for _, event := range events {
		if !event.ObservedAt.Before(start) && event.ObservedAt.Before(end) {
			result = append(result, event)
		}
	}
	return result
}

func sub2APIRollingRate(events []model.Event, now time.Time) (int64, int64) {
	cutoff := now.Add(-5 * time.Minute)
	var requests, tokens int64
	for _, event := range events {
		if event.ObservedAt.Before(cutoff) || event.ObservedAt.After(now.Add(time.Second)) {
			continue
		}
		requests++
		tokens += int64(event.SimulatedInputTokens + event.SimulatedOutputTokens)
	}
	return (requests + 4) / 5, (tokens + 4) / 5
}

func sub2APIUsageLocation(raw string) *time.Location {
	if strings.TrimSpace(raw) != "" {
		if location, err := time.LoadLocation(strings.TrimSpace(raw)); err == nil {
			return location
		}
	}
	if location, err := time.LoadLocation(model.InteractionChainTimezone); err == nil {
		return location
	}
	return time.FixedZone("Asia/Shanghai", 8*60*60)
}

func sub2APIUsageWindow(r *http.Request, events []model.Event) ([]model.Event, string, string, string, *time.Location) {
	query := r.URL.Query()
	location := sub2APIUsageLocation(query.Get("timezone"))
	now := time.Now().In(location)
	startDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, location).AddDate(0, 0, -29)
	endDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, location).AddDate(0, 0, 1)
	period := strings.ToLower(strings.TrimSpace(query.Get("period")))
	if period != "" {
		switch period {
		case "today":
			startDay = endDay.AddDate(0, 0, -1)
		case "week":
			startDay = endDay.AddDate(0, 0, -7)
		case "month":
			startDay = endDay.AddDate(0, -1, 0)
		case "year":
			startDay = endDay.AddDate(-1, 0, 0)
		}
	}
	if value := strings.TrimSpace(query.Get("start_date")); value != "" {
		if parsed, err := time.ParseInLocation("2006-01-02", value, location); err == nil {
			startDay = parsed
		}
	}
	if value := strings.TrimSpace(query.Get("end_date")); value != "" {
		if parsed, err := time.ParseInLocation("2006-01-02", value, location); err == nil {
			endDay = parsed.AddDate(0, 0, 1)
		}
	}
	if !endDay.After(startDay) {
		endDay = startDay.AddDate(0, 0, 1)
	}
	granularity := strings.ToLower(strings.TrimSpace(query.Get("granularity")))
	if granularity != "hour" {
		granularity = "day"
	}
	filtered := make([]model.Event, 0, len(events))
	for _, event := range events {
		localTime := event.ObservedAt.In(location)
		if !localTime.Before(startDay) && localTime.Before(endDay) {
			filtered = append(filtered, event)
		}
	}
	return filtered, startDay.Format("2006-01-02"), endDay.AddDate(0, 0, -1).Format("2006-01-02"), granularity, location
}

func sub2APITrend(events []model.Event, granularity string, location *time.Location) []map[string]any {
	type bucket struct {
		key string
		sub2APIUsageAggregate
	}
	buckets := make(map[string]*bucket)
	for _, event := range events {
		localTime := event.ObservedAt.In(location)
		key := localTime.Format("2006-01-02")
		if granularity == "hour" {
			key = localTime.Format("2006-01-02 15:00")
		}
		item := buckets[key]
		if item == nil {
			item = &bucket{key: key}
			buckets[key] = item
		}
		item.Requests++
		item.InputTokens += int64(event.SimulatedInputTokens)
		item.OutputTokens += int64(event.SimulatedOutputTokens)
		item.TotalTokens += int64(event.SimulatedInputTokens + event.SimulatedOutputTokens)
		item.Cost += float64(event.SimulatedCost)
		item.ActualCost += float64(event.SimulatedCost)
	}
	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		item := buckets[key]
		result = append(result, map[string]any{"date": item.key, "requests": item.Requests, "input_tokens": item.InputTokens, "output_tokens": item.OutputTokens, "cache_creation_tokens": 0, "cache_read_tokens": 0, "total_tokens": item.TotalTokens, "cost": item.Cost, "actual_cost": item.ActualCost})
	}
	return result
}

func sub2APIModelStats(events []model.Event) []map[string]any {
	items := make(map[string]*sub2APIUsageAggregate)
	for _, event := range events {
		name := event.ModelID
		if name == "" {
			name = "unknown"
		}
		item := items[name]
		if item == nil {
			item = &sub2APIUsageAggregate{}
			items[name] = item
		}
		item.Requests++
		item.InputTokens += int64(event.SimulatedInputTokens)
		item.OutputTokens += int64(event.SimulatedOutputTokens)
		item.TotalTokens += int64(event.SimulatedInputTokens + event.SimulatedOutputTokens)
		item.Cost += float64(event.SimulatedCost)
		item.ActualCost += float64(event.SimulatedCost)
	}
	names := make([]string, 0, len(items))
	for name := range items {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]map[string]any, 0, len(names))
	for _, name := range names {
		item := items[name]
		result = append(result, map[string]any{"model": name, "requests": item.Requests, "input_tokens": item.InputTokens, "output_tokens": item.OutputTokens, "cache_creation_tokens": 0, "cache_read_tokens": 0, "total_tokens": item.TotalTokens, "cost": item.Cost, "actual_cost": item.ActualCost})
	}
	return result
}

func sub2APIModelCount(events []model.Event) map[string]int64 {
	result := make(map[string]int64)
	for _, event := range events {
		name := event.ModelID
		if name == "" {
			name = "unknown"
		}
		result[name]++
	}
	return result
}

func sub2APITotalCost(rows []map[string]any) int64 {
	var total int64
	for _, row := range rows {
		if value, ok := row["cost"].(int64); ok {
			total += value
		}
	}
	return total
}

func sub2APITotalTokens(rows []map[string]any) int {
	total := 0
	for _, row := range rows {
		if value, ok := row["total_tokens"].(int); ok {
			total += value
		}
	}
	return total
}

func (a *App) handleSub2APIRedeem(w *captureWriter, r *http.Request, body []byte, profile profiles.Profile, session Session, obs *Observation) {
	values := requestValues(r, body)
	code := strings.TrimSpace(values["code"])
	if code == "" {
		code = strings.TrimSpace(values["redeem_code"])
	}
	if code == "" || len([]rune(code)) > 256 {
		obs.EventType = "sub2api.redeem.failed"
		sub2APIError(w, http.StatusBadRequest, "redeem code is required")
		return
	}
	user, ok := a.store.GetHoneyUser(session.UserID)
	if !ok {
		sub2APIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	obs.Metadata["redeem_code_fp"] = security.Fingerprint(a.cfg.InstanceKey, code)
	obs.Metadata["redeem_raw_retained"] = "false"
	balance, err := a.store.AddQuota(user.ID, sub2APIRedeemQuota)
	if err != nil {
		obs.EventType = "sub2api.redeem.failed"
		sub2APIError(w, http.StatusConflict, "redeem failed")
		return
	}
	scope, ownerKey, ttl := virtualEffectOwner(profile, session)
	now := time.Now().UTC()
	_ = a.store.AddEffect(model.VirtualEffect{ID: "ve_" + security.MustRandomToken(8), OwnerScope: scope, OwnerKey: ownerKey, Product: model.ProductSub2API, EffectType: "sub2api_redeem_virtual", State: map[string]string{"amount": strconv.FormatInt(sub2APIRedeemQuota, 10)}, CreatedAt: now, ExpiresAt: now.Add(ttl)})
	obs.EventType = "sub2api.redeem.accepted"
	obs.EffectOutcome = "virtual_pending"
	sub2APISuccess(a, w, http.StatusOK, map[string]any{"amount": sub2APIRedeemQuota, "balance": balance})
}

func (a *App) handleSub2APIRedeemHistory(w *captureWriter, session Session, obs *Observation) {
	events, _ := a.store.Events(-1, model.ProductSub2API, "")
	items := make([]map[string]any, 0)
	for _, event := range events {
		if event.SessionID != session.ID || event.EventType != "sub2api.redeem.accepted" {
			continue
		}
		items = append(items, map[string]any{"id": event.EventID, "amount": sub2APIRedeemQuota, "created_at": event.ObservedAt, "status": "completed"})
	}
	obs.EventType = "sub2api.redeem.history.listed"
	sub2APISuccess(a, w, http.StatusOK, items)
}

func (a *App) handleSub2APIGateway(w *captureWriter, r *http.Request, _ profiles.Profile, session Session, body []byte, obs *Observation) {
	sub2APIAnnotateClientSurface(r, obs)
	token, auth, source, fingerprint := a.sub2APIAuthenticate(r)
	obs.AuthOutcome = auth
	obs.CredentialFingerprint = fingerprint
	obs.Metadata["api_key_source"] = source
	obs.Metadata["api_key_present"] = strconv.FormatBool(fingerprint != "")
	if auth != "valid_honey_key" {
		a.startInvocation(obs, auth, false, sub2APIAuthReason(auth))
		obs.EventType = sub2APIGatewayEvent(obs.RouteTemplate, false)
		status, message := sub2APIAuthError(auth)
		sub2APIGatewayError(a, w, obs.RouteTemplate, status, message)
		return
	}
	obs.Metadata["honey_user_id"] = token.HoneyUserID
	obs.Metadata["api_key_id"] = strconv.FormatInt(newAPIPublicID(token.ID), 10)
	obs.Metadata["group_id"] = "1"
	obs.Metadata["group_name"] = "default"
	obs.Metadata["upstream_endpoint"] = "sub2api.synthetic.local"
	_ = a.store.TouchToken(token.ID, func(current *model.HoneyToken) { current.LastUsedAt = time.Now().UTC() })

	switch obs.RouteTemplate {
	case "sub2api.gateway.models":
		obs.EventType = "sub2api.models.listed"
		catalog := a.catalogForSession(model.ProductSub2API, "user", session)
		if obs.Metadata["client_surface"] == "codex" {
			obs.Metadata["api_family"] = "codex.models"
			a.writeJSON(w, http.StatusOK, sub2APICodexModelsManifest(catalog))
			return
		}
		cards := profiles.OpenAIModelCardsForCatalog(a.cfg.InstanceKey, catalog, "sub2api")
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": cards})
		return
	case "sub2api.gateway.codex.models":
		obs.EventType = "sub2api.models.listed"
		obs.Metadata["client_surface"] = "codex"
		obs.Metadata["api_family"] = "codex.models"
		a.writeJSON(w, http.StatusOK, sub2APICodexModelsManifest(a.catalogForSession(model.ProductSub2API, "user", session)))
		return
	case "sub2api.gateway.model":
		requested := strings.TrimPrefix(r.URL.Path, "/v1/models/")
		requested, _ = url.PathUnescape(requested)
		entry, ok := a.resolveCatalogModelForSession(model.ProductSub2API, requested, "user", session)
		if !ok {
			obs.EventType = "sub2api.models.list.failed"
			sub2APIGatewayError(a, w, obs.RouteTemplate, http.StatusNotFound, "model not found")
			return
		}
		obs.EventType = "sub2api.models.viewed"
		a.writeJSON(w, http.StatusOK, profiles.OpenAIModelCardsForCatalog(a.cfg.InstanceKey, []profiles.CatalogEntry{entry}, "sub2api")[0])
		return
	case "sub2api.gateway.billing":
		obs.EventType = "sub2api.gateway.billing.viewed"
		a.writeJSON(w, http.StatusOK, map[string]any{"quota": token.RemainQuota, "remain_quota": token.RemainQuota, "unlimited_quota": token.UnlimitedQuota, "expires_at": token.ExpiredAt, "status": "active"})
		return
	case "sub2api.gateway.count_tokens":
		value, _, _, validation := sub2APIInvocationRequest(r, body, "sub2api.gateway.count_tokens")
		if validation != "" {
			obs.EventType = "sub2api.gateway.count_tokens.rejected"
			sub2APIGatewayError(a, w, obs.RouteTemplate, http.StatusBadRequest, "invalid request")
			return
		}
		obs.EventType = "sub2api.gateway.count_tokens.accepted"
		tokens := maxInt(1, len(body)/4)
		a.writeJSON(w, http.StatusOK, map[string]any{"input_tokens": tokens, "total_tokens": tokens})
		_ = value
		return
	case "sub2api.gateway.alpha_search":
		obs.EventType = "sub2api.gateway.alpha_search.accepted"
		// Alpha search is represented locally as an empty synthetic result. It
		// never sends a query to a search provider or performs model inference.
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": []any{}, "has_more": false})
		return
	case "sub2api.gateway.usage":
		a.handleSub2APIUsage(w, r, session, token.HoneyUserID, obs)
		return
	case "sub2api.gateway.live":
		obs.EventType = "sub2api.gateway.live.accepted"
		a.writeJSON(w, http.StatusOK, map[string]any{"id": "call_" + security.MustRandomToken(8), "status": "completed"})
		return
	}
	value, requestedModel, stream, validation := sub2APIInvocationRequest(r, body, obs.RouteTemplate)
	obs.Metadata["stream"] = strconv.FormatBool(stream)
	annotateSub2APIRequestMetadata(obs, value, requestedModel)
	if validation != "" {
		a.startInvocation(obs, auth, false, validation)
		obs.EventType = sub2APIGatewayEvent(obs.RouteTemplate, false)
		if validation == "quota_overflow" {
			obs.ExtraScore += 35
		}
		sub2APIGatewayError(a, w, obs.RouteTemplate, http.StatusBadRequest, "invalid request")
		return
	}
	entry, resolved := a.resolveCatalogModelForSession(model.ProductSub2API, requestedModel, "user", session)
	if !resolved {
		a.startInvocation(obs, auth, false, "model_not_found")
		obs.EventType = sub2APIGatewayEvent(obs.RouteTemplate, false)
		sub2APIGatewayError(a, w, obs.RouteTemplate, http.StatusNotFound, "model not found")
		return
	}
	if len(token.ModelAllowlist) > 0 && !containsString(token.ModelAllowlist, entry.ID) {
		a.startInvocation(obs, auth, false, "model_not_allowed_for_key")
		obs.EventType = sub2APIGatewayEvent(obs.RouteTemplate, false)
		obs.ExtraScore += 25
		sub2APIGatewayError(a, w, obs.RouteTemplate, http.StatusForbidden, "model is not available for this API key")
		return
	}
	obs.ModelID, obs.ModelResolved = entry.ID, true
	annotateSub2APIResolvedModel(obs, requestedModel, entry)
	obs.Metadata["api_family"] = sub2APIRouteFamilyForRequest(r, obs)
	obs.ExtraReasons = append(obs.ExtraReasons, "sub2api_synthetic_compute_use")
	a.startInvocation(obs, auth, true)
	cost := int64(maxInt(1, len(body)/4))
	if !token.UnlimitedQuota && token.RemainQuota < cost {
		obs.ExecutionOutcome = "rejected_before_dispatch"
		obs.RejectionReason = "quota_exhausted"
		obs.EventType = sub2APIGatewayEvent(obs.RouteTemplate, false)
		obs.ExtraReasons = append(obs.ExtraReasons, "sub2api_virtual_quota_exhausted")
		sub2APIGatewayError(a, w, obs.RouteTemplate, http.StatusPaymentRequired, "insufficient quota")
		return
	}
	if _, err := a.store.ConsumeQuota(token.HoneyUserID, token.ID, obs.InvocationID, cost); err != nil {
		obs.ExecutionOutcome = "rejected_before_dispatch"
		obs.RejectionReason = "quota_exhausted"
		obs.EventType = sub2APIGatewayEvent(obs.RouteTemplate, false)
		obs.ExtraReasons = append(obs.ExtraReasons, "sub2api_virtual_quota_exhausted")
		sub2APIGatewayError(a, w, obs.RouteTemplate, http.StatusPaymentRequired, "insufficient quota")
		return
	}
	if !token.UnlimitedQuota {
		_ = a.store.TouchToken(token.ID, func(current *model.HoneyToken) {
			if current.RemainQuota >= cost {
				current.RemainQuota -= cost
			} else {
				current.RemainQuota = 0
			}
		})
	}
	obs.EventType = sub2APIGatewayEvent(obs.RouteTemplate, true)
	switch obs.RouteTemplate {
	case "sub2api.gateway.messages":
		a.writeAnthropicResponse(w, body, stream, obs, entry.ID)
	case "sub2api.gateway.responses":
		a.writeOpenAIResponseForRoute(w, body, model.ProductSub2API, "openai.responses", stream, obs, entry.ID)
	case "sub2api.gateway.embeddings":
		a.writeOpenAIResponseForRoute(w, body, model.ProductSub2API, "openai.embeddings", false, obs, entry.ID)
	case "sub2api.gateway.completions":
		a.writeOpenAIResponseForRoute(w, body, model.ProductSub2API, "openai.completions", stream, obs, entry.ID)
	default:
		a.writeOpenAIResponseForRoute(w, body, model.ProductSub2API, "openai.chat.completions", stream, obs, entry.ID)
	}
	_ = value
}

func (a *App) sub2APIAuthenticate(r *http.Request) (model.HoneyToken, string, string, string) {
	value, source := sub2APICredentialValue(r)
	if value == "" {
		return model.HoneyToken{}, "missing", "", ""
	}
	fingerprint := security.Fingerprint(a.cfg.InstanceKey, value)
	token, ok := a.store.FindToken(fingerprint)
	if !ok {
		for _, candidate := range a.store.ListTokens("") {
			if candidate.Hash == fingerprint {
				token = candidate
				if !candidate.DisabledAt.IsZero() {
					return token, "disabled", source, fingerprint
				}
				break
			}
		}
		if token.Hash == "" {
			return model.HoneyToken{}, "invalid", source, fingerprint
		}
	}
	if !token.ExpiredAt.IsZero() && !token.ExpiredAt.After(time.Now().UTC()) {
		return token, "expired", source, fingerprint
	}
	if !token.UnlimitedQuota && token.RemainQuota <= 0 {
		return token, "quota_exhausted", source, fingerprint
	}
	if !sub2APIAllowIP(token.AllowIPs, requestSourceIP(r)) {
		return token, "ip_denied", source, fingerprint
	}
	return token, "valid_honey_key", source, fingerprint
}

func sub2APICredentialValue(r *http.Request) (string, string) {
	if value := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return strings.TrimSpace(value[7:]), "authorization_bearer"
	}
	for _, item := range []struct{ name, source string }{{"X-API-Key", "x-api-key"}, {"X-Goog-API-Key", "x-goog-api-key"}} {
		if value := strings.TrimSpace(r.Header.Get(item.name)); value != "" {
			return value, item.source
		}
	}
	return "", ""
}

func sub2APIAllowIP(raw, sourceIP string) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	ip := net.ParseIP(strings.TrimSpace(sourceIP))
	if ip == nil {
		return false
	}
	for _, item := range splitSub2APIIPlist(raw) {
		if candidate := net.ParseIP(item); candidate != nil && candidate.Equal(ip) {
			return true
		}
		if _, network, err := net.ParseCIDR(item); err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func sub2APIAuthReason(auth string) string {
	switch auth {
	case "missing":
		return "missing_authentication"
	case "quota_exhausted":
		return "quota_exhausted"
	case "disabled":
		return "key_disabled"
	case "expired":
		return "key_expired"
	case "ip_denied":
		return "key_ip_not_allowed"
	default:
		return "invalid_authentication"
	}
}

func sub2APIAuthError(auth string) (int, string) {
	switch auth {
	case "quota_exhausted":
		return http.StatusPaymentRequired, "insufficient quota"
	case "ip_denied":
		return http.StatusForbidden, "API key is not allowed from this IP"
	case "missing":
		return http.StatusUnauthorized, "API key is required"
	default:
		return http.StatusUnauthorized, "invalid API key"
	}
}

func sub2APIGatewayEvent(route string, accepted bool) string {
	suffix := "rejected"
	if accepted {
		suffix = "accepted"
	}
	switch route {
	case "sub2api.gateway.messages":
		return "sub2api.gateway.messages." + suffix
	case "sub2api.gateway.count_tokens":
		return "sub2api.gateway.count_tokens." + suffix
	case "sub2api.gateway.billing":
		return "sub2api.gateway.billing." + suffix
	case "sub2api.gateway.alpha_search":
		return "sub2api.gateway.alpha_search." + suffix
	case "sub2api.gateway.responses":
		return "sub2api.gateway.responses." + suffix
	case "sub2api.gateway.embeddings":
		return "sub2api.gateway.embeddings." + suffix
	case "sub2api.gateway.completions":
		return "sub2api.gateway.completions." + suffix
	default:
		return "sub2api.gateway.chat." + suffix
	}
}

func sub2APIRouteFamily(route string) string {
	switch route {
	case "sub2api.gateway.messages":
		return "anthropic"
	case "sub2api.gateway.count_tokens":
		return "anthropic.count_tokens"
	case "sub2api.gateway.billing":
		return "billing"
	case "sub2api.gateway.alpha_search":
		return "openai.alpha_search"
	case "sub2api.gateway.responses":
		return "responses"
	case "sub2api.gateway.embeddings":
		return "embeddings"
	case "sub2api.gateway.completions":
		return "completions"
	default:
		return "openai"
	}
}

func sub2APIGatewayError(a *App, w *captureWriter, route string, status int, message string) {
	if route == "sub2api.gateway.messages" {
		a.writeNewAPIProtocolError(w, "anthropic.messages", status, message, sub2APIGatewayErrorType)
		return
	}
	a.writeNewAPIProtocolError(w, "openai.chat.completions", status, message, sub2APIGatewayErrorType)
}

func sub2APIInvocationRequest(r *http.Request, body []byte, route string) (map[string]any, string, bool, string) {
	if !jsonContentTypeOK(r) {
		return nil, "", false, "invalid_request"
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return nil, "", false, "invalid_request"
	}
	modelName, ok := value["model"].(string)
	modelName = strings.TrimSpace(modelName)
	if !ok || modelName == "" || len([]rune(modelName)) > 256 {
		return value, modelName, false, "invalid_request"
	}
	stream := false
	if raw, exists := value["stream"]; exists {
		var streamOK bool
		stream, streamOK = sub2APIBool(raw)
		if !streamOK {
			return value, modelName, false, "invalid_request"
		}
	}
	if raw, exists := value["max_tokens"]; exists {
		count, numberOK := sub2APIInt64(raw)
		if !numberOK || count < 0 {
			return value, modelName, stream, "invalid_request"
		}
		if count > 1_000_000 {
			return value, modelName, stream, "quota_overflow"
		}
	}
	switch route {
	case "sub2api.gateway.messages", "sub2api.gateway.chat":
		raw, exists := value["messages"]
		messages, messagesOK := raw.([]any)
		if !exists || !messagesOK || len(messages) > 128 {
			return value, modelName, stream, "invalid_request"
		}
		for _, item := range messages {
			message, ok := item.(map[string]any)
			if !ok {
				return value, modelName, stream, "invalid_request"
			}
			if role, present := message["role"]; present {
				if text, ok := role.(string); !ok || len([]rune(text)) > 32 {
					return value, modelName, stream, "invalid_request"
				}
			}
		}
	case "sub2api.gateway.responses":
		if _, input := value["input"]; !input {
			if _, messages := value["messages"]; !messages {
				return value, modelName, stream, "invalid_request"
			}
		}
	case "sub2api.gateway.embeddings":
		if _, input := value["input"]; !input {
			return value, modelName, stream, "invalid_request"
		}
	case "sub2api.gateway.completions":
		if _, prompt := value["prompt"]; !prompt {
			return value, modelName, stream, "invalid_request"
		}
	}
	return value, modelName, stream, ""
}

const sub2APIRequestContentLimit = 4096

type sub2APIContentCollector struct {
	value     strings.Builder
	truncated bool
}

func sub2APIRequestContent(value map[string]any) (string, string) {
	if value == nil {
		return "", ""
	}
	fields := []struct {
		name string
		kind string
	}{
		{name: "messages", kind: "messages"},
		{name: "input", kind: "input"},
		{name: "instructions", kind: "instructions"},
		{name: "prompt", kind: "prompt"},
	}
	kinds := make([]string, 0, len(fields))
	parts := make([]string, 0, len(fields))
	for _, field := range fields {
		raw, exists := value[field.name]
		if !exists {
			continue
		}
		content := sub2APIContentText(raw)
		if content == "" {
			content = "[structured input]"
		}
		kinds = append(kinds, field.kind)
		parts = append(parts, field.name+": "+content)
	}
	if len(parts) == 0 {
		return "", ""
	}
	content := strings.Join(parts, "\n")
	runes := []rune(content)
	if len(runes) > sub2APIRequestContentLimit {
		content = string(runes[:sub2APIRequestContentLimit]) + "…"
	}
	return strings.Join(kinds, "+"), content
}

func sub2APIContentText(value any) string {
	collector := &sub2APIContentCollector{}
	collector.walk(value, 0)
	return strings.TrimSpace(collector.value.String())
}

func (c *sub2APIContentCollector) walk(value any, depth int) {
	if c == nil || depth > 8 || c.truncated {
		return
	}
	switch typed := value.(type) {
	case string:
		c.add(typed)
	case []any:
		for _, item := range typed {
			c.walk(item, depth+1)
			if c.truncated {
				return
			}
		}
	case map[string]any:
		if role := strings.TrimSpace(stringValue(typed["role"])); role != "" {
			c.add(role + ":")
		}
		// These are the text-bearing fields used by OpenAI Chat Completions,
		// Responses, and Codex input items. Unknown fields (URLs, tool
		// arguments, credentials, and metadata) are intentionally omitted.
		for _, key := range []string{"content", "text", "input_text", "output_text", "instructions", "prompt"} {
			if nested, exists := typed[key]; exists {
				c.walk(nested, depth+1)
				if c.truncated {
					return
				}
			}
		}
	}
}

func (c *sub2APIContentCollector) add(value string) {
	value = strings.TrimSpace(value)
	if value == "" || c.truncated {
		return
	}
	current := []rune(c.value.String())
	separator := 0
	if len(current) > 0 {
		separator = 1
	}
	available := sub2APIRequestContentLimit - len(current) - separator
	if available <= 0 {
		c.truncated = true
		return
	}
	if separator > 0 {
		c.value.WriteByte('\n')
	}
	runes := []rune(value)
	if len(runes) > available {
		c.value.WriteString(string(runes[:available]))
		c.truncated = true
		return
	}
	c.value.WriteString(value)
}

func sub2APIRequestObject(r *http.Request, body []byte) map[string]any {
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return map[string]any{}
		}
		result := make(map[string]any, len(values))
		for key, item := range values {
			if len(item) == 1 {
				result[key] = item[0]
			}
		}
		return result
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return map[string]any{}
	}
	return value
}

func sub2APIBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return false, false
	}
}

func sub2APIInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case json.Number:
		parsed, err := typed.Int64()
		return parsed, err == nil
	case float64:
		if typed != float64(int64(typed)) {
			return 0, false
		}
		return int64(typed), true
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func sub2APITime(value any) (time.Time, bool) {
	if text, ok := value.(string); ok {
		text = strings.TrimSpace(text)
		if text == "" {
			return time.Time{}, true
		}
		parsed, err := time.Parse(time.RFC3339, text)
		return parsed.UTC(), err == nil
	}
	if seconds, ok := sub2APIInt64(value); ok {
		if seconds == 0 {
			return time.Time{}, true
		}
		return time.Unix(seconds, 0).UTC(), true
	}
	return time.Time{}, false
}

func sub2APIStringList(value any) ([]string, bool) {
	if text, ok := value.(string); ok {
		if strings.TrimSpace(text) == "" {
			return []string{}, true
		}
		items := strings.Split(text, ",")
		for index := range items {
			items[index] = strings.TrimSpace(items[index])
		}
		return items, true
	}
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, false
		}
		result = append(result, strings.TrimSpace(text))
	}
	return result, true
}

func validSub2APIIPlist(items []string) bool {
	if len(items) > sub2APIMaxKeyAllowIPs {
		return false
	}
	for _, item := range items {
		if item == "" || len(item) > 128 {
			return false
		}
		if net.ParseIP(item) == nil {
			if _, _, err := net.ParseCIDR(item); err != nil {
				return false
			}
		}
	}
	return true
}

func splitSub2APIIPlist(value string) []string {
	items := strings.Split(value, ",")
	result := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func redactSub2APIRawRequest(raw *model.RawRequest, body []byte) *model.RawRequest {
	if raw == nil {
		return nil
	}
	result := *raw
	result.Headers = make(map[string][]string, len(raw.Headers))
	for name, values := range raw.Headers {
		lower := strings.ToLower(name)
		copyValues := append([]string(nil), values...)
		if lower == "authorization" || lower == "x-api-key" || lower == "x-goog-api-key" || lower == "cookie" || lower == "set-cookie" {
			for index := range copyValues {
				copyValues[index] = "[REDACTED]"
			}
		}
		result.Headers[name] = copyValues
	}
	if len(body) > 0 {
		redacted := security.RedactPreview(string(body), 1<<20)
		result.BodyBase64 = base64.StdEncoding.EncodeToString([]byte(redacted))
	}
	result.URL = redactSub2APIURL(result.URL)
	return &result
}

func redactSub2APIURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.RawQuery == "" {
		return raw
	}
	query := parsed.Query()
	for key := range query {
		lower := strings.ToLower(key)
		if lower == "key" || strings.Contains(lower, "token") || strings.Contains(lower, "secret") || lower == "code" || lower == "state" {
			query.Set(key, "[REDACTED]")
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}
