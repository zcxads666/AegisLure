package app

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/zcxads666/AegisLure/internal/detect"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/oauth"
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
	case "newapi.spa":
		a.writeNewAPIIndex(w, http.StatusOK)
	case "newapi.asset":
		a.writeNewAPIAsset(w, r)
	case "newapi.logo":
		a.writeNewAPILogo(w, r)
	case "newapi.blocked", "newapi.unknown":
		a.writeNewAPINotFound(w)
	case "newapi.auth.refresh":
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w)
			return
		}
		// Anonymous bootstrap is a normal public-page path. A 204 response
		// lets the upstream client clear its local auth state without logging a
		// noisy 401 network error; authenticated sessions still receive the
		// regular refresh bundle below.
		if session.UserID == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		user, ok := a.store.GetHoneyUser(session.UserID)
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		session.UserID = user.ID
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": newAPIAuthBundle(user, session)})
	case "newapi.oauth.simulation":
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w)
			return
		}
		a.handleNewAPIOAuthSimulation(w, r, body, obs)
	case "newapi.oauth.start":
		provider, ok := newAPIOAuthProvider(r.URL.Path, false)
		if ok && a.oauthChannelEnabled(provider) {
			markNewAPIOAuthObservation(obs, string(provider), "login", "login", "enabled", "rejected")
			a.writeNewAPIOAuthRejected(w, http.StatusUnauthorized)
			return
		}
		broker := a.currentOAuthBroker()
		if broker == nil || !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"message": "Not found", "type": "invalid_request_error"}})
			return
		}
		authorization, err := broker.Begin(provider)
		if err != nil {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"message": "Not found", "type": "invalid_request_error"}})
			return
		}
		http.Redirect(w, r, authorization.URL, http.StatusFound)
	case "newapi.oauth.callback":
		provider, ok := newAPIOAuthProvider(r.URL.Path, true)
		if ok && a.oauthChannelEnabled(provider) {
			markNewAPIOAuthObservation(obs, string(provider), "login", "login", "enabled", "rejected")
			a.writeNewAPIOAuthRejected(w, http.StatusUnauthorized)
			return
		}
		broker := a.currentOAuthBroker()
		if broker == nil || !ok || r.URL.Query().Get("error") != "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "OAuth login could not be completed"})
			return
		}
		identity, err := broker.Callback(provider, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
		if err != nil {
			obs.Metadata["oauth_callback_outcome"] = "rejected"
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "OAuth login could not be completed"})
			return
		}
		user, _, err := a.bindHoneyOAuthIdentity(identity, broker.PolicyMode(provider))
		if err != nil {
			obs.Metadata["oauth_callback_outcome"] = "binding_failed"
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "OAuth login could not be completed"})
			return
		}
		_ = a.store.TouchHoneyUser(user.ID, func(current *model.HoneyUser) { current.LastSeen = time.Now().UTC() })
		a.setSessionUser(session.ID, user.ID)
		obs.Metadata["oauth_provider"] = string(identity.Provider)
		obs.Metadata["oauth_scopes"] = strings.Join(identity.Scopes, ",")
		obs.Metadata["oauth_callback_outcome"] = "accepted"
		// Ordinary OAuth login is not itself suspicious; only subsequent
		// behavior contributes risk evidence.
		score := 0
		obs.ScoreOverride = &score
		obs.IntentClass = "normal_use"
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"id": user.ID, "provider": identity.Provider}})
	case "newapi.user.register":
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w)
			return
		}
		if !a.allowRate("newapi-register-ip:"+requestSourceIP(r), 8, time.Minute) {
			obs.ExtraScore += 20
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_registration_rate_limited")
			a.writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "message": "registration temporarily unavailable"})
			return
		}
		if !newAPIStringFieldsOK(r, body, "username", "email", "password", "verification_code", "captcha", "invite_code") {
			obs.ExtraScore += 20
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_registration_shape_probe")
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid registration request"})
			return
		}
		value := requestValues(r, body)
		username := normalizeHoneyUsername(value["username"])
		if username == "" || len([]rune(username)) > 128 || !a.allowRate("newapi-register-user:"+security.Fingerprint(a.cfg.InstanceKey, username), 4, time.Minute) {
			obs.ExtraScore += 15
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_registration_invalid_or_enumeration_probe")
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid registration request"})
			return
		}
		password := value["password"]
		email, emailOK := normalizeHoneyEmail(value["email"])
		verificationCode := strings.TrimSpace(value["verification_code"])
		if verificationCode == "" {
			verificationCode = strings.TrimSpace(value["captcha"])
		}
		// Email verification is disabled for the standalone tenant. Accept the
		// actual New API form, which omits both fields, while still validating
		// optional values supplied by legacy clients/tests.
		if password == "" || len([]rune(password)) > 1024 || (email != "" && !emailOK) || !validHoneyVerificationCode(verificationCode) {
			obs.ExtraScore += 20
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_registration_shape_probe")
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid registration request"})
			return
		}
		lengthBucket, passwordClasses, weakClass := passwordProfile(password)
		userID := "hu_" + security.MustRandomToken(10)
		now := time.Now().UTC()
		user := model.HoneyUser{ID: userID, InstanceID: a.cfg.InstanceID, UsernameFP: security.Fingerprint(a.cfg.InstanceKey, username), UsernameHint: security.RedactPreview(username, 3), EmailLocalFP: emailLocalFingerprint(a.cfg.InstanceKey, email), EmailDomain: emailDomain(email), PasswordFP: security.Fingerprint(a.cfg.InstanceKey, password), PasswordLengthBucket: lengthBucket, PasswordClasses: passwordClasses, PasswordWeakClass: weakClass, VirtualQuota: 0, CreatedAt: now, LastSeen: now}
		if err := a.store.CreateHoneyUser(user); err != nil {
			// Keep duplicate usernames indistinguishable from other invalid
			// registration attempts; the username fingerprint never leaves the
			// local store.
			obs.ExtraScore += 25
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_registration_duplicate_attempt")
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid registration request"})
			return
		}
		if email != "" || verificationCode != "" {
			// Keep the legacy in-process test flow usable when it supplies the
			// optional verification fields. The real New API registration form
			// returns to sign-in and does not get an authenticated session here.
			a.setSessionUser(session.ID, user.ID)
		}
		obs.ExtraScore += 25
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_batch_registration_or_account_creation")
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"id": user.ID, "username": username, "quota": user.VirtualQuota}})
	case "newapi.user.login":
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w)
			return
		}
		value := requestValues(r, body)
		username := normalizeHoneyUsername(value["username"])
		accountRateOK := username == "" || a.allowRate("newapi-login-user:"+security.Fingerprint(a.cfg.InstanceKey, username), 8, time.Minute)
		if !a.allowRate("newapi-login-ip:"+requestSourceIP(r), 20, time.Minute) || !accountRateOK {
			obs.ExtraScore += 20
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_login_rate_limited")
			a.writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "message": "login temporarily unavailable"})
			return
		}
		user, ok := a.store.FindHoneyUser(security.Fingerprint(a.cfg.InstanceKey, username))
		if !ok || user.PasswordFP != security.Fingerprint(a.cfg.InstanceKey, value["password"]) {
			addNewAPILoginFailureRisk(obs)
			a.writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "invalid username or password"})
			return
		}
		_ = a.store.TouchHoneyUser(user.ID, func(u *model.HoneyUser) { u.LastSeen = time.Now().UTC() })
		a.setSessionUser(session.ID, user.ID)
		session.UserID = user.ID
		session.LastSeen = time.Now().UTC()
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "login successful", "data": newAPIAuthBundle(user, session)})
	case "newapi.user.logout":
		if r.Method != http.MethodPost {
			a.methodNotAllowed(w)
			return
		}
		a.clearSessionUser(session.ID)
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true})
	case "newapi.user.forgot":
		if r.Method != http.MethodPost && r.Method != http.MethodGet {
			a.methodNotAllowed(w)
			return
		}
		value := requestValues(r, body)
		// This endpoint deliberately returns the same response for every
		// target. Rate limiting is still applied to both the source and the
		// normalized target, but it never becomes an account oracle.
		target := strings.ToLower(strings.TrimSpace(value["email"]))
		if r.Method == http.MethodGet && target == "" {
			target = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("email")))
		}
		ipOK := a.allowRate("newapi-forgot-ip:"+requestSourceIP(r), 8, time.Minute)
		targetOK := target == "" || a.allowRate("newapi-forgot-target:"+security.Fingerprint(a.cfg.InstanceKey, target), 5, time.Minute)
		if !ipOK || !targetOK {
			obs.ExtraScore += 15
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_forgot_password_rate_limited")
		}
		a.writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "message": "If the account exists, password recovery instructions are available."})
	case "newapi.status":
		status := map[string]any{
			"status":                     true,
			"version":                    "v0.0.0",
			"system_name":                "New API",
			"logo":                       "/logo.png",
			"password_login_enabled":     true,
			"password_register_enabled":  true,
			"register_enabled":           true,
			"email_verification":         false,
			"turnstile_check":            false,
			"wechat_login":               false,
			"passkey_login":              false,
			"checkin_enabled":            true,
			"display_in_currency":        false,
			"display_token_stat_enabled": true,
			"quota_display_type":         "TOKENS",
			"quota_per_unit":             1,
			"demo_site_enabled":          false,
			"user_agreement_enabled":     false,
			"privacy_policy_enabled":     false,
			"docs_link":                  "/docs",
			"HeaderNavModules":           `{"home":true,"console":true,"pricing":{"enabled":true,"requireAuth":false},"rankings":{"enabled":true,"requireAuth":false},"docs":true,"about":true}`,
			"SidebarModulesAdmin":        `{"chat":{"enabled":false},"console":{"enabled":true,"detail":true,"token":true,"log":true,"midjourney":false,"task":false},"personal":{"enabled":true,"topup":false,"personal":true},"admin":{"enabled":false}}`,
			"footer_html":                `Frontend design and development by New API contributors.`,
			"notice":                     "",
		}
		for key, value := range a.newAPIOAuthStatus() {
			status[key] = value
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": status})
	case "newapi.checkin":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		now := time.Now().UTC()
		day := now.Format("2006-01-02")
		if r.Method == http.MethodGet {
			month := strings.TrimSpace(r.URL.Query().Get("month"))
			if month == "" {
				month = now.Format("2006-01")
			}
			records := make([]map[string]any, 0, 1)
			if user.CheckinDay != "" && strings.HasPrefix(user.CheckinDay, month) {
				records = append(records, map[string]any{"checkin_date": user.CheckinDay, "quota_awarded": 1000})
			}
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{
				"enabled": true,
				"stats": map[string]any{
					"checked_in_today": user.CheckinDay == day,
					"total_checkins":   len(records),
					"total_quota":      len(records) * 1000,
					"checkin_count":    len(records),
					"records":          records,
				},
			}})
			return
		}
		if user.CheckinDay == day {
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"quota_awarded": 0}, "already_checked_in": true, "quota": user.VirtualQuota})
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
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"quota_awarded": 1000}, "quota_added": 1000, "quota": balance})
	case "newapi.token.create":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		if !a.allowRate("newapi-token-ip:"+requestSourceIP(r), 40, time.Minute) || !a.allowRate("newapi-token-user:"+user.ID, 20, time.Minute) {
			obs.ExtraScore += 15
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_token_creation_rate_limited")
			a.writeJSON(w, http.StatusTooManyRequests, map[string]any{"success": false, "message": "token creation temporarily unavailable"})
			return
		}
		options, err := parseNewAPITokenOptions(r, body, false)
		if err != nil {
			obs.ExtraScore += 20
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_token_option_probe")
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid token request"})
			return
		}
		value, err := security.RandomToken(24)
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false})
			return
		}
		raw := "sk-proj-" + value
		name := ""
		if options.Name != nil {
			name = *options.Name
		}
		actual := r.URL.Path == "/api/token/"
		unlimited := actual
		if options.UnlimitedQuota != nil {
			unlimited = *options.UnlimitedQuota
		}
		remainQuota := int64(0)
		if options.RemainQuota != nil {
			remainQuota = *options.RemainQuota
		}
		group := ""
		if actual {
			group = "default"
		}
		if options.Group != nil && strings.TrimSpace(*options.Group) != "" {
			group = strings.TrimSpace(*options.Group)
		}
		var expiredAt time.Time
		if options.ExpiredTime != nil && *options.ExpiredTime > 0 {
			expiredAt = time.Unix(*options.ExpiredTime, 0).UTC()
		}
		token := model.HoneyToken{ID: "ht_" + security.MustRandomToken(8), HoneyUserID: user.ID, Hash: security.Fingerprint(a.cfg.InstanceKey, raw), PrefixHint: raw[:12], Name: name, ModelAllowlist: append([]string(nil), options.ModelAllowlist...), RemainQuota: remainQuota, UnlimitedQuota: unlimited, ExpiredAt: expiredAt, Group: group, AllowIPs: stringPointerValue(options.AllowIPs), AutoGroups: append([]string(nil), options.AutoGroups...), CrossGroupRetry: boolValue(options.CrossGroupRetry), CreatedAt: time.Now().UTC()}
		if err := a.store.AddToken(token); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false})
			return
		}
		a.rememberNewAPIRawKey(token.ID, raw)
		obs.ExtraScore += 20
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_honey_token_created")
		if actual {
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": newAPIPublicTokenView(token)})
			return
		}
		data := publicTokenView(token)
		data["key"] = raw
		data["warning"] = "The key is shown once and is valid only in this service."
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": data})
	case "newapi.token.list":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		actual := r.URL.Path == "/api/token/" || r.URL.Path == "/api/token/search"
		search := strings.TrimSpace(r.URL.Query().Get("search"))
		if search == "" {
			search = strings.TrimSpace(r.URL.Query().Get("keyword"))
		}
		if search == "" {
			search = strings.TrimSpace(r.URL.Query().Get("token"))
		}
		if len([]rune(search)) > 64 {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid token search"})
			return
		}
		includeDisabled := true
		if raw := r.URL.Query().Get("include_disabled"); raw != "" {
			parsed, parseErr := strconv.ParseBool(raw)
			if parseErr != nil {
				a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid token search"})
				return
			}
			includeDisabled = parsed
		}
		search = strings.ToLower(search)
		data := make([]map[string]any, 0)
		for _, token := range a.store.ListTokens(user.ID) {
			if !includeDisabled && !token.DisabledAt.IsZero() {
				continue
			}
			if search != "" && !strings.Contains(strings.ToLower(token.ID), search) && !strings.Contains(strings.ToLower(token.Name), search) && !strings.Contains(strings.ToLower(token.PrefixHint), search) {
				continue
			}
			if actual {
				data = append(data, newAPIPublicTokenView(token))
			} else {
				data = append(data, publicTokenView(token))
			}
		}
		if actual {
			page := boundedQueryInt(r, "p", 1, 1, 100000)
			pageSize := boundedQueryInt(r, "size", 10, 1, 100)
			start := (page - 1) * pageSize
			if start > len(data) {
				start = len(data)
			}
			end := start + pageSize
			if end > len(data) {
				end = len(data)
			}
			items := data[start:end]
			if items == nil {
				items = []map[string]any{}
			}
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"items": items, "total": len(data), "page": page, "page_size": pageSize}})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "object": "list", "data": data})
	case "newapi.token.get":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		tokenID, ok := newAPITokenIDForUser(a.store.ListTokens(user.ID), strings.TrimPrefix(r.URL.Path, "/api/token/"))
		if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "token not found"})
			return
		}
		token, ok := findHoneyToken(a.store.ListTokens(user.ID), tokenID)
		if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "token not found"})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": newAPIPublicTokenView(token)})
	case "newapi.token.auto-groups":
		if _, ok := a.requireHoneyUser(w, session); !ok {
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"groups": []string{}, "max_count": 5}})
	case "newapi.token.key":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		tokens := a.store.ListTokens(user.ID)
		tokenID, ok := newAPITokenKeyIDForUser(tokens, r.URL.Path)
		if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "token not found"})
			return
		}
		token, ok := findHoneyToken(tokens, tokenID)
		if !ok || !token.DisabledAt.IsZero() {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "token not found"})
			return
		}
		raw := a.newAPIRawKey(tokenID)
		if raw == "" {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "key is no longer available after restart"})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]string{"key": newAPIKeySuffix(raw)}})
	case "newapi.user.list":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		_, raw, canaryOK := a.ensureNewAPIUserListCanary(user.ID)
		if !canaryOK {
			a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{"success": false, "message": "user list unavailable"})
			return
		}
		entry := newAPIUserView(user)
		// These are intentionally synthetic, process-local canary values. They
		// resemble fields historical clients exposed without returning a real
		// account credential or any other user's data.
		entry["access_token"] = raw
		entry["api_key"] = raw
		entry["token"] = raw
		obs.ExtraScore += 40
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_user_list_honey_token_exposure")
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"items": []map[string]any{entry}, "total": 1}})
	case "newapi.video.proxy":
		obs.ExtraScore += 20
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_video_proxy_virtual_content")
		w.Header().Set("Content-Type", "video/mp4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0, 0, 0, 24, 'f', 't', 'y', 'p', 'm', 'p', '4', '2', 0, 0, 0, 0, 'm', 'p', '4', '2', 0, 0, 0, 0, 'm', 'p', '4', '2'})
	case "newapi.payment.webhook":
		if int64(len(body)) >= 256*1024 {
			obs.ExtraScore += 25
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_payment_webhook_bounded_body")
			a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"success": false, "message": "request body too large"})
			return
		}
		a.writeJSON(w, http.StatusAccepted, map[string]any{"success": true})
	case "newapi.user.binding":
		if _, ok := a.requireHoneyUser(w, session); !ok {
			return
		}
		obs.ExtraScore += 20
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_binding_virtual_state_change_rejected")
		a.writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "message": "binding request rejected"})
	case "newapi.token.batch":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		value, ok := decodeJSONObject(body)
		if !ok {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid token request"})
			return
		}
		ids, ok := value["ids"].([]any)
		if !ok || len(ids) > 100 {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid token ids"})
			return
		}
		deleted := 0
		for _, id := range ids {
			publicID, valid := newAPIInt64(id)
			if !valid || publicID <= 0 {
				continue
			}
			tokenID, found := newAPITokenIDForUser(a.store.ListTokens(user.ID), strconv.FormatInt(publicID, 10))
			if !found {
				continue
			}
			if a.store.DeleteToken(user.ID, tokenID) == nil {
				a.forgetNewAPIRawKey(tokenID)
				deleted++
			}
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": deleted})
	case "newapi.token.batch-keys":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		value, ok := decodeJSONObject(body)
		if !ok {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid token request"})
			return
		}
		ids, ok := value["ids"].([]any)
		if !ok || len(ids) > 100 {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid token ids"})
			return
		}
		keys := make(map[int64]string)
		tokens := a.store.ListTokens(user.ID)
		for _, id := range ids {
			publicID, valid := newAPIInt64(id)
			if !valid || publicID <= 0 {
				continue
			}
			tokenID, found := newAPITokenIDForUser(tokens, strconv.FormatInt(publicID, 10))
			if !found {
				continue
			}
			if raw := a.newAPIRawKey(tokenID); raw != "" {
				keys[publicID] = newAPIKeySuffix(raw)
			}
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"keys": keys}})
	case "newapi.token.update":
		if r.Method != http.MethodPatch && r.Method != http.MethodPut {
			a.methodNotAllowed(w)
			return
		}
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		options, err := parseNewAPITokenOptions(r, body, true)
		if err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid token request"})
			return
		}
		tokens := a.store.ListTokens(user.ID)
		actual := r.URL.Path == "/api/token/"
		tokenID := ""
		if actual {
			if options.ID == nil {
				a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "token id is required"})
				return
			}
			tokenID, ok = newAPITokenIDForUser(tokens, strconv.FormatInt(*options.ID, 10))
		} else {
			tokenID, ok = newAPITokenIDForUser(tokens, strings.TrimPrefix(r.URL.Path, "/api/token/"))
		}
		if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "token not found"})
			return
		}
		disabled := options.Disabled
		if options.Status != nil {
			value := *options.Status != 1
			disabled = &value
		}
		if options.Name == nil && disabled == nil && !options.ModelAllowlistSet && options.RemainQuota == nil && options.ExpiredTime == nil && options.UnlimitedQuota == nil && options.AllowIPs == nil && options.Group == nil && !options.AutoGroupsSet && options.CrossGroupRetry == nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid token request"})
			return
		}
		if err := a.store.UpdateToken(user.ID, tokenID, options.Name, disabled, options.ModelAllowlist); err != nil {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "token not found"})
			return
		}
		if err := a.store.TouchToken(tokenID, func(current *model.HoneyToken) {
			if options.RemainQuota != nil {
				current.RemainQuota = *options.RemainQuota
			}
			if options.ExpiredTime != nil {
				current.ExpiredAt = time.Time{}
				if *options.ExpiredTime > 0 {
					current.ExpiredAt = time.Unix(*options.ExpiredTime, 0).UTC()
				}
			}
			if options.UnlimitedQuota != nil {
				current.UnlimitedQuota = *options.UnlimitedQuota
			}
			if options.ModelLimitsEnabled != nil && !*options.ModelLimitsEnabled {
				current.ModelAllowlist = nil
			}
			if options.AllowIPs != nil {
				current.AllowIPs = *options.AllowIPs
			}
			if options.Group != nil {
				current.Group = *options.Group
			}
			if options.AutoGroupsSet {
				current.AutoGroups = append([]string(nil), options.AutoGroups...)
			}
			if options.CrossGroupRetry != nil {
				current.CrossGroupRetry = *options.CrossGroupRetry
			}
		}); err != nil {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "token not found"})
			return
		}
		updated, ok := findHoneyToken(a.store.ListTokens(user.ID), tokenID)
		if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "token not found"})
			return
		}
		obs.ExtraScore += 10
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_honey_token_updated")
		if actual {
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": newAPIPublicTokenView(updated)})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": publicTokenView(updated)})
	case "newapi.token.delete":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		tokens := a.store.ListTokens(user.ID)
		tokenID, ok := newAPITokenIDForUser(tokens, strings.TrimPrefix(r.URL.Path, "/api/token/"))
		if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "token not found"})
			return
		}
		if err := a.store.DeleteToken(user.ID, tokenID); err != nil {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "token not found"})
			return
		}
		a.forgetNewAPIRawKey(tokenID)
		obs.ExtraScore += 10
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_honey_token_deleted")
		if r.URL.Path != "/api/token/" && !strings.HasPrefix(strings.TrimPrefix(r.URL.Path, "/api/token/"), "ht_") {
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"id": newAPIPublicID(tokenID)}})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]string{"id": tokenID}})
	case "newapi.user.status":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		today := time.Now().UTC().Format("2006-01-02")
		tokens := a.store.ListTokens(user.ID)
		data := newAPIUserView(user)
		data["token_count"] = len(tokens)
		data["checked_in"] = user.CheckinDay == today
		data["checkin_day"] = user.CheckinDay
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": data})
	case "newapi.user.update":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		if r.Method == http.MethodDelete {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Not found"})
			return
		}
		value, valid := decodeJSONObject(body)
		if !valid {
			a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid profile request"})
			return
		}
		passwordChanged := false
		if raw, exists := value["password"]; exists {
			password, ok := raw.(string)
			if !ok || len([]rune(password)) == 0 || len([]rune(password)) > 1024 {
				a.writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "message": "invalid password"})
				return
			}
			if original, exists := value["original_password"]; exists {
				originalPassword, ok := original.(string)
				if !ok || user.PasswordFP != security.Fingerprint(a.cfg.InstanceKey, originalPassword) {
					a.writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "message": "current password is incorrect"})
					return
				}
			}
			if err := a.store.TouchHoneyUser(user.ID, func(current *model.HoneyUser) {
				current.PasswordFP = security.Fingerprint(a.cfg.InstanceKey, password)
				current.PasswordLengthBucket, current.PasswordClasses, current.PasswordWeakClass = passwordProfile(password)
			}); err != nil {
				a.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false})
				return
			}
			passwordChanged = true
		}
		updated, _ := a.store.GetHoneyUser(user.ID)
		if passwordChanged {
			session.UserID = updated.ID
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": newAPIAuthBundle(updated, session)})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": newAPIUserView(updated)})
	case "newapi.user.models":
		if _, ok := a.requireHoneyUser(w, session); !ok {
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": newAPIProfileModelIDs(a.catalogForSession(model.ProductNewAPI, "user", session))})
	case "newapi.user.groups":
		if _, ok := a.requireHoneyUser(w, session); !ok {
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"default": map[string]any{"desc": "Default group", "ratio": 1}}})
	case "newapi.user.setting":
		if _, ok := a.requireHoneyUser(w, session); !ok {
			return
		}
		if r.Method != http.MethodPut {
			a.methodNotAllowed(w)
			return
		}
		// Settings are accepted for UI compatibility but never trigger a
		// notification, webhook, billing or other outbound integration.
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{}})
	case "newapi.user.token":
		if _, ok := a.requireHoneyUser(w, session); !ok {
			return
		}
		a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Not found"})
	case "newapi.user.sessions":
		if _, ok := a.requireHoneyUser(w, session); !ok {
			return
		}
		if r.Method == http.MethodGet {
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": []map[string]any{newAPISessionView(session)}})
			return
		}
		if r.Method == http.MethodDelete {
			value := strings.TrimPrefix(r.URL.Path, "/api/user/sessions/")
			if value != "" && value != session.ID {
				a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "session not found"})
				return
			}
			a.clearSessionUser(session.ID)
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true})
	case "newapi.user.oauth-bindings":
		if _, ok := a.requireHoneyUser(w, session); !ok {
			return
		}
		if r.Method == http.MethodGet {
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": []any{}})
			return
		}
		a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Not found"})
	case "newapi.verification":
		// Deliberately uniform and side-effect free: no email or verification
		// provider is configured in the single-node bait.
		a.writeJSON(w, http.StatusAccepted, map[string]any{"success": true, "message": "If applicable, a verification code is available."})
	case "newapi.home-content":
		// An empty custom-home response makes the real bundled New API home
		// sections render, while avoiding an iframe or remote content source.
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": ""})
	case "newapi.about-content":
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "", "data": ""})
	case "newapi.pricing-data":
		a.writeJSON(w, http.StatusOK, newAPIPricingView(a.catalogForSession(model.ProductNewAPI, "guest", session)))
	case "newapi.perf-summary":
		events, err := a.store.Events(1000, model.ProductNewAPI, "")
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "metrics unavailable", "data": map[string]any{"models": []any{}}})
			return
		}
		hours := boundedQueryInt(r, "hours", 24, 1, 168)
		a.writeJSON(w, http.StatusOK, newAPIPerformanceSummaryView(events, hours, time.Now().UTC()))
	case "newapi.perf-metrics":
		events, err := a.store.Events(1000, model.ProductNewAPI, "")
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "message": "metrics unavailable", "data": map[string]any{"model_name": "", "groups": []any{}}})
			return
		}
		hours := boundedQueryInt(r, "hours", 24, 1, 168)
		modelName := strings.TrimSpace(r.URL.Query().Get("model"))
		a.writeJSON(w, http.StatusOK, newAPIPerformanceDetailView(events, modelName, hours, time.Now().UTC()))
	case "newapi.rankings-data":
		a.writeJSON(w, http.StatusOK, newAPIRankingsView())
	case "newapi.setup":
		if r.Method != http.MethodGet {
			a.writeJSON(w, http.StatusNotFound, map[string]any{"success": false, "message": "Not found"})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"status": true}})
	case "newapi.notice":
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": ""})
	case "newapi.dashboard-data":
		if _, ok := a.requireHoneyUser(w, session); !ok {
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": []any{}})
	case "newapi.usage.logs":
		user, ok := a.requireHoneyUser(w, session)
		if !ok {
			return
		}
		obs.EffectOutcome = "verified"
		obs.ExtraScore += 15
		obs.ExtraReasons = append(obs.ExtraReasons, "post_call_effect_verification")
		events, _ := a.store.Events(200, model.ProductNewAPI, "")
		if strings.HasSuffix(r.URL.Path, "/stat") {
			var quota int64
			for _, event := range events {
				if event.SessionID == session.ID && event.InvocationID != "" {
					quota += event.SimulatedCost
				}
			}
			a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"quota": quota, "rpm": 0, "tpm": 0}})
			return
		}
		logs := make([]map[string]any, 0)
		for _, event := range events {
			if event.SessionID != session.ID || event.InvocationID == "" {
				continue
			}
			logs = append(logs, newAPIUsageLog(event, user))
		}
		page := boundedQueryInt(r, "p", 1, 1, 100000)
		pageSize := boundedQueryInt(r, "page_size", 20, 1, 100)
		start := (page - 1) * pageSize
		if start > len(logs) {
			start = len(logs)
		}
		end := start + pageSize
		if end > len(logs) {
			end = len(logs)
		}
		items := logs[start:end]
		if items == nil {
			items = []map[string]any{}
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "data": map[string]any{"items": items, "total": len(logs), "page": page, "page_size": pageSize}})
	case "openai.models":
		audience := "guest"
		if session.UserID != "" {
			audience = "user"
		}
		catalog := a.catalogForSession(model.ProductNewAPI, audience, session)
		switch newAPIModelListFormat(r) {
		case "anthropic":
			a.writeJSON(w, http.StatusOK, newAPIAnthropicModelList(a.cfg.InstanceKey, catalog))
		case "gemini":
			a.writeJSON(w, http.StatusOK, newAPIGeminiModelList(catalog))
		default:
			a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": profiles.OpenAIModelCardsForCatalog(a.cfg.InstanceKey, catalog, "new-api")})
		}
	case "gemini.models":
		audience := "guest"
		if session.UserID != "" {
			audience = "user"
		}
		a.writeJSON(w, http.StatusOK, newAPIGeminiModelList(a.catalogForSession(model.ProductNewAPI, audience, session)))
	case "openai.model":
		audience := "guest"
		if session.UserID != "" {
			audience = "user"
		}
		requestedModel, ok := newAPIOpenAIModelFromPath(r.URL.Path)
		if !ok {
			a.writeNewAPIProtocolError(w, "openai.models", http.StatusNotFound, "Not found", "invalid_request_error")
			return
		}
		entry, found := a.resolveCatalogModelForAudience(model.ProductNewAPI, requestedModel, audience)
		if !found {
			// New API returns a model-not-found error object for this lookup.
			a.writeJSON(w, http.StatusOK, map[string]any{"error": map[string]string{"message": fmt.Sprintf("The model '%s' does not exist", requestedModel), "type": "invalid_request_error", "param": "model", "code": "model_not_found"}})
			return
		}
		if newAPIModelListFormat(r) == "anthropic" {
			a.writeJSON(w, http.StatusOK, newAPIAnthropicModelList(a.cfg.InstanceKey, []profiles.CatalogEntry{entry})["data"].([]map[string]any)[0])
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"id": entry.ID, "object": "model", "created": profiles.OpenAIModelCardsForCatalog(a.cfg.InstanceKey, []profiles.CatalogEntry{entry}, "new-api")[0].Created, "owned_by": "new-api"})
	case "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings", "anthropic.messages", "gemini.generate", "gemini.stream":
		a.newAPIInvoke(w, r, body, session, obs)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"message": "Not found", "type": "invalid_request_error"}})
	}
}

func (a *App) newAPIInvoke(w *captureWriter, r *http.Request, body []byte, session Session, obs *Observation) {
	token, auth := a.newAPIHoneyAuth(r, obs.RouteTemplate)
	leakedUserListKey := auth == "valid_honey_key" && token.Name == newAPIUserListCanaryName
	if leakedUserListKey {
		auth = "leaked_key_reused"
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_user_list_honey_token_reused")
	}
	if auth == "valid_honey_key" || leakedUserListKey {
		obs.CredentialFingerprint = token.Hash
	}
	if auth != "valid_honey_key" && !leakedUserListKey {
		a.startInvocation(obs, auth, false)
		a.writeNewAPIProtocolError(w, obs.RouteTemplate, http.StatusUnauthorized, "Incorrect API key provided", "invalid_request_error")
		return
	}
	if session.UserID != "" && token.HoneyUserID != session.UserID && !leakedUserListKey {
		obs.AuthOutcome = "invalid"
		a.startInvocation(obs, "invalid", false)
		a.writeNewAPIProtocolError(w, obs.RouteTemplate, http.StatusUnauthorized, "API key is not available to this session", "invalid_request_error")
		return
	}
	_ = a.store.TouchToken(token.ID, func(current *model.HoneyToken) { current.LastUsedAt = time.Now().UTC() })
	requestedModel := newAPIRequestedModel(r, body, obs.RouteTemplate)
	resolvedEntry, modelResolved := a.resolveCatalogModelForSession(model.ProductNewAPI, requestedModel, "user", session)
	if len(token.ModelAllowlist) > 0 && (!modelResolved || !containsString(token.ModelAllowlist, resolvedEntry.ID)) {
		obs.ExtraScore += 25
		obs.ExtraReasons = append(obs.ExtraReasons, "newapi_token_model_restriction_probe")
		a.startInvocation(obs, auth, false)
		a.writeNewAPIProtocolError(w, obs.RouteTemplate, http.StatusForbidden, "model is not available for this API key", "invalid_request_error")
		return
	}
	validationErr := validateNewAPIInvocation(r, body, obs.RouteTemplate)
	switch obs.RouteTemplate {
	case "anthropic.messages":
		validationErr = validateNewAPIAnthropicInvocation(r, body)
	case "gemini.generate", "gemini.stream":
		validationErr = validateNewAPIGeminiInvocation(r, body)
	}
	if validationErr != "" {
		a.startInvocation(obs, auth, false)
		message := "invalid request"
		if validationErr == "quota_overflow" {
			obs.ExtraScore += 35
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_quota_overflow_probe")
		} else {
			obs.ExtraScore += 10
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_invalid_request")
		}
		a.writeNewAPIProtocolError(w, obs.RouteTemplate, http.StatusBadRequest, message, "invalid_request_error")
		return
	}
	if modelResolved == false && requestedModel != "" && (obs.RouteTemplate == "anthropic.messages" || obs.RouteTemplate == "gemini.generate" || obs.RouteTemplate == "gemini.stream") {
		a.startInvocation(obs, auth, false)
		a.writeNewAPIProtocolError(w, obs.RouteTemplate, http.StatusNotFound, "model not found", "not_found_error")
		return
	}
	modelName := a.validModelNameForSession(model.ProductNewAPI, requestedModel, session)
	if modelResolved {
		obs.ModelID, obs.ModelResolved = resolvedEntry.ID, true
	} else if requestedModel == "" {
		obs.ModelID, obs.ModelResolved = modelName, true
	} else {
		obs.ModelID = modelName
	}
	obs.ExtraScore += 25
	obs.ExtraReasons = append(obs.ExtraReasons, "newapi_synthetic_compute_use")
	a.startInvocation(obs, auth, true)
	cost := int64(maxInt(1, len(body)/4))
	if token.Name != newAPIUserListCanaryName {
		if _, err := a.store.ConsumeQuota(token.HoneyUserID, token.ID, obs.InvocationID, cost); err != nil {
			obs.ExecutionOutcome = "rejected_before_dispatch"
			obs.ExtraReasons = append(obs.ExtraReasons, "newapi_virtual_quota_exhausted")
			a.writeNewAPIProtocolError(w, obs.RouteTemplate, http.StatusPaymentRequired, "insufficient quota", "insufficient_quota")
			return
		}
	}
	switch obs.RouteTemplate {
	case "anthropic.messages":
		a.writeAnthropicResponse(w, body, streamRequested(r, body), obs, modelName)
	case "gemini.generate", "gemini.stream":
		a.writeGeminiResponse(w, body, obs.RouteTemplate == "gemini.stream" || streamRequested(r, body), obs, modelName)
	default:
		a.writeOpenAIResponseForRoute(w, body, model.ProductNewAPI, obs.RouteTemplate, streamRequested(r, body), obs, modelName)
	}
}

func newAPIOAuthProvider(path string, callback bool) (oauth.Provider, bool) {
	value := strings.TrimPrefix(path, "/api/oauth/")
	suffix := "/start"
	if callback {
		suffix = "/callback"
	}
	if strings.HasSuffix(value, suffix) {
		value = strings.TrimSuffix(value, suffix)
	}
	if value == "" || strings.Contains(value, "/") {
		return "", false
	}
	return oauth.ParseProvider(value)
}

func (a *App) bindHoneyOAuthIdentity(identity oauth.Identity, policyMode string) (model.HoneyUser, model.HoneyIdentity, error) {
	if identity.Provider == "" || identity.SubjectHMAC == "" {
		return model.HoneyUser{}, model.HoneyIdentity{}, fmt.Errorf("oauth identity is incomplete")
	}
	provider := string(identity.Provider)
	if existing, ok := a.store.FindHoneyIdentity(provider, identity.SubjectHMAC); ok {
		user, userOK := a.store.GetHoneyUser(existing.HoneyUserID)
		if !userOK {
			return model.HoneyUser{}, model.HoneyIdentity{}, fmt.Errorf("oauth identity user is missing")
		}
		updated, err := a.store.BindHoneyIdentity(model.HoneyIdentity{Provider: provider, SubjectHMAC: identity.SubjectHMAC, Scopes: identity.Scopes}, user)
		return user, updated, err
	}
	now := time.Now().UTC()
	user := model.HoneyUser{
		ID:                   "hu_" + security.MustRandomToken(10),
		InstanceID:           a.cfg.InstanceID,
		UsernameFP:           security.Fingerprint(a.cfg.InstanceKey, "oauth-user:"+provider+":"+identity.SubjectHMAC),
		UsernameHint:         string(identity.Provider) + " account",
		PasswordFP:           security.Fingerprint(a.cfg.InstanceKey, "oauth-password:"+identity.SubjectHMAC),
		PasswordLengthBucket: "oauth",
		PasswordClasses:      []string{"oauth"},
		VirtualQuota:         0,
		CreatedAt:            now,
		LastSeen:             now,
	}
	linked := model.HoneyIdentity{ID: "hi_" + security.MustRandomToken(8), Provider: provider, SubjectHMAC: identity.SubjectHMAC, HoneyUserID: user.ID, Scopes: append([]string(nil), identity.Scopes...), PolicyMode: policyMode, LinkedAt: now, LastSeenAt: now}
	bound, err := a.store.BindHoneyIdentity(linked, user)
	return user, bound, err
}

type newAPITokenOptions struct {
	Name               *string
	Disabled           *bool
	ModelAllowlist     []string
	ModelAllowlistSet  bool
	RemainQuota        *int64
	ExpiredTime        *int64
	UnlimitedQuota     *bool
	ModelLimitsEnabled *bool
	AllowIPs           *string
	Group              *string
	AutoGroups         []string
	AutoGroupsSet      bool
	CrossGroupRetry    *bool
	ID                 *int64
	Status             *int
}

func parseNewAPITokenOptions(r *http.Request, body []byte, allowDisabled bool) (newAPITokenOptions, error) {
	options := newAPITokenOptions{}
	if len(body) == 0 {
		return options, nil
	}
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(string(body))
		if err != nil {
			return options, fmt.Errorf("invalid token form")
		}
		if raw, ok := values["name"]; ok {
			if len(raw) != 1 {
				return options, fmt.Errorf("invalid token name")
			}
			name := strings.TrimSpace(raw[0])
			if len([]rune(name)) > 128 {
				return options, fmt.Errorf("token name is too long")
			}
			options.Name = &name
		}
		if raw, ok := values["model_allowlist"]; ok {
			options.ModelAllowlistSet = true
			items := make([]string, 0, len(raw))
			for _, item := range raw {
				items = append(items, strings.Split(item, ",")...)
			}
			canonical, err := canonicalNewAPIModelAllowlist(items)
			if err != nil {
				return options, err
			}
			options.ModelAllowlist = canonical
		}
		if raw, ok := values["disabled"]; ok {
			if !allowDisabled || len(raw) != 1 {
				return options, fmt.Errorf("disabled is not allowed")
			}
			disabled, err := strconv.ParseBool(raw[0])
			if err != nil {
				return options, fmt.Errorf("invalid disabled flag")
			}
			options.Disabled = &disabled
		}
		if raw, ok := values["remain_quota"]; ok && len(raw) == 1 {
			value, err := strconv.ParseInt(strings.TrimSpace(raw[0]), 10, 64)
			if err != nil || value < 0 {
				return options, fmt.Errorf("invalid remain quota")
			}
			options.RemainQuota = &value
		}
		if raw, ok := values["expired_time"]; ok && len(raw) == 1 {
			value, err := strconv.ParseInt(strings.TrimSpace(raw[0]), 10, 64)
			if err != nil {
				return options, fmt.Errorf("invalid expired time")
			}
			options.ExpiredTime = &value
		}
		return options, nil
	}
	if !jsonContentTypeOK(r) {
		return options, fmt.Errorf("invalid token content type")
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return options, fmt.Errorf("invalid token JSON")
	}
	if raw, exists := value["name"]; exists {
		name, ok := raw.(string)
		if !ok || len([]rune(strings.TrimSpace(name))) > 128 {
			return options, fmt.Errorf("invalid token name")
		}
		name = strings.TrimSpace(name)
		options.Name = &name
	}
	if raw, exists := value["model_allowlist"]; exists {
		options.ModelAllowlistSet = true
		canonical, err := canonicalNewAPIModelAllowlist(raw)
		if err != nil {
			return options, err
		}
		options.ModelAllowlist = canonical
	}
	if raw, exists := value["disabled"]; exists {
		if !allowDisabled {
			return options, fmt.Errorf("disabled is not allowed")
		}
		disabled, ok := raw.(bool)
		if !ok {
			return options, fmt.Errorf("invalid disabled flag")
		}
		options.Disabled = &disabled
	}
	if raw, exists := value["remain_quota"]; exists {
		parsed, ok := newAPIInt64(raw)
		if !ok || parsed < 0 {
			return options, fmt.Errorf("invalid remain quota")
		}
		options.RemainQuota = &parsed
	}
	if raw, exists := value["expired_time"]; exists {
		parsed, ok := newAPIInt64(raw)
		if !ok {
			return options, fmt.Errorf("invalid expired time")
		}
		options.ExpiredTime = &parsed
	}
	if raw, exists := value["unlimited_quota"]; exists {
		parsed, ok := newAPIBool(raw)
		if !ok {
			return options, fmt.Errorf("invalid unlimited quota")
		}
		options.UnlimitedQuota = &parsed
	}
	if raw, exists := value["model_limits_enabled"]; exists {
		parsed, ok := newAPIBool(raw)
		if !ok {
			return options, fmt.Errorf("invalid model limits flag")
		}
		options.ModelLimitsEnabled = &parsed
	}
	if raw, exists := value["model_limits"]; exists {
		options.ModelAllowlistSet = true
		canonical, err := canonicalNewAPIModelAllowlist(raw)
		if err != nil {
			return options, err
		}
		options.ModelAllowlist = canonical
	}
	if raw, exists := value["allow_ips"]; exists {
		parsed, ok := raw.(string)
		if !ok || len([]rune(parsed)) > 4096 {
			return options, fmt.Errorf("invalid allow ips")
		}
		parsed = strings.TrimSpace(parsed)
		options.AllowIPs = &parsed
	}
	if raw, exists := value["group"]; exists {
		parsed, ok := raw.(string)
		if !ok || len([]rune(parsed)) > 128 {
			return options, fmt.Errorf("invalid group")
		}
		parsed = strings.TrimSpace(parsed)
		options.Group = &parsed
	}
	if raw, exists := value["auto_groups"]; exists {
		options.AutoGroupsSet = true
		parsed, ok := newAPIStringSlice(raw, 5, 128)
		if !ok {
			return options, fmt.Errorf("invalid auto groups")
		}
		options.AutoGroups = parsed
	}
	if raw, exists := value["cross_group_retry"]; exists {
		parsed, ok := newAPIBool(raw)
		if !ok {
			return options, fmt.Errorf("invalid cross group retry")
		}
		options.CrossGroupRetry = &parsed
	}
	if raw, exists := value["id"]; exists {
		parsed, ok := newAPIInt64(raw)
		if !ok || parsed <= 0 {
			return options, fmt.Errorf("invalid token id")
		}
		options.ID = &parsed
	}
	if raw, exists := value["status"]; exists {
		parsed, ok := newAPIInt64(raw)
		if !ok || parsed < 1 || parsed > 4 {
			return options, fmt.Errorf("invalid token status")
		}
		status := int(parsed)
		options.Status = &status
	}
	return options, nil
}

func newAPIInt64(raw any) (int64, bool) {
	switch value := raw.(type) {
	case json.Number:
		parsed, err := value.Int64()
		return parsed, err == nil
	case float64:
		parsed := int64(value)
		return parsed, float64(parsed) == value
	case int:
		return int64(value), true
	case int64:
		return value, true
	default:
		return 0, false
	}
}

func newAPIBool(raw any) (bool, bool) {
	switch value := raw.(type) {
	case bool:
		return value, true
	case json.Number:
		parsed, err := value.Int64()
		return parsed != 0, err == nil && (parsed == 0 || parsed == 1)
	case float64:
		return value != 0, value == 0 || value == 1
	default:
		return false, false
	}
}

func newAPIStringSlice(raw any, limit, itemLimit int) ([]string, bool) {
	var values []string
	switch value := raw.(type) {
	case string:
		if strings.TrimSpace(value) != "" {
			values = strings.Split(value, ",")
		}
	case []any:
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			values = append(values, text)
		}
	case []string:
		values = append(values, value...)
	default:
		return nil, false
	}
	if len(values) > limit {
		return nil, false
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len([]rune(value)) > itemLimit || seen[value] {
			if seen[value] {
				continue
			}
			return nil, false
		}
		seen[value] = true
		result = append(result, value)
	}
	return result, true
}

func stringPointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func boolValue(value *bool) bool {
	return value != nil && *value
}

func boundedQueryInt(r *http.Request, key string, fallback, minimum, maximum int) int {
	value := strings.TrimSpace(r.URL.Query().Get(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return fallback
	}
	return parsed
}

func canonicalNewAPIModelAllowlist(raw any) ([]string, error) {
	var values []string
	switch value := raw.(type) {
	case string:
		if strings.TrimSpace(value) != "" {
			values = strings.Split(value, ",")
		}
	case []string:
		values = append(values, value...)
	case []any:
		if len(value) > 32 {
			return nil, fmt.Errorf("too many models")
		}
		for _, item := range value {
			name, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("invalid model allowlist")
			}
			values = append(values, name)
		}
	default:
		return nil, fmt.Errorf("invalid model allowlist")
	}
	if len(values) > 32 {
		return nil, fmt.Errorf("too many models")
	}
	result := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if len([]rune(value)) > 256 {
			return nil, fmt.Errorf("model name is too long")
		}
		entry, ok := profiles.ResolveModel(model.ProductNewAPI, value)
		if !ok {
			return nil, fmt.Errorf("unknown model")
		}
		if !seen[entry.ID] {
			seen[entry.ID] = true
			result = append(result, entry.ID)
		}
	}
	return result, nil
}

func newAPITokenID(path string) (string, bool) {
	if !strings.HasPrefix(path, "/api/token/") {
		return "", false
	}
	id, err := url.PathUnescape(strings.TrimPrefix(path, "/api/token/"))
	if err != nil || id == "" || len(id) > 128 || !strings.HasPrefix(id, "ht_") || strings.ContainsAny(id, "/\\\r\n") {
		return "", false
	}
	return id, true
}

func findHoneyToken(tokens []model.HoneyToken, id string) (model.HoneyToken, bool) {
	for _, token := range tokens {
		if token.ID == id {
			return token, true
		}
	}
	return model.HoneyToken{}, false
}

func publicTokenView(token model.HoneyToken) map[string]any {
	allowlist := append([]string{}, token.ModelAllowlist...)
	view := map[string]any{
		"id":              token.ID,
		"name":            token.Name,
		"prefix_hint":     token.PrefixHint,
		"model_allowlist": allowlist,
		"created_at":      token.CreatedAt,
		"disabled":        !token.DisabledAt.IsZero(),
	}
	if !token.DisabledAt.IsZero() {
		view["disabled_at"] = token.DisabledAt
	}
	if !token.LastUsedAt.IsZero() {
		view["last_used_at"] = token.LastUsedAt
	}
	return view
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validateNewAPIInvocation(r *http.Request, body []byte, route string) string {
	if !jsonContentTypeOK(r) {
		return "invalid_request"
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return "invalid_request"
	}
	if raw, exists := value["model"]; exists {
		modelName, ok := raw.(string)
		if !ok || strings.TrimSpace(modelName) == "" || len([]rune(modelName)) > 256 {
			return "invalid_request"
		}
	}
	if raw, exists := value["stream"]; exists {
		if _, ok := raw.(bool); !ok {
			return "invalid_request"
		}
	}
	for _, field := range []string{"max_tokens", "max_completion_tokens", "n", "best_of"} {
		raw, exists := value[field]
		if !exists {
			continue
		}
		if newAPIIntegerOverflow(raw, 1_000_000) {
			return "quota_overflow"
		}
		number, ok := boundedNewAPIInteger(raw, 1_000_000)
		if !ok || number < 1 {
			return "invalid_request"
		}
	}
	_ = route
	return ""
}

func boundedNewAPIInteger(value any, maximum int64) (int64, bool) {
	switch number := value.(type) {
	case float64:
		if math.IsNaN(number) || math.IsInf(number, 0) || number < 1 || number > float64(maximum) || math.Trunc(number) != number {
			return 0, false
		}
		return int64(number), true
	case float32:
		converted := float64(number)
		if math.IsNaN(converted) || math.IsInf(converted, 0) || converted < 1 || converted > float64(maximum) || math.Trunc(converted) != converted {
			return 0, false
		}
		return int64(number), true
	case int:
		if number < 1 || int64(number) > maximum {
			return 0, false
		}
		return int64(number), true
	case int64:
		if number < 1 || number > maximum {
			return 0, false
		}
		return number, true
	case json.Number:
		parsed, err := strconv.ParseInt(string(number), 10, 64)
		if err != nil || parsed < 1 || parsed > maximum {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func newAPIIntegerOverflow(value any, maximum int64) bool {
	switch number := value.(type) {
	case float64:
		return math.IsInf(number, 0) || number > float64(maximum) || number < -float64(maximum)
	case float32:
		return float64(number) > float64(maximum) || float64(number) < -float64(maximum)
	case int:
		return int64(number) > maximum || int64(number) < -maximum
	case int64:
		return number > maximum || number < -maximum
	case json.Number:
		parsed, err := strconv.ParseInt(string(number), 10, 64)
		if err == nil {
			return parsed > maximum || parsed < -maximum
		}
		floating, floatErr := strconv.ParseFloat(string(number), 64)
		return floatErr == nil && (floating > float64(maximum) || floating < -float64(maximum))
	default:
		return false
	}
}

func normalizeHoneyUsername(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeHoneyEmail(value string) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(value))
	if email == "" {
		return "", true
	}
	if len([]rune(email)) > 320 || strings.Count(email, "@") != 1 || strings.ContainsAny(email, "\r\n\t ") {
		return "", false
	}
	parts := strings.SplitN(email, "@", 2)
	if parts[0] == "" || parts[1] == "" || len([]rune(parts[1])) > 255 || strings.HasPrefix(parts[1], ".") || strings.HasSuffix(parts[1], ".") {
		return "", false
	}
	return email, true
}

func emailLocalFingerprint(key, email string) string {
	if email == "" {
		return ""
	}
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[0] == "" {
		return ""
	}
	return security.Fingerprint(key, parts[0])
}

func validHoneyVerificationCode(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 6 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func passwordProfile(password string) (string, []string, string) {
	length := len([]rune(password))
	lengthBucket := "32_plus"
	switch {
	case length == 0:
		lengthBucket = "empty"
	case length <= 7:
		lengthBucket = "1_7"
	case length <= 11:
		lengthBucket = "8_11"
	case length <= 15:
		lengthBucket = "12_15"
	case length <= 31:
		lengthBucket = "16_31"
	}
	seen := map[string]bool{}
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			seen["lower"] = true
		case unicode.IsUpper(r):
			seen["upper"] = true
		case unicode.IsDigit(r):
			seen["digit"] = true
		case unicode.IsSpace(r):
			seen["space"] = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			seen["symbol"] = true
		default:
			seen["other"] = true
		}
	}
	classes := make([]string, 0, len(seen))
	for _, class := range []string{"lower", "upper", "digit", "symbol", "space", "other"} {
		if seen[class] {
			classes = append(classes, class)
		}
	}
	weakClass := classifyWeakPassword(password)
	return lengthBucket, classes, weakClass
}

func classifyWeakPassword(password string) string {
	normalized := strings.ToLower(strings.TrimSpace(password))
	switch normalized {
	case "password", "password1", "password123", "123456", "12345678", "123456789", "qwerty", "qwerty123", "admin", "admin123", "letmein", "welcome", "changeme":
		return "common_password"
	}
	if normalized != "" {
		allDigits := true
		for _, r := range normalized {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits && len(normalized) <= 10 {
			return "numeric_only"
		}
	}
	return ""
}

func (a *App) handleVLLM(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	w.Header().Set("Server", "uvicorn")
	switch obs.RouteTemplate {
	case "vllm.root":
		a.writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Not Found"})
	case "vllm.health":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, effectOwner, _ := virtualEffectOwner(profile, session)
		if len(a.store.ActiveEffects(effectOwner, model.ProductVLLM, time.Now().UTC())) > 0 {
			_ = a.store.MarkEffectsVerified(effectOwner, model.ProductVLLM, "virtual_worker_degraded", time.Now().UTC())
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
		a.writeJSON(w, http.StatusOK, map[string]string{"version": profile.Persona.VLLM.Version})
	case "vllm.metrics":
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(a.vllmMetrics(profile)))
	case "openai.models":
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": profiles.VLLMModelCardsForProfile(a.cfg.InstanceKey, profile.Persona.VLLM)})
	case "vllm.invocations", "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings":
		a.vllmInvoke(w, r, profile, session, body, obs)
	case "vllm.tokenize":
		a.writeJSON(w, http.StatusOK, map[string]any{"tokens": []int{101, 2026, 8080, 102}, "count": 4})
	case "vllm.detokenize":
		a.writeJSON(w, http.StatusOK, map[string]any{"prompt": "The request was decoded."})
	case "vllm.docs":
		if !profile.Persona.VLLM.DocsEnabled {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Not Found"})
			return
		}
		a.writeHTML(w, http.StatusOK, "vLLM OpenAI-Compatible Server", vllmDocsHTML)
	case "vllm.openapi":
		if !profile.Persona.VLLM.DocsEnabled {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Not Found"})
			return
		}
		a.writeJSON(w, http.StatusOK, vllmOpenAPISchema(profile))
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]any{"detail": "Not Found"})
	}
}

func (a *App) vllmInvoke(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	value, validationErr := validateVLLMRequest(r, body, obs.RouteTemplate)
	if validationErr != nil {
		a.notePersonaError(model.ProductVLLM, profile.Persona.VLLM.MetricsModelName())
		a.startInvocation(obs, "invalid", false)
		a.writeJSON(w, validationErr.Status, map[string]any{"detail": validationErr.Detail})
		return
	}
	token, auth := a.honeyAuth(r)
	if auth == "valid_honey_key" {
		obs.CredentialFingerprint = token.Hash
	}
	if obs.RouteTemplate == "vllm.invocations" && profile.Scenario == "legacy-gap" && auth == "missing" {
		modelName, resolved := a.vllmModelName(profile, stringValue(value["model"]))
		if !resolved {
			a.notePersonaError(model.ProductVLLM, profile.Persona.VLLM.MetricsModelName())
			a.writeJSON(w, http.StatusNotFound, map[string]string{"detail": "The requested model does not exist."})
			return
		}
		obs.ModelID, obs.ModelResolved = modelName, true
		a.startInvocation(obs, "bypass_simulated", true)
		obs.ExtraScore += 20
		obs.ExtraReasons = append(obs.ExtraReasons, "vllm_invocations_auth_gap")
		a.maybeDegradeVLLM(profile, session, body, obs)
		a.beginPersonaRequest(model.ProductVLLM, profile.Persona.VLLM.MetricsModelName())
		defer func() {
			a.finishPersonaRequest(model.ProductVLLM, profile.Persona.VLLM.MetricsModelName(), obs.SimulatedInputTokens, obs.SimulatedOutputTokens, true)
		}()
		a.writeVLLMResponse(w, body, obs.RouteTemplate, streamValue(value), obs, profile.Persona.VLLM.MetricsModelName())
		return
	}
	if profile.Scenario != "no-key" && auth != "valid_honey_key" {
		a.notePersonaError(model.ProductVLLM, profile.Persona.VLLM.MetricsModelName())
		a.startInvocation(obs, auth, false)
		a.writeJSON(w, http.StatusUnauthorized, map[string]any{"detail": "Not authenticated"})
		return
	}
	modelName, resolved := a.vllmModelName(profile, stringValue(value["model"]))
	if !resolved {
		a.notePersonaError(model.ProductVLLM, profile.Persona.VLLM.MetricsModelName())
		a.writeJSON(w, http.StatusNotFound, map[string]string{"detail": "The requested model does not exist."})
		return
	}
	obs.ModelID, obs.ModelResolved = modelName, true
	a.startInvocation(obs, auth, true)
	obs.ExtraScore += 25
	obs.ExtraReasons = append(obs.ExtraReasons, "vllm_synthetic_compute_use")
	a.maybeDegradeVLLM(profile, session, body, obs)
	metricModel := profile.Persona.VLLM.MetricsModelName()
	a.beginPersonaRequest(model.ProductVLLM, metricModel)
	defer func() {
		a.finishPersonaRequest(model.ProductVLLM, metricModel, obs.SimulatedInputTokens, obs.SimulatedOutputTokens, true)
	}()
	a.writeVLLMResponse(w, body, obs.RouteTemplate, streamValue(value), obs, modelName)
}

func (a *App) vllmModelName(profile profiles.Profile, requested string) (string, bool) {
	return profiles.ResolveVLLMServedModel(profile.Persona.VLLM, requested)
}

func isVLLMReadRoute(route string) bool {
	switch route {
	case "vllm.root", "vllm.health", "vllm.version", "vllm.metrics", "openai.models", "vllm.docs", "vllm.openapi":
		return true
	default:
		return false
	}
}

func (a *App) maybeDegradeVLLM(profile profiles.Profile, session Session, body []byte, obs *Observation) {
	result := detect.Analyze(model.ProductVLLM, obs.RouteTemplate, string(body))
	if result.Score < 60 {
		return
	}
	scope, ownerKey, ttl := virtualEffectOwner(profile, session)
	now := time.Now().UTC()
	_ = a.store.AddEffect(model.VirtualEffect{ID: "ve_" + security.MustRandomToken(8), OwnerScope: scope, OwnerKey: ownerKey, Product: model.ProductVLLM, EffectType: "virtual_worker_degraded", State: map[string]string{"simulated_worker_crash": "true"}, CreatedAt: now, ExpiresAt: now.Add(ttl)})
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
		a.writeJSON(w, http.StatusOK, map[string]string{"version": profile.Persona.Ollama.Version})
	case "ollama.tags":
		a.writeJSON(w, http.StatusOK, map[string]any{"models": profiles.OllamaModelsForProfile(a.cfg.InstanceKey, profile.Persona.Ollama)})
	case "ollama.ps":
		_, effectOwner, _ := virtualEffectOwner(profile, session)
		activeNames := map[string]time.Time{}
		for _, active := range a.activePersonaModels(model.ProductOllama, effectOwner) {
			activeNames[active.Name] = active.ExpiresAt
		}
		for _, effect := range a.store.ActiveEffects(effectOwner, model.ProductOllama, time.Now().UTC()) {
			if effect.EffectType == "model_virtually_loaded" {
				if name := effect.State["model"]; name != "" {
					if _, exists := activeNames[name]; !exists {
						activeNames[name] = effect.ExpiresAt
					}
				}
			}
		}
		modelNames := make([]string, 0, len(activeNames))
		for name := range activeNames {
			modelNames = append(modelNames, name)
		}
		sort.Strings(modelNames)
		models := []map[string]any{}
		for _, name := range modelNames {
			expiresAt := activeNames[name]
			if item, ok := profiles.FindOllamaModelForProfile(a.cfg.InstanceKey, profile.Persona.Ollama, name); ok {
				models = append(models, map[string]any{"name": item.Name, "model": item.Model, "size": item.Size, "digest": item.Digest, "details": item.Details, "expires_at": expiresAt.Format(time.RFC3339Nano), "size_vram": item.Size / 2})
			}
		}
		if len(models) > 0 {
			obs.EffectOutcome = "verified"
			obs.ExtraScore += 15
			obs.ExtraReasons = append(obs.ExtraReasons, "post_call_effect_verification")
			_ = a.store.MarkEffectsVerified(effectOwner, model.ProductOllama, "model_virtually_loaded", time.Now().UTC())
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"models": models})
	case "ollama.show":
		requested := a.requestModel(body)
		if requested == "" {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "model is required"})
			return
		}
		item, ok := profiles.FindOllamaModelForProfile(a.cfg.InstanceKey, profile.Persona.Ollama, requested)
		if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model not found"})
			return
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"modelfile": "FROM " + item.Name, "parameters": "", "template": "{{ .Response }}", "details": item.Details, "model_info": map[string]any{"general.architecture": item.Details.Family, "general.parameter_count": item.Details.ParameterSize}})
	case "ollama.generate", "ollama.chat":
		a.ollamaInvoke(w, r, profile, body, session, obs)
	case "ollama.embeddings":
		value, validationErr := validateOllamaOpenAIRequest(r, body, "openai.embeddings")
		if validationErr != nil {
			a.notePersonaError(model.ProductOllama, profile.Persona.Ollama.Version)
			a.startInvocation(obs, "invalid", false)
			a.writeJSON(w, validationErr.Status, map[string]string{"error": validationErr.Message})
			return
		}
		item, ok := profiles.FindOllamaModelForProfile(a.cfg.InstanceKey, profile.Persona.Ollama, stringValue(value["model"]))
		if !ok {
			a.notePersonaError(model.ProductOllama, stringValue(value["model"]))
			a.startInvocation(obs, "not_required", false)
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
		a.noteOllamaModelLoaded(profile, session, item.Name, profile.Persona.Ollama.KeepAlive)
		a.writeJSON(w, http.StatusOK, map[string]any{"model": item.Name, "embedding": []float64{0.0123, -0.0456, 0.0789}, "embeddings": [][]float64{{0.0123, -0.0456, 0.0789}}})
	case "openai.models":
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": profiles.OllamaOpenAIModelsForProfile(a.cfg.InstanceKey, profile.Persona.Ollama)})
	case "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings":
		a.ollamaOpenAIInvoke(w, r, profile, body, session, obs)
	case "ollama.pull", "ollama.push", "ollama.create", "ollama.copy", "ollama.delete", "ollama.blob":
		a.ollamaTask(w, r, profile, body, session, obs)
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

func (a *App) ollamaInvoke(w *captureWriter, r *http.Request, profile profiles.Profile, body []byte, session Session, obs *Observation) {
	request, validationErr := validateOllamaRequest(r, body, obs.RouteTemplate, profile.Persona.Ollama.KeepAlive)
	if validationErr != nil {
		a.notePersonaError(model.ProductOllama, profile.Persona.Ollama.Version)
		a.startInvocation(obs, "invalid", false)
		a.writeJSON(w, validationErr.Status, map[string]string{"error": validationErr.Message})
		return
	}
	item, ok := profiles.FindOllamaModelForProfile(a.cfg.InstanceKey, profile.Persona.Ollama, request.Model)
	if !ok {
		a.notePersonaError(model.ProductOllama, request.Model)
		a.startInvocation(obs, "not_required", false)
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model not found"})
		return
	}
	modelName := item.Model
	publicModelName := item.Name
	obs.ModelID, obs.ModelResolved = modelName, true
	a.startInvocation(obs, "not_required", true)
	obs.ExtraScore += 25
	obs.ExtraReasons = append(obs.ExtraReasons, "ollama_open_deployment_synthetic_use")
	a.noteOllamaModelLoaded(profile, session, publicModelName, request.KeepAlive)
	responseText := personaResponseText(body, model.ProductOllama)
	inputTokens, outputTokens := maxInt(8, len(body)/4), maxInt(6, len(responseText)/4)
	setInvocationMeasurements(obs, inputTokens, outputTokens, "synthetic_accepted")
	a.notePersonaInvocation(model.ProductOllama, modelName, inputTokens, outputTokens)
	if request.Stream {
		doneReason := "stop"
		if request.Unload {
			doneReason = "unload"
		}
		a.writeOllamaStream(w, obs.RouteTemplate, publicModelName, responseText, inputTokens, outputTokens, obs, doneReason)
		return
	}
	doneReason := "stop"
	if request.Unload {
		doneReason = "unload"
	}
	createdAt := time.Now().UTC().Format(time.RFC3339Nano)
	response := map[string]any{"model": publicModelName, "created_at": createdAt, "done": true, "done_reason": doneReason, "total_duration": int64(28_000_000), "load_duration": int64(4_000_000), "prompt_eval_count": inputTokens, "prompt_eval_duration": int64(3_000_000), "eval_count": outputTokens, "eval_duration": int64(21_000_000)}
	if obs.RouteTemplate == "ollama.generate" {
		response["response"] = responseText
	} else {
		response["message"] = map[string]string{"role": "assistant", "content": responseText}
	}
	a.writeJSON(w, http.StatusOK, response)
}

func (a *App) ollamaOpenAIInvoke(w *captureWriter, r *http.Request, profile profiles.Profile, body []byte, session Session, obs *Observation) {
	value, validationErr := validateOllamaOpenAIRequest(r, body, obs.RouteTemplate)
	if validationErr != nil {
		a.notePersonaError(model.ProductOllama, profile.Persona.Ollama.Version)
		a.startInvocation(obs, "invalid", false)
		a.writeJSON(w, validationErr.Status, map[string]string{"error": validationErr.Message})
		return
	}
	item, ok := profiles.FindOllamaModelForProfile(a.cfg.InstanceKey, profile.Persona.Ollama, stringValue(value["model"]))
	if !ok {
		a.notePersonaError(model.ProductOllama, stringValue(value["model"]))
		a.startInvocation(obs, "not_required", false)
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model not found"})
		return
	}
	modelName := item.Model
	obs.ModelID, obs.ModelResolved = modelName, true
	a.startInvocation(obs, "not_required", true)
	obs.ExtraScore += 25
	obs.ExtraReasons = append(obs.ExtraReasons, "ollama_openai_compat_synthetic_use")
	a.noteOllamaModelLoaded(profile, session, item.Name, profile.Persona.Ollama.KeepAlive)
	a.writeOllamaOpenAIResponse(w, body, obs.RouteTemplate, streamValue(value), obs, item.Name)
	a.notePersonaInvocation(model.ProductOllama, modelName, obs.SimulatedInputTokens, obs.SimulatedOutputTokens)
}

func (a *App) ollamaTask(w *captureWriter, r *http.Request, profile profiles.Profile, body []byte, session Session, obs *Observation) {
	if obs.RouteTemplate == "ollama.blob" {
		// Blob probes are intentionally bounded and never persisted as files.
		obs.ExtraScore += 15
		a.startInvocation(obs, "not_required", true)
		obs.ExtraReasons = append(obs.ExtraReasons, "ollama_bounded_blob_probe")
		digest := ""
		if models := profiles.OllamaModelsForProfile(a.cfg.InstanceKey, profile.Persona.Ollama); len(models) > 0 {
			digest = models[0].Digest
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"status": "success", "digest": digest, "size": 256})
		return
	}
	value, validationErr := validateOllamaTaskRequest(r, body, obs.RouteTemplate)
	if validationErr != nil {
		a.notePersonaError(model.ProductOllama, profile.Persona.Ollama.Version)
		a.startInvocation(obs, "invalid", false)
		a.writeJSON(w, validationErr.Status, map[string]string{"error": validationErr.Message})
		return
	}
	name := stringValue(value["model"])
	item, ok := profiles.FindOllamaModelForProfile(a.cfg.InstanceKey, profile.Persona.Ollama, name)
	if !ok {
		a.notePersonaError(model.ProductOllama, name)
		a.startInvocation(obs, "not_required", false)
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model not found"})
		return
	}
	obs.ModelID, obs.ModelResolved = item.Model, true
	a.startInvocation(obs, "not_required", true)
	obs.ExtraScore += 35
	obs.ExtraReasons = append(obs.ExtraReasons, "ollama_model_lifecycle_probe")
	if obs.RouteTemplate == "ollama.pull" {
		pullStream := true
		if raw, exists := value["stream"]; exists {
			pullStream, _ = raw.(bool)
		}
		statuses := []string{"pulling manifest", "pulling layers", "verifying sha256 digest", "success"}
		if !pullStream {
			a.writeJSON(w, http.StatusOK, map[string]any{"status": "success", "digest": item.Digest, "completed": true})
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		for _, status := range statuses {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "digest": item.Digest, "completed": status == "success"})
			w.Flush()
		}
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"status": "success", "task_id": "task_" + obs.InvocationID, "model": item.Name, "digest": item.Digest, "progress": []string{"pulling manifest", "pulling layers", "verifying sha256 digest", "success"}})
}

func (a *App) noteOllamaModelLoaded(profile profiles.Profile, session Session, modelName string, keepAlive time.Duration) {
	scope, ownerKey, scenarioTTL := virtualEffectOwner(profile, session)
	if keepAlive <= 0 {
		now := time.Now().UTC()
		_ = a.store.ExpireEffects(ownerKey, model.ProductOllama, "model_virtually_loaded", "model", modelName, now)
		a.unmarkPersonaModel(model.ProductOllama, ownerKey, modelName)
		return
	}
	if scenarioTTL < keepAlive {
		keepAlive = scenarioTTL
	}
	now := time.Now().UTC()
	expiresAt := now.Add(keepAlive)
	_ = a.store.AddEffect(model.VirtualEffect{
		ID:         "ve_" + security.MustRandomToken(8),
		OwnerScope: scope,
		OwnerKey:   ownerKey,
		Product:    model.ProductOllama,
		EffectType: "model_virtually_loaded",
		State:      map[string]string{"model": modelName},
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
	})
	a.markPersonaModel(model.ProductOllama, ownerKey, modelName, keepAlive)
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
		a.writeHTML(w, http.StatusOK, "SGLang API", `<h1>SGLang API</h1><p>Interactive API documentation.</p><p>OpenAPI schema: <a href="/openapi.json">/openapi.json</a></p><p>OpenAI-compatible and native generation endpoints are available.</p>`)
	case "sglang.openapi":
		a.writeJSON(w, http.StatusOK, sglangOpenAPISchema(profile))
	case "sglang.server_info":
		info := map[string]any{"model_path": "/models/Qwen/Qwen3.6-35B-A3B", "api_key": a.derivedHoneyKey(model.ProductSGLang), "ssl_keyfile": "/run/secrets/server.key", "rank": 0, "world_size": 1, "tp_size": 1, "pp_size": 1}
		_, effectOwner, _ := virtualEffectOwner(profile, session)
		for _, effect := range a.store.ActiveEffects(effectOwner, model.ProductSGLang, time.Now().UTC()) {
			switch effect.EffectType {
			case "sglang_lora_adapter_virtualized":
				info["lora_adapters"] = []string{"adapter-canary"}
				obs.EffectOutcome = "verified"
				_ = a.store.MarkEffectsVerified(effectOwner, model.ProductSGLang, effect.EffectType, time.Now().UTC())
			case "sglang_weight_update_virtualized":
				info["weight_revision"] = "weight-canary-active"
				obs.EffectOutcome = "verified"
				_ = a.store.MarkEffectsVerified(session.ID, model.ProductSGLang, effect.EffectType, time.Now().UTC())
			}
		}
		if obs.EffectOutcome == "verified" {
			obs.ExtraScore += 15
			obs.ExtraReasons = append(obs.ExtraReasons, "post_call_effect_verification")
		}
		a.writeJSON(w, http.StatusOK, info)
	case "sglang.dumper":
		obs.ExtraScore += 20
		obs.ExtraReasons = append(obs.ExtraReasons, "sglang_dumper_virtual_worker_error")
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]any{"detail": "worker unavailable"})
	case "openai.models":
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": profiles.OpenAIModelCardsForCatalog(a.cfg.InstanceKey, a.catalogForSession(model.ProductSGLang, "guest", session), "sglang")})
	case "sglang.generate", "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings":
		a.sglangInvoke(w, r, profile, session, body, obs)
	case "sglang.lora.load", "sglang.weights.update", "sglang.cache.flush", "sglang.weights.get":
		a.sglangAdminAction(w, r, profile, session, body, obs)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]any{"detail": "Not Found"})
	}
}

func (a *App) sglangInvoke(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
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
	requestedModel := a.requestModel(body)
	entry, modelResolved := a.resolveCatalogModelForSession(model.ProductSGLang, requestedModel, "guest", session)
	if requestedModel != "" && !modelResolved {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"detail": "The requested model does not exist."})
		return
	}
	modelName := entry.ID
	if !modelResolved {
		modelName = a.validModelNameForSession(model.ProductSGLang, requestedModel, session)
		modelResolved = true
	}
	obs.ModelID = modelName
	obs.ModelResolved = modelResolved
	a.writeOpenAIResponseForRoute(w, body, model.ProductSGLang, obs.RouteTemplate, streamRequested(r, body), obs, modelName)
}

func (a *App) sglangAdminAction(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, body []byte, obs *Observation) {
	key := a.bearer(r)
	if key == "" {
		a.startInvocation(obs, "missing", false)
		obs.ExtraScore += 25
		obs.ExtraReasons = append(obs.ExtraReasons, "sglang_admin_route_without_key")
		a.writeJSON(w, http.StatusUnauthorized, map[string]string{"detail": "Not authenticated"})
		return
	}
	if key != a.derivedHoneyKey(model.ProductSGLang) {
		a.startInvocation(obs, "invalid", false)
		obs.ExtraScore += 25
		obs.ExtraReasons = append(obs.ExtraReasons, "sglang_admin_route_invalid_key")
		a.writeJSON(w, http.StatusForbidden, map[string]string{"detail": "Invalid admin key"})
		return
	}
	obs.CredentialFingerprint = security.Fingerprint(a.cfg.InstanceKey, key)
	a.startInvocation(obs, "leaked_key_reused", true)
	obs.ExtraScore += 55
	obs.ExtraReasons = append(obs.ExtraReasons, "sglang_server_info_honey_key_reused")
	effectType := "sglang_weight_update_virtualized"
	if obs.RouteTemplate == "sglang.lora.load" {
		effectType = "sglang_lora_adapter_virtualized"
	} else if obs.RouteTemplate == "sglang.cache.flush" {
		effectType = "sglang_cache_flush_virtualized"
	} else if obs.RouteTemplate == "sglang.weights.get" {
		effectType = "sglang_weight_metadata_canary"
	}
	obs.EffectOutcome = "applied"
	scope, effectOwner, ttl := virtualEffectOwner(profile, session)
	now := time.Now().UTC()
	_ = a.store.AddEffect(model.VirtualEffect{ID: "ve_" + security.MustRandomToken(8), OwnerScope: scope, OwnerKey: effectOwner, Product: model.ProductSGLang, EffectType: effectType, State: map[string]string{"canary": "weight_canary_" + obs.InvocationID, "request_hash": security.Fingerprint(a.cfg.InstanceKey, string(body))[:20]}, CreatedAt: now, ExpiresAt: now.Add(ttl)})
	switch obs.RouteTemplate {
	case "sglang.cache.flush":
		a.writeJSON(w, http.StatusOK, map[string]any{"status": "success", "flushed": true, "task_id": "cache_" + obs.InvocationID})
	case "sglang.weights.get":
		a.writeJSON(w, http.StatusOK, map[string]any{"status": "success", "weights": []map[string]any{{"name": "weight_canary", "revision": "virtual"}}})
	case "sglang.lora.load":
		a.writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "task_id": "lora_" + obs.InvocationID, "adapter_name": "adapter-canary", "weight_id": "weight_" + obs.InvocationID})
	default:
		a.writeJSON(w, http.StatusOK, map[string]any{"status": "accepted", "task_id": "weights_" + obs.InvocationID, "weight_id": "weight_" + obs.InvocationID})
	}
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
		_, effectOwner, _ := virtualEffectOwner(profile, session)
		loaded := len(a.store.ActiveEffects(effectOwner, model.ProductLocalAI, time.Now().UTC()))
		_, _ = w.Write([]byte(fmt.Sprintf("localai_requests_total 18\nlocalai_models_loaded %d\n", loaded)))
	case "localai.docs":
		a.writeJSON(w, http.StatusOK, localAIOpenAPISchema(profile))
	case "localai.models.available":
		a.writeJSON(w, http.StatusOK, map[string]any{"models": localAIGalleryModels(a.catalogForSession(model.ProductLocalAI, "guest", session)), "source": "model-gallery"})
	case "localai.models.installed":
		a.localAIInstalled(w, profile, session, obs)
	case "localai.models.apply":
		if profile.Scenario == "current-rbac" && !a.localAIAdminAuth(r, obs, w) {
			return
		}
		value, ok := decodeJSONObject(body)
		if !ok {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid model installation request"})
			return
		}
		modelName := stringValue(value["model"])
		if modelName == "" {
			modelName = stringValue(value["name"])
		}
		if modelName == "" {
			catalog := a.catalogForSession(model.ProductLocalAI, "guest", session)
			if len(catalog) == 0 {
				catalog = profiles.Catalog(model.ProductLocalAI)
			}
			if len(catalog) > 0 {
				modelName = catalog[0].ID
			}
		}
		if len(modelName) > 256 || strings.ContainsAny(modelName, "\r\n") {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid model name"})
			return
		}
		jobID := "job_" + security.MustRandomToken(10)
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 50
		obs.ExtraReasons = append(obs.ExtraReasons, "localai_model_install_probe")
		obs.EffectOutcome = "applied"
		scope, effectOwner, ttl := virtualEffectOwner(profile, session)
		now := time.Now().UTC()
		_ = a.store.AddEffect(model.VirtualEffect{ID: "ve_" + security.MustRandomToken(8), OwnerScope: scope, OwnerKey: effectOwner, Product: model.ProductLocalAI, EffectType: "localai_model_install_virtualized", State: map[string]string{"task_id": jobID, "model": modelName, "source": "gallery"}, CreatedAt: now, ExpiresAt: now.Add(ttl)})
		a.writeJSON(w, http.StatusOK, map[string]any{"id": jobID, "status": "ready", "model": modelName, "steps": []string{"resolving source", "downloading manifest", "validating archive", "installing backend", "ready"}})
	case "localai.models.delete":
		if profile.Scenario == "current-rbac" && !a.localAIAdminAuth(r, obs, w) {
			return
		}
		value, ok := decodeJSONObject(body)
		if !ok {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid model delete request"})
			return
		}
		modelName := stringValue(value["model"])
		if modelName == "" {
			modelName = stringValue(value["name"])
		}
		if len(modelName) > 256 || strings.ContainsAny(modelName, "\r\n") {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid model name"})
			return
		}
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 45
		obs.ExtraReasons = append(obs.ExtraReasons, "localai_model_delete_probe")
		_, effectOwner, _ := virtualEffectOwner(profile, session)
		deleted := a.store.ExpireEffects(effectOwner, model.ProductLocalAI, "localai_model_install_virtualized", "model", modelName, time.Now().UTC())
		obs.EffectOutcome = "applied"
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": deleted > 0, "model": modelName})
	case "localai.models.task":
		a.localAIModelTask(w, r, profile, session, obs)
	case "localai.audio.transcriptions":
		if profile.Scenario == "current-rbac" && !a.localAIUserAuth(r, obs, w) {
			return
		}
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 25
		a.writeJSON(w, http.StatusOK, map[string]any{"text": "Transcription completed.", "duration": 1.2, "language": "en"})
	case "localai.audio.speech":
		if profile.Scenario == "current-rbac" && !a.localAIUserAuth(r, obs, w) {
			return
		}
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 25
		w.Header().Set("Content-Type", "audio/mpeg")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ID3\x04\x00AegisLure audio sample"))
	case "localai.images.generations":
		if profile.Scenario == "current-rbac" && !a.localAIUserAuth(r, obs, w) {
			return
		}
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 30
		a.writeJSON(w, http.StatusOK, map[string]any{"created": time.Now().Unix(), "data": []map[string]string{{"b64_json": "c3l1c2VyLWltYWdl"}}})
	case "openai.models":
		a.writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": profiles.OpenAIModelCardsForCatalog(a.cfg.InstanceKey, a.catalogForSession(model.ProductLocalAI, "guest", session), "localai")})
	case "openai.chat.completions", "openai.completions", "openai.responses", "openai.embeddings":
		if profile.Scenario == "current-rbac" {
			if !a.localAIUserAuth(r, obs, w) {
				return
			}
		}
		a.startInvocation(obs, "not_required", true)
		obs.ExtraScore += 25
		obs.ExtraReasons = append(obs.ExtraReasons, "localai_synthetic_compute_use")
		requestedModel := a.requestModel(body)
		entry, modelResolved := a.resolveCatalogModelForSession(model.ProductLocalAI, requestedModel, "guest", session)
		if requestedModel != "" && !modelResolved {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "model not found"})
			return
		}
		modelName := entry.ID
		if !modelResolved {
			modelName = a.validModelNameForSession(model.ProductLocalAI, requestedModel, session)
			modelResolved = true
		}
		obs.ModelID = modelName
		obs.ModelResolved = modelResolved
		a.writeOpenAIResponseForRoute(w, body, model.ProductLocalAI, obs.RouteTemplate, streamRequested(r, body), obs, modelName)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (a *App) localAIUserAuth(r *http.Request, obs *Observation, w *captureWriter) bool {
	token, auth := a.honeyAuth(r)
	if auth != "valid_honey_key" {
		a.startInvocation(obs, auth, false)
		a.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return false
	}
	obs.CredentialFingerprint = token.Hash
	return true
}

func (a *App) localAIAdminAuth(r *http.Request, obs *Observation, w *captureWriter) bool {
	return a.localAIUserAuth(r, obs, w)
}

func (a *App) localAIInstalled(w *captureWriter, profile profiles.Profile, session Session, obs *Observation) {
	items := make([]map[string]any, 0)
	_, effectOwner, _ := virtualEffectOwner(profile, session)
	for _, effect := range a.store.ActiveEffects(effectOwner, model.ProductLocalAI, time.Now().UTC()) {
		if effect.EffectType != "localai_model_install_virtualized" {
			continue
		}
		name := effect.State["model"]
		item := map[string]any{"id": name, "name": name, "status": "ready", "backend": "llama-cpp", "task_id": effect.State["task_id"], "source": "gallery"}
		items = append(items, item)
		obs.EffectOutcome = "verified"
	}
	if len(items) > 0 {
		obs.ExtraScore += 15
		obs.ExtraReasons = append(obs.ExtraReasons, "post_call_effect_verification")
		_ = a.store.MarkEffectsVerified(effectOwner, model.ProductLocalAI, "localai_model_install_virtualized", time.Now().UTC())
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"models": items, "data_only": true})
}

func (a *App) localAIModelTask(w *captureWriter, r *http.Request, profile profiles.Profile, session Session, obs *Observation) {
	taskID := strings.TrimPrefix(r.URL.Path, "/models/jobs/")
	if taskID == "" || strings.ContainsAny(taskID, "/\r\n") {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "task not found"})
		return
	}
	_, effectOwner, _ := virtualEffectOwner(profile, session)
	for _, effect := range a.store.ActiveEffects(effectOwner, model.ProductLocalAI, time.Now().UTC()) {
		if effect.EffectType == "localai_model_install_virtualized" && effect.State["task_id"] == taskID {
			obs.EffectOutcome = "verified"
			obs.ExtraScore += 15
			obs.ExtraReasons = append(obs.ExtraReasons, "post_call_effect_verification")
			_ = a.store.MarkEffectsVerified(effectOwner, model.ProductLocalAI, effect.EffectType, time.Now().UTC())
			a.writeJSON(w, http.StatusOK, map[string]any{"id": taskID, "status": "ready", "progress": []string{"resolving source", "downloading manifest", "validating archive", "installing backend", "ready"}, "model": effect.State["model"]})
			return
		}
	}
	a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "task not found"})
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

func newAPIStringFieldsOK(r *http.Request, body []byte, fields ...string) bool {
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		_, err := url.ParseQuery(string(body))
		return err == nil
	}
	if !jsonContentTypeOK(r) {
		return false
	}
	value, ok := decodeJSONObject(body)
	if !ok {
		return false
	}
	for _, field := range fields {
		if raw, exists := value[field]; exists {
			if _, ok := raw.(string); !ok {
				return false
			}
		}
	}
	return true
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
		// Account/page requests are observations, not usage rows. Keep the
		// public New API usage surface aligned with real invocation history.
		if event.InvocationID == "" {
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
	if w.Header().Get("Allow") == "" {
		w.Header().Set("Allow", http.MethodPost)
	}
	a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func (a *App) writeMethodNotAllowed(w *captureWriter, product string) {
	if w.Header().Get("Allow") == "" {
		w.Header().Set("Allow", http.MethodPost)
	}
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
	if entry, ok := a.resolveCatalogModel(product, requested); ok {
		return entry
	}
	catalog := a.catalogFor(product)
	if len(catalog) == 0 {
		catalog = profiles.Catalog(product)
	}
	if len(catalog) == 0 {
		return profiles.CatalogEntry{ID: requested, Object: "model", DisplayName: requested, Provider: "local", Origin: "open", Capabilities: []string{"chat"}}
	}
	return catalog[0]
}

func localAIGalleryModels(catalog []profiles.CatalogEntry) []map[string]any {
	result := make([]map[string]any, 0, len(catalog))
	seen := make(map[string]bool, len(catalog))
	for _, entry := range catalog {
		if entry.ID == "" || seen[entry.ID] {
			continue
		}
		seen[entry.ID] = true
		name := entry.DisplayName
		if name == "" {
			name = entry.ID
		}
		result = append(result, map[string]any{
			"id":           entry.ID,
			"name":         name,
			"status":       "available",
			"backend":      "llama-cpp",
			"capabilities": append([]string(nil), entry.Capabilities...),
		})
	}
	return result
}

func (a *App) resolveCatalogModel(product, requested string) (profiles.CatalogEntry, bool) {
	return a.resolveCatalogModelForAudience(product, requested, "guest")
}

func (a *App) validModelName(product, requested string) string {
	return a.validCatalogEntry(product, requested).ID
}

func (a *App) validModelNameForSession(product, requested string, session Session) string {
	if entry, ok := a.resolveCatalogModelForSession(product, requested, "guest", session); ok {
		return entry.ID
	}
	catalog := a.catalogForSession(product, "guest", session)
	if len(catalog) == 0 {
		catalog = profiles.Catalog(product)
	}
	if len(catalog) == 0 {
		return strings.TrimSpace(requested)
	}
	return catalog[0].ID
}

func (a *App) derivedHoneyKey(product string) string {
	return "sk-" + security.Fingerprint(a.cfg.InstanceKey, "server-info:"+product)[:40]
}
