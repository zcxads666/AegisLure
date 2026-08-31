package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/config"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/security"
)

type AdminSession struct {
	ID        string
	Username  string
	CreatedAt time.Time
	LastSeen  time.Time
}

var errOwnerAlreadyInitialized = fmt.Errorf("owner already initialized")

func (a *App) adminHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.HasPrefix(r.URL.Path, a.cfg.AdminPath) {
			silentClose(w)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, a.cfg.AdminPath)
		if r.Method == http.MethodGet && isAdminUIPath(path) {
			a.adminPage(w)
			return
		}
		if r.Method == http.MethodGet && (strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "assets/")) {
			a.writeAdminAsset(w, path)
			return
		}
		path = strings.TrimPrefix(path, "/")
		switch {
		case path == "setup/status" && r.Method == http.MethodGet:
			a.setupStatus(w)
		case path == "setup/create-owner" && r.Method == http.MethodPost:
			a.setupCreateOwner(w, r)
		case path == "admin/api/v1/auth/forgot-password" && r.Method == http.MethodPost:
			a.adminForgotPassword(w, r)
		case path == "admin/api/v1/auth/recovery-code/reset" && r.Method == http.MethodPost:
			a.adminRecoveryReset(w, r)
		case path == "admin/api/v1/auth/login" && r.Method == http.MethodPost:
			a.adminLogin(w, r)
		case path == "admin/api/v1/auth/logout" && r.Method == http.MethodPost:
			a.adminLogout(w, r)
		case strings.HasPrefix(path, "admin/api/v1/"):
			a.handleAdminAPI(w, r, strings.TrimPrefix(path, "admin/api/v1/"))
		default:
			silentClose(w)
		}
	})
}

func silentClose(w http.ResponseWriter) {
	if hijacker, ok := w.(http.Hijacker); ok {
		conn, _, err := hijacker.Hijack()
		if err == nil {
			_ = conn.Close()
		}
		return
	}
}

func (a *App) setupStatus(w http.ResponseWriter) {
	admin := a.store.Admin()
	a.writeJSON(w, http.StatusOK, map[string]any{"initialized": admin.Initialized, "setup_available": !admin.Initialized})
}

func (a *App) setupCreateOwner(w http.ResponseWriter, r *http.Request) {
	a.setupMu.Lock()
	defer a.setupMu.Unlock()
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if a.store.Admin().Initialized {
		a.writeJSON(w, http.StatusGone, map[string]string{"error": "owner already initialized"})
		return
	}
	if !a.allowRate("setup-owner:"+requestSourceIP(r), 5, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 16*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	value := a.jsonBody(body)
	username := strings.TrimSpace(stringValue(value["username"]))
	password := stringValue(value["password"])
	if username == "" || len(username) > 128 || len(password) < 8 || len(password) > 128 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "username or password does not meet policy"})
		return
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "password setup failed"})
		return
	}
	recovery := make([]string, 0, 8)
	recoveryHashes := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		value, _ := security.RandomToken(12)
		recovery = append(recovery, value)
		recoveryHashes = append(recoveryHashes, security.Fingerprint(a.cfg.InstanceKey, value))
	}
	err = a.store.Update(func(state *model.State) error {
		if state.Admin.Initialized {
			return errOwnerAlreadyInitialized
		}
		state.Admin = model.AdminState{Initialized: true, OwnerUsername: username, PasswordHash: hash, RecoveryHashes: recoveryHashes, CreatedAt: time.Now().UTC()}
		return nil
	})
	if err != nil {
		if errors.Is(err, errOwnerAlreadyInitialized) {
			a.writeJSON(w, http.StatusGone, map[string]string{"error": "owner already initialized"})
			return
		}
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner setup failed"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "recovery_codes": recovery, "warning": "Recovery codes are shown once. Store them offline.", "security_note": "MFA and bootstrap verification are disabled by this deployment configuration."})
}

func (a *App) adminLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-login:"+requestSourceIP(r), 12, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 16*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	value := a.jsonBody(body)
	username := strings.TrimSpace(stringValue(value["username"]))
	password := stringValue(value["password"])
	if username != "" && !a.allowRate("admin-login-account:"+security.Fingerprint(a.cfg.InstanceKey, username), 6, time.Minute) {
		rateLimited(w)
		return
	}
	admin := a.store.Admin()
	passwordOK := security.VerifyPassword(admin.PasswordHash, password)
	if !admin.Initialized || username != admin.OwnerUsername || !passwordOK {
		a.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	id, _ := security.RandomToken(24)
	a.setAdminSession(id, AdminSession{ID: id, Username: admin.OwnerUsername, CreatedAt: time.Now().UTC(), LastSeen: time.Now().UTC()})
	http.SetCookie(w, &http.Cookie{Name: "hp_admin", Value: id, Path: a.cfg.AdminPath, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: os.Getenv("HP_COOKIE_SECURE") == "1", MaxAge: 8 * 3600})
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "username": admin.OwnerUsername})
}

func (a *App) adminForgotPassword(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-forgot:"+requestSourceIP(r), 5, time.Minute) {
		rateLimited(w)
		return
	}
	// Mail delivery is deliberately not implemented in the core process. Keep
	// the response uniform so this endpoint cannot enumerate an owner account.
	_, _ = readBoundedBody(r, 4*1024)
	a.writeJSON(w, http.StatusAccepted, map[string]string{"message": "If recovery is configured, instructions will be sent."})
}

func (a *App) adminRecoveryReset(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-recovery:"+requestSourceIP(r), 5, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 16*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid recovery request"})
		return
	}
	value := a.jsonBody(body)
	username := strings.TrimSpace(stringValue(value["username"]))
	code := strings.TrimSpace(stringValue(value["recovery_code"]))
	password := stringValue(value["new_password"])
	if username == "" || len(username) > 128 || len(password) < 8 || len(password) > 128 || code == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid recovery request"})
		return
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "password reset failed"})
		return
	}
	codeHash := security.Fingerprint(a.cfg.InstanceKey, code)
	reset := false
	now := time.Now().UTC()
	err = a.store.Update(func(state *model.State) error {
		if !state.Admin.Initialized || state.Admin.OwnerUsername != username {
			return nil
		}
		remove := func(values []string) ([]string, bool) {
			for i, candidate := range values {
				if candidate == codeHash {
					return append(values[:i], values[i+1:]...), true
				}
			}
			return values, false
		}
		if values, ok := remove(state.Admin.RecoveryHashes); ok {
			state.Admin.RecoveryHashes = values
			reset = true
		} else {
			// Expired rescue codes are pruned while checking, so a replayed or
			// stale CLI code cannot remain valid after its deadline.
			valid := state.Admin.RescueCodes[:0]
			for _, candidate := range state.Admin.RescueCodes {
				if candidate.ExpiresAt.IsZero() || !candidate.ExpiresAt.After(now) {
					continue
				}
				if candidate.Hash == codeHash {
					reset = true
					continue
				}
				valid = append(valid, candidate)
			}
			state.Admin.RescueCodes = valid
			// Older state files used RescueHashes without an expiry. Keep the
			// migration path readable for existing local installations, but all
			// newly issued rescue codes use the expiring representation above.
			if !reset {
				if values, ok := remove(state.Admin.RescueHashes); ok {
					state.Admin.RescueHashes = values
					reset = true
				}
			}
		}
		if reset {
			state.Admin.PasswordHash = hash
		}
		return nil
	})
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "password reset failed"})
		return
	}
	if !reset {
		a.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid recovery request"})
		return
	}
	a.mu.Lock()
	for id := range a.adminSessions {
		delete(a.adminSessions, id)
	}
	a.mu.Unlock()
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "password reset"})
}

func (a *App) adminLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if cookie, err := r.Cookie("hp_admin"); err == nil {
		a.deleteAdminSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "hp_admin", Value: "", Path: a.cfg.AdminPath, MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: os.Getenv("HP_COOKIE_SECURE") == "1"})
	a.writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

func (a *App) adminSession(r *http.Request) (AdminSession, bool) {
	cookie, err := r.Cookie("hp_admin")
	if err != nil {
		return AdminSession{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.adminSessions[cookie.Value]
	if !ok || time.Since(session.LastSeen) > 8*time.Hour {
		return AdminSession{}, false
	}
	session.LastSeen = time.Now().UTC()
	a.adminSessions[cookie.Value] = session
	return session, true
}

func (a *App) setAdminSession(id string, session AdminSession) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.adminSessions[id] = session
}

func (a *App) deleteAdminSession(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.adminSessions, id)
}

func (a *App) handleAdminAPI(w http.ResponseWriter, r *http.Request, path string) {
	if path == "setup/status" {
		a.setupStatus(w)
		return
	}
	if _, ok := a.adminSession(r); !ok {
		a.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin authentication required"})
		return
	}
	switch {
	case path == "dashboard":
		a.adminDashboard(w)
	case path == "events":
		a.adminEvents(w, r)
	case path == "invocations":
		a.adminInvocations(w, r)
	case path == "interaction-chains":
		a.adminInteractionChains(w, r)
	case path == "indicators" || path == "indicators/ips":
		a.adminIndicators(w, r)
	case path == "instances":
		a.adminInstances(w)
	case path == "packs":
		a.adminPacks(w)
	case path == "identity-policies":
		a.writeJSON(w, http.StatusOK, map[string]any{"providers": []map[string]string{{"provider": "github", "mode": "local_only", "cross_site": "disabled_by_default"}, {"provider": "discord", "mode": "local_only", "cross_site": "blocked"}, {"provider": "linuxdo", "mode": "local_only", "cross_site": "pending_approval"}}})
	case path == "auth/change-password" && r.Method == http.MethodPost:
		a.adminChangePassword(w, r)
	case path == "admin-entry:rotate" && r.Method == http.MethodPost:
		if !sameOriginRequest(r) {
			a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
			return
		}
		a.rotateAdminEntry(w)
	case strings.HasPrefix(path, "instances/") && r.Method == http.MethodPost:
		a.adminInstanceAction(w, r, path)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "admin route not found"})
	}
}

func (a *App) adminChangePassword(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-change-password:"+requestSourceIP(r), 5, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 16*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid password request"})
		return
	}
	value := a.jsonBody(body)
	current := stringValue(value["current_password"])
	next := stringValue(value["new_password"])
	confirm := stringValue(value["confirm_password"])
	if len(next) < 8 || len(next) > 128 || next != confirm || !security.VerifyPassword(a.store.Admin().PasswordHash, current) {
		if len(next) < 8 || len(next) > 128 || next != confirm {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new password does not meet policy"})
			return
		}
		a.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
		return
	}
	hash, err := security.HashPassword(next)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "password change failed"})
		return
	}
	if err := a.store.Update(func(state *model.State) error {
		if !state.Admin.Initialized || !security.VerifyPassword(state.Admin.PasswordHash, current) {
			return errors.New("current password is incorrect")
		}
		state.Admin.PasswordHash = hash
		return nil
	}); err != nil {
		if strings.Contains(err.Error(), "incorrect") {
			a.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
			return
		}
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "password change failed"})
		return
	}
	a.mu.Lock()
	for id := range a.adminSessions {
		delete(a.adminSessions, id)
	}
	a.mu.Unlock()
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "password changed; sign in again"})
}

func (a *App) adminInstanceAction(w http.ResponseWriter, r *http.Request, path string) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 3 || parts[0] != "instances" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance route not found"})
		return
	}
	name, action := parts[1], parts[2]
	if _, ok := a.profiles[name]; !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "profile not found"})
		return
	}
	if action != "start" && action != "stop" && action != "restart" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported instance action"})
		return
	}
	if !a.allowRate("admin-instance:"+name, 30, time.Minute) {
		rateLimited(w)
		return
	}
	if action == "stop" || action == "restart" {
		if err := a.stopProfile(name); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "instance stop failed"})
			return
		}
	}
	if action == "start" || action == "restart" {
		if err := a.startProfile(name); err != nil {
			a.writeJSON(w, http.StatusConflict, map[string]string{"error": "instance start failed: " + err.Error()})
			return
		}
	}
	if action != "restart" {
		if err := a.persistProfileSelection(name, action == "start"); err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "instance configuration save failed"})
			return
		}
	} else if err := a.persistProfileSelection(name, true); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "instance configuration save failed"})
		return
	}
	a.adminInstances(w)
}

func (a *App) persistProfileSelection(name string, enabled bool) error {
	seen := make(map[string]bool, len(a.cfg.EnabledProfiles))
	profiles := make([]string, 0, len(a.cfg.EnabledProfiles)+1)
	for _, current := range a.cfg.EnabledProfiles {
		if current == name {
			if enabled && !seen[current] {
				profiles = append(profiles, current)
				seen[current] = true
			}
			continue
		}
		if !seen[current] {
			profiles = append(profiles, current)
			seen[current] = true
		}
	}
	if enabled && !seen[name] {
		profiles = append(profiles, name)
	}
	a.cfg.EnabledProfiles = profiles
	return config.Save(configPathForApp(), a.cfg)
}

func (a *App) adminDashboard(w http.ResponseWriter) {
	events, eventErr := a.store.Events(-1, "", "")
	indicators, indicatorErr := a.store.Indicators()
	if eventErr != nil || indicatorErr != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "dashboard query failed"})
		return
	}
	counts := map[string]int{"events": len(events), "unique_ips": len(indicators), "high_risk": 0, "invocations": 0, "accepted": 0, "rejected": 0, "sessions": 0}
	products := map[string]int{}
	levels := map[string]int{}
	risk := map[string]int{"low": 0, "medium": 0, "high": 0}
	sessions := make(map[string]bool)
	for _, item := range indicators {
		if item.Score >= 60 {
			counts["high_risk"]++
		}
		switch {
		case item.Score >= 60:
			risk["high"]++
		case item.Score >= 30:
			risk["medium"]++
		default:
			risk["low"]++
		}
	}
	for _, event := range events {
		if event.InvocationID != "" {
			counts["invocations"]++
		}
		if event.SessionID != "" {
			sessions[event.SessionID] = true
		}
		if event.ExecutionOutcome == "synthetic_accepted" || event.ExecutionOutcome == "synthetic_stream_completed" {
			counts["accepted"]++
		}
		if event.ExecutionOutcome == "rejected_before_dispatch" {
			counts["rejected"]++
		}
		products[event.Product]++
		if event.InvocationLevel != "" {
			levels[string(event.InvocationLevel)]++
		}
	}
	counts["sessions"] = len(sessions)
	activity := make([]map[string]any, 0, 12)
	now := time.Now().UTC()
	for i := 11; i >= 0; i-- {
		end := now.Add(-time.Duration(i) * 2 * time.Hour)
		start := end.Add(-2 * time.Hour)
		count := 0
		for _, event := range events {
			if !event.ObservedAt.Before(start) && event.ObservedAt.Before(end) {
				count++
			}
		}
		activity = append(activity, map[string]any{"label": start.Local().Format("15:04"), "count": count})
	}
	productList := make([]map[string]any, 0, len(products))
	for product, count := range products {
		productList = append(productList, map[string]any{"name": product, "count": count})
	}
	sort.Slice(productList, func(i, j int) bool { return productList[i]["count"].(int) > productList[j]["count"].(int) })
	recent := events
	if len(recent) > 8 {
		recent = recent[:8]
	}
	enabled := append([]string{}, a.cfg.EnabledProfiles...)
	a.writeJSON(w, http.StatusOK, map[string]any{
		"service": "AegisLure", "synthetic_only": true, "generated_at": now,
		"counts": counts, "enabled_profiles": enabled, "admin_port": a.cfg.AdminPort,
		"admin_path_hint": "stored in root-owned config; never returned after setup",
		"activity":        activity, "products": productList, "risk_distribution": risk, "invocation_levels": levels, "recent_events": recent,
	})
}

func (a *App) adminEvents(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if value := r.URL.Query().Get("limit"); value != "" {
		_, _ = fmt.Sscanf(value, "%d", &limit)
	}
	if limit < 1 || limit > 1000 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 1000"})
		return
	}
	events, err := a.store.Events(limit, r.URL.Query().Get("product"), r.URL.Query().Get("ip"))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "event query failed"})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events), "synthetic_only": true})
}

func (a *App) adminInvocations(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	if limit < 1 || limit > 1000 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 1000"})
		return
	}
	events, err := a.store.Events(-1, r.URL.Query().Get("product"), r.URL.Query().Get("ip"))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invocation query failed"})
		return
	}
	items := make([]model.Event, 0, limit)
	for _, event := range events {
		if event.InvocationID == "" {
			continue
		}
		if value := r.URL.Query().Get("level"); value != "" && string(event.InvocationLevel) != value {
			continue
		}
		if value := r.URL.Query().Get("auth"); value != "" && event.AuthOutcome != value {
			continue
		}
		if value := r.URL.Query().Get("execution"); value != "" && event.ExecutionOutcome != value {
			continue
		}
		items = append(items, event)
		if len(items) == limit {
			break
		}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"invocations": items, "count": len(items), "synthetic_only": true})
}

type interactionChainView struct {
	ID              string                `json:"id"`
	SessionID       string                `json:"session_id"`
	Product         string                `json:"product"`
	FirstEventID    string                `json:"first_event_id"`
	LastEventID     string                `json:"last_event_id"`
	EventCount      int                   `json:"event_count"`
	Stage           string                `json:"stage"`
	IntentClass     string                `json:"intent_class"`
	InvocationLevel model.InvocationLevel `json:"invocation_level"`
	Score           int                   `json:"score"`
	Events          []model.Event         `json:"events"`
}

func (a *App) adminInteractionChains(w http.ResponseWriter, r *http.Request) {
	events, err := a.store.Events(-1, r.URL.Query().Get("product"), r.URL.Query().Get("ip"))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "chain query failed"})
		return
	}
	bySession := make(map[string]*interactionChainView)
	for i := len(events) - 1; i >= 0; i-- {
		event := events[i]
		if event.SessionID == "" {
			continue
		}
		item := bySession[event.SessionID]
		if item == nil {
			item = &interactionChainView{ID: "chain_" + security.Fingerprint(a.cfg.InstanceKey, event.SessionID)[:20], SessionID: event.SessionID, Product: event.Product, FirstEventID: event.EventID, LastEventID: event.EventID, InvocationLevel: model.L0}
			bySession[event.SessionID] = item
		}
		item.EventCount++
		item.Events = append(item.Events, event)
		item.LastEventID = event.EventID
		if event.Score > item.Score {
			item.Score = event.Score
		}
		if invocationRank(event.InvocationLevel) > invocationRank(item.InvocationLevel) {
			item.InvocationLevel = event.InvocationLevel
		}
		if event.IntentClass != "" {
			item.IntentClass = event.IntentClass
		}
	}
	result := make([]*interactionChainView, 0, len(bySession))
	for _, item := range bySession {
		switch item.InvocationLevel {
		case model.L4:
			item.Stage = "post_call_verified"
		case model.L3:
			item.Stage = "response_consumed"
		case model.L2:
			item.Stage = "synthetic_accepted"
		case model.L1:
			item.Stage = "rejected_attempt"
		default:
			item.Stage = "discovery"
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Score > result[j].Score })
	if limit := queryInt(r, "limit", 100); limit >= 1 && limit < len(result) {
		result = result[:limit]
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"chains": result, "synthetic_only": true})
}

func invocationRank(level model.InvocationLevel) int {
	switch level {
	case model.L4:
		return 4
	case model.L3:
		return 3
	case model.L2:
		return 2
	case model.L1:
		return 1
	default:
		return 0
	}
}

func (a *App) adminIndicators(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "csv" || format == "plain" || format == "txt" {
		content, checksum, err := a.store.Export(format, queryInt(r, "min_score", 0))
		if err != nil {
			a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "export failed"})
			return
		}
		w.Header().Set("Content-Type", map[string]string{"csv": "text/csv; charset=utf-8", "plain": "text/plain; charset=utf-8", "txt": "text/plain; charset=utf-8"}[format])
		w.Header().Set("Content-Disposition", "attachment; filename=indicators."+format)
		w.Header().Set("X-Content-SHA256", checksum)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
		return
	}
	items, err := a.store.Indicators()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "indicator query failed"})
		return
	}
	minScore := queryInt(r, "min_score", 0)
	filtered := items[:0]
	for _, item := range items {
		if item.Score >= minScore {
			filtered = append(filtered, item)
		}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": filtered, "approved_only": false, "note": "MVP exposes observations; production feeds must require manual approval and TTL."})
}

func (a *App) adminInstances(w http.ResponseWriter) {
	configured := make(map[string]bool, len(a.cfg.EnabledProfiles))
	for _, name := range a.cfg.EnabledProfiles {
		configured[name] = true
	}
	a.serverMu.RLock()
	running := make(map[string]bool, len(a.profileServers))
	for name := range a.profileServers {
		running[name] = true
	}
	a.serverMu.RUnlock()
	instances := make([]map[string]any, 0, len(a.profiles))
	for _, name := range []string{model.ProductNewAPI, model.ProductVLLM, model.ProductOllama, model.ProductSGLang, model.ProductLocalAI} {
		profile := a.profiles[name]
		state := "stopped"
		if running[name] {
			state = "running"
		}
		instances = append(instances, map[string]any{"id": "inst_" + name, "product": name, "profile_id": profile.ID, "port": profile.DefaultPort, "scenario": profile.Scenario, "state": state, "enabled": configured[name], "endpoint": fmt.Sprintf("%s:%d", a.cfg.PublicBind, profile.DefaultPort), "version": profile.DisplayVersion, "synthetic_only": true})
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"instances": instances})
}

func (a *App) adminPacks(w http.ResponseWriter) {
	a.writeJSON(w, http.StatusOK, map[string]any{"fingerprint_revision": "builtin-v1", "model_catalog_revision": "seed-2026q3", "scenario_revision": "builtin-safe-v1", "detector_revision": "builtin-rules-v1", "lifecycle": []string{"Draft", "Validate", "UnitTest", "Replay", "Shadow", "Canary", "Active", "Rollback"}})
}

func (a *App) rotateAdminEntry(w http.ResponseWriter) {
	token, err := security.RandomToken(18)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rotation failed"})
		return
	}
	a.cfg.AdminPath = "/" + token + "/"
	path := os.Getenv("HP_CONFIG")
	if path == "" {
		path = "config.json"
	}
	if err := config.Save(path, a.cfg); err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rotation failed"})
		return
	}
	a.mu.Lock()
	for id := range a.adminSessions {
		delete(a.adminSessions, id)
	}
	a.mu.Unlock()
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "entry path rotated; restart the admin listener if the port also changes", "new_path": a.cfg.AdminPath, "port": a.cfg.AdminPort})
}

func queryInt(r *http.Request, name string, fallback int) int {
	value := r.URL.Query().Get(name)
	if value == "" {
		return fallback
	}
	var result int
	if _, err := fmt.Sscanf(value, "%d", &result); err != nil {
		return fallback
	}
	return result
}

func sameOriginRequest(r *http.Request) bool {
	for _, header := range []string{"Origin", "Referer"} {
		value := strings.TrimSpace(r.Header.Get(header))
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" || !strings.EqualFold(parsed.Host, r.Host) || !strings.EqualFold(parsed.Scheme, requestScheme(r)) {
			return false
		}
	}
	return true
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func requestSourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}

func rateLimited(w http.ResponseWriter) {
	setSecurityHeaders(w)
	w.Header().Set("Retry-After", "60")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "temporarily rate limited"})
}

func configPathForApp() string {
	if path := os.Getenv("HP_CONFIG"); path != "" {
		return path
	}
	return "config.json"
}
