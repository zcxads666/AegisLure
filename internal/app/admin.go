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
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.HasPrefix(r.URL.Path, a.cfg.AdminPath) {
			silentClose(w)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, a.cfg.AdminPath)
		if (path == "" || path == "/") && r.Method == http.MethodGet {
			nonce := security.MustRandomToken(18)
			a.writeHTMLWithNonce(w, http.StatusOK, "AegisLure Admin", adminHTML(a.cfg.AdminPath, nonce), nonce)
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
		} else if values, ok := remove(state.Admin.RescueHashes); ok {
			state.Admin.RescueHashes = values
			reset = true
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
	case path == "indicators/ips":
		a.adminIndicators(w, r)
	case path == "instances":
		a.adminInstances(w)
	case path == "packs":
		a.adminPacks(w)
	case path == "identity-policies":
		a.writeJSON(w, http.StatusOK, map[string]any{"providers": []map[string]string{{"provider": "github", "mode": "local_only", "cross_site": "disabled_by_default"}, {"provider": "discord", "mode": "local_only", "cross_site": "blocked"}, {"provider": "linuxdo", "mode": "local_only", "cross_site": "pending_approval"}}})
	case path == "admin-entry:rotate" && r.Method == http.MethodPost:
		if !sameOriginRequest(r) {
			a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
			return
		}
		a.rotateAdminEntry(w)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "admin route not found"})
	}
}

func (a *App) adminDashboard(w http.ResponseWriter) {
	events, _ := a.store.Events(1000, "", "")
	indicators, _ := a.store.Indicators()
	counts := map[string]int{"events": len(events), "unique_ips": len(indicators), "high_risk": 0, "invocations": 0, "accepted": 0, "rejected": 0}
	for _, item := range indicators {
		if item.Score >= 60 {
			counts["high_risk"]++
		}
	}
	for _, event := range events {
		if event.InvocationID != "" {
			counts["invocations"]++
		}
		if event.ExecutionOutcome == "synthetic_accepted" || event.ExecutionOutcome == "synthetic_stream_completed" {
			counts["accepted"]++
		}
		if event.ExecutionOutcome == "rejected_before_dispatch" {
			counts["rejected"]++
		}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"service": "AegisLure", "synthetic_only": true, "counts": counts, "enabled_profiles": a.cfg.EnabledProfiles, "admin_port": a.cfg.AdminPort, "admin_path_hint": "stored in root-owned config; never returned after setup"})
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
	a.writeJSON(w, http.StatusOK, map[string]any{"events": events, "synthetic_only": true})
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
	a.writeJSON(w, http.StatusOK, map[string]any{"invocations": items, "synthetic_only": true})
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
	instances := make([]map[string]any, 0, len(a.cfg.EnabledProfiles))
	for _, name := range a.cfg.EnabledProfiles {
		profile := a.profiles[name]
		instances = append(instances, map[string]any{"id": "inst_" + name, "product": name, "profile_id": profile.ID, "port": profile.DefaultPort, "scenario": profile.Scenario, "state": "running", "synthetic_only": true})
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

func interpolateAdminHTML(template string, values ...string) string {
	for _, value := range values {
		marker := strings.Index(template, "%s")
		if marker < 0 {
			break
		}
		template = template[:marker] + value + template[marker+2:]
	}
	return template
}

func adminHTML(path, nonce string) string {
	pathJSON, _ := json.Marshal(path)
	return interpolateAdminHTML(`<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AegisLure · Control Plane</title>
<style>
:root{color-scheme:dark;--bg:#080d19;--panel:#111a2b;--panel-2:#16233a;--line:#263754;--text:#edf4ff;--muted:#8fa3c2;--cyan:#55d6c2;--blue:#72a7ff;--pink:#ff86b7;--danger:#ff8d8d;--shadow:0 24px 80px rgba(0,0,0,.28)}
*,*::before,*::after{box-sizing:border-box}
html{min-width:320px;background:var(--bg)}
body{margin:0;min-height:100vh;overflow-x:hidden;background:radial-gradient(circle at 15% 0,#17325d 0,transparent 34%),radial-gradient(circle at 100% 10%,#3c174b 0,transparent 28%),var(--bg);color:var(--text);font-family:"Inter","Noto Sans SC","Microsoft YaHei","PingFang SC",system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}
button,input{font:inherit}button{appearance:none;border:0;cursor:pointer;pointer-events:auto}
button:focus-visible,input:focus-visible{outline:3px solid rgba(85,214,194,.55);outline-offset:3px}
.app{display:grid;grid-template-columns:minmax(210px,240px) minmax(0,1fr);min-height:100vh}
.side{display:flex;flex-direction:column;position:sticky;top:0;align-self:start;min-height:100vh;border-right:1px solid rgba(142,169,214,.16);padding:28px 20px;background:rgba(5,10,21,.56);backdrop-filter:blur(18px)}
.brand{display:flex;gap:12px;align-items:center;margin-bottom:54px}.brand-mark{display:grid;place-items:center;width:40px;height:40px;flex:0 0 40px;border-radius:13px;background:linear-gradient(135deg,var(--cyan),var(--blue));color:#07121e;font-weight:900;box-shadow:0 12px 30px rgba(85,214,194,.25)}.brand strong{display:block;font-size:16px;letter-spacing:.03em}.brand small,.eyebrow{color:var(--muted);font-size:10px;letter-spacing:.16em;text-transform:uppercase}
.nav-label{margin:0 0 12px 10px;color:#607495;font-size:10px;letter-spacing:.16em;text-transform:uppercase}.nav-item{display:flex;align-items:center;gap:11px;padding:11px 12px;margin:5px 0;border-radius:11px;color:var(--muted);user-select:none}.nav-item.active{background:rgba(114,167,255,.13);color:var(--text)}.dot{width:7px;height:7px;flex:0 0 7px;border-radius:50%;background:var(--cyan);box-shadow:0 0 14px var(--cyan)}
.side-note{width:auto;margin-top:auto;padding-top:32px;color:#637896;font-size:12px}.main{width:100%;max-width:1360px;margin:0 auto;padding:clamp(20px,4vw,48px)}
.topbar{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-start;gap:18px;margin-bottom:30px}.topbar h1{margin:4px 0 7px;font-size:clamp(28px,4vw,44px);letter-spacing:-.04em}.topbar p{margin:0;color:var(--muted)}.status-pill{display:inline-flex;align-items:center;gap:8px;padding:9px 13px;border:1px solid rgba(85,214,194,.3);border-radius:999px;color:var(--cyan);background:rgba(85,214,194,.08);font-size:12px;white-space:nowrap}.status-pill:before{content:"";width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 12px currentColor}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));align-items:stretch;gap:18px}.card{min-width:0;position:relative;overflow:hidden;border:1px solid rgba(142,169,214,.17);border-radius:20px;background:linear-gradient(145deg,rgba(23,35,58,.92),rgba(12,19,34,.94));box-shadow:var(--shadow);padding:24px}.hero{grid-column:span 7;min-height:310px;padding:clamp(24px,3vw,34px)}.hero:after{content:"";position:absolute;z-index:0;pointer-events:none;width:260px;height:260px;right:-80px;bottom:-100px;border-radius:50%;border:1px solid rgba(85,214,194,.2);box-shadow:0 0 0 22px rgba(85,214,194,.03),0 0 0 44px rgba(85,214,194,.025)}.hero>*{position:relative;z-index:1}.hero h2{max-width:520px;margin:16px 0 12px;font-size:clamp(27px,4vw,48px);line-height:1.06;letter-spacing:-.06em}.hero p{max-width:520px;color:var(--muted)}.form-card{grid-column:span 5}
.card h3{margin:0 0 6px;font-size:19px}.card-sub{margin:0 0 22px;color:var(--muted);font-size:13px}.field{display:block;margin:15px 0}.field span{display:block;margin-bottom:7px;color:#b8c8e1;font-size:12px}.field input{display:block;width:100%;min-width:0;padding:12px 13px;border:1px solid var(--line);border-radius:11px;background:#0c1526;color:var(--text);outline:none;transition:border .2s,box-shadow .2s}.field input:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(114,167,255,.12)}
.primary,.secondary{position:relative;z-index:2;display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:44px;pointer-events:auto}.primary{width:100%;padding:13px 16px;border-radius:11px;background:linear-gradient(100deg,var(--cyan),var(--blue));color:#07121e;font-weight:800;box-shadow:0 12px 25px rgba(85,214,194,.18);transition:transform .16s,filter .16s,box-shadow .16s}.primary:hover{filter:brightness(1.08);transform:translateY(-1px);box-shadow:0 15px 30px rgba(85,214,194,.27)}.primary:active{transform:translateY(0)}.secondary{padding:10px 14px;border-radius:10px;background:rgba(114,167,255,.12);color:var(--text);border:1px solid rgba(114,167,255,.2);transition:background .16s,border-color .16s}.secondary:hover{background:rgba(114,167,255,.22);border-color:rgba(114,167,255,.45)}
.message{min-height:24px;margin:15px 0 0;color:var(--muted);font-size:13px;white-space:pre-wrap}.message.error{color:var(--danger)}.info-card{grid-column:span 5}.info-card p{color:var(--muted);font-size:13px}.signal-list{display:grid;gap:10px;margin-top:18px}.signal{display:flex;align-items:center;gap:10px;color:#bdd0ec;font-size:13px}.signal i{width:9px;height:9px;flex:0 0 9px;border-radius:3px;background:var(--pink);transform:rotate(45deg)}.wide{grid-column:span 7}.metric-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:19px}.metric{min-width:0;padding:16px;border:1px solid rgba(142,169,214,.14);border-radius:14px;background:rgba(6,12,24,.42)}.metric span{display:block;color:var(--muted);font-size:11px}.metric strong{display:block;margin-top:7px;font-size:clamp(22px,3vw,27px);letter-spacing:-.05em}.profile-row{display:flex;flex-wrap:wrap;gap:9px;margin-top:20px}.profile{padding:8px 10px;border-radius:9px;background:rgba(85,214,194,.08);border:1px solid rgba(85,214,194,.18);color:var(--cyan);font-size:12px}.hidden{display:none!important}.footer-note{margin-top:22px;color:#647996;font-size:12px}.footer-note strong{color:#9db2d1}
@media(max-width:1100px){.main{padding:28px 24px}.app{grid-template-columns:210px minmax(0,1fr)}}
@media(max-width:900px){.app{display:block}.side{display:none}.main{padding:24px 18px 40px}.hero,.form-card,.info-card,.wide{grid-column:1/-1}.metric-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:520px){body{font-size:14px}.main{padding:18px 12px 32px}.topbar{margin-bottom:22px}.topbar h1{font-size:31px}.status-pill{width:100%;justify-content:center}.card{padding:18px;border-radius:16px}.hero{min-height:0;padding:22px}.hero h2{font-size:34px}.metric-grid{grid-template-columns:1fr}.secondary{width:100%;margin-top:8px}.footer-note{margin-top:16px}}
</style></head>
<body><div class="app"><aside class="side"><div class="brand"><div class="brand-mark">A</div><div><strong>AegisLure</strong><small>Control Plane</small></div></div><p class="nav-label">Workspace</p><div class="nav-item active"><span class="dot"></span>Overview</div><div class="nav-item"><span>◈</span>Observations</div><div class="nav-item"><span>⌁</span>Instances</div><div class="nav-item"><span>◇</span>Rules &amp; Packs</div><p class="side-note">Synthetic-only telemetry<br>No real model or URL access</p></aside>
<main class="main"><header class="topbar"><div><p class="eyebrow">Standalone sensor · local node</p><h1>Control plane</h1><p>Monitor decoy traffic, simulated calls and risk signals.</p></div><div id="status-pill" class="status-pill">CONNECTING</div></header>
<section id="setup" class="grid hidden"><div class="card hero"><p class="eyebrow">First-time setup</p><h2>Make the control plane yours.</h2><p>Create the local owner account to open the observation dashboard. This deployment is synthetic-only: no real LLM, model repository or attacker-supplied URL is contacted.</p><p class="footer-note"><strong>Local access only is recommended.</strong> Keep this management endpoint behind your trusted network or VPN.</p></div><form id="owner-form" class="card form-card"><h3>Create owner</h3><p class="card-sub">Choose an account for this control plane.</p><label class="field"><span>Username</span><input id="owner-username" autocomplete="username" maxlength="128" required></label><label class="field"><span>Password · 8 characters minimum</span><input id="owner-password" type="password" autocomplete="new-password" minlength="8" maxlength="128" required></label><button class="primary" type="submit">Create owner <span>→</span></button><p id="setup-message" class="message"></p></form><div class="card info-card"><h3>What is protected</h3><p>All observations are bounded, redacted and stored locally. Admin changes remain behind the hidden path, session cookie and same-origin mutation checks.</p><div class="signal-list"><div class="signal"><i></i>IP and session risk signals</div><div class="signal"><i></i>Virtual invocation timeline</div><div class="signal"><i></i>Exportable evidence trail</div></div></div></section>
<section id="login" class="grid hidden"><div class="card hero"><p class="eyebrow">Secure observation console</p><h2>See the signal behind the noise.</h2><p>Review product discovery, synthetic invocation attempts, simulated effects and the evidence chain behind each risk score.</p><p class="footer-note"><strong>Admin session:</strong> 8 hours maximum · same-origin requests only</p></div><form id="login-form" class="card form-card"><h3>Welcome back</h3><p class="card-sub">Sign in to the AegisLure control plane.</p><label class="field"><span>Username</span><input id="login-username" autocomplete="username" maxlength="128" required></label><label class="field"><span>Password</span><input id="login-password" type="password" autocomplete="current-password" required></label><button class="primary" type="submit">Sign in <span>→</span></button><p id="login-message" class="message"></p></form><div class="card info-card"><h3>Decoy boundary</h3><p>The console reports observations only. It never executes prompts, loads models, follows URLs or contacts upstream providers.</p><div class="signal-list"><div class="signal"><i></i>Bounded request ingestion</div><div class="signal"><i></i>Deterministic synthetic responses</div><div class="signal"><i></i>Auditable configuration revisions</div></div></div></section>
<section id="dashboard" class="grid hidden"><div class="card wide"><p class="eyebrow">Live overview</p><h2>Observation status</h2><div class="metric-grid"><div class="metric"><span>Events</span><strong id="metric-events">—</strong></div><div class="metric"><span>Unique IPs</span><strong id="metric-ips">—</strong></div><div class="metric"><span>Invocations</span><strong id="metric-invocations">—</strong></div><div class="metric"><span>High risk</span><strong id="metric-risk">—</strong></div></div><div id="profile-list" class="profile-row"></div></div><div class="card info-card"><h3>Session</h3><p id="dashboard-copy">Authenticated · synthetic-only</p><button id="refresh" class="secondary" type="button">Refresh data</button> <button id="logout" class="secondary" type="button">Log out</button><p class="footer-note">No real inference is performed.</p></div></section>
<p id="output" class="footer-note"></p></main></div>
<noscript><p>JavaScript is required for the control plane.</p></noscript>
<script nonce="%s">(function(){const base=%s;const q=(id)=>document.getElementById(id);const setup=q('setup'),login=q('login'),dashboard=q('dashboard'),pill=q('status-pill'),output=q('output');function show(which){setup.classList.toggle('hidden',which!=='setup');login.classList.toggle('hidden',which!=='login');dashboard.classList.toggle('hidden',which!=='dashboard')}function message(id,text,error){const el=q(id);if(!el)return;el.textContent=text;el.classList.toggle('error',!!error)}function setPill(text,error){pill.textContent=text;pill.style.color=error?'var(--danger)':'var(--cyan)'}async function request(path,options){const init=Object.assign({credentials:'same-origin'},options||{});init.headers=Object.assign({'Accept':'application/json'},init.headers||{});if(init.body&&!init.headers['Content-Type'])init.headers['Content-Type']='application/json';const response=await fetch(base+path,init);let data={};try{data=await response.json()}catch(_){data={}}if(!response.ok){const error=new Error(data.error||data.message||('request failed: '+response.status));error.status=response.status;error.data=data;throw error}return data}function render(data){const c=data.counts||{};q('metric-events').textContent=c.events||0;q('metric-ips').textContent=c.unique_ips||0;q('metric-invocations').textContent=c.invocations||0;q('metric-risk').textContent=c.high_risk||0;q('profile-list').innerHTML=(data.enabled_profiles||[]).map(function(p){const span=document.createElement('span');span.className='profile';span.textContent=p;return span.outerHTML}).join('')}async function refresh(){try{const data=await request('admin/api/v1/dashboard');render(data);show('dashboard');setPill('ONLINE');output.textContent='Last refreshed '+new Date().toLocaleTimeString()}catch(error){show('login');setPill('AUTH REQUIRED',true);message('login-message',error.status===401?'Sign in to continue.':'Dashboard unavailable: '+error.message,true)}}q('owner-form').addEventListener('submit',async function(event){event.preventDefault();message('setup-message','Creating owner…',false);try{const data=await request('setup/create-owner',{method:'POST',body:JSON.stringify({username:q('owner-username').value,password:q('owner-password').value})});const codes=(data.recovery_codes||[]).join('\n');message('setup-message','Owner created. Save the recovery codes before continuing.',false);output.textContent='Recovery codes (shown once):\n'+codes;show('login');setPill('READY')}catch(error){message('setup-message',error.message||'Owner setup failed',true)}});q('login-form').addEventListener('submit',async function(event){event.preventDefault();message('login-message','Signing in…',false);try{await request('admin/api/v1/auth/login',{method:'POST',body:JSON.stringify({username:q('login-username').value,password:q('login-password').value})});await refresh()}catch(error){message('login-message',error.message||'Invalid credentials',true)}});q('refresh').addEventListener('click',refresh);q('logout').addEventListener('click',async function(){try{await request('admin/api/v1/auth/logout',{method:'POST'});show('login');setPill('SIGNED OUT');message('login-message','You have been signed out.',false)}catch(error){message('login-message','Sign out failed',true)}});(async function init(){try{const data=await request('setup/status');if(data.initialized){show('login');setPill('AUTH REQUIRED')}else{show('setup');setPill('SETUP READY')}}catch(error){setPill('UNAVAILABLE',true);message('setup-message','Admin status unavailable: '+error.message,true)}})()})();</script></body></html>`, htmlEscape(nonce), string(pathJSON))
}
