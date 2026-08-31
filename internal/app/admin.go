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
	"strconv"
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
		if !a.adminHostAllowed(r.Host) || !strings.HasPrefix(r.URL.Path, a.cfg.AdminPath) {
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

func (a *App) auditActor(r *http.Request) string {
	if r != nil {
		if cookie, err := r.Cookie("hp_admin"); err == nil {
			a.mu.Lock()
			session, ok := a.adminSessions[cookie.Value]
			a.mu.Unlock()
			if ok && session.Username != "" {
				return session.Username
			}
		}
	}
	return "system"
}

func (a *App) recordAudit(r *http.Request, action, target, result string, metadata map[string]string) {
	if a.store == nil {
		return
	}
	if err := a.store.AppendAudit(model.AuditEntry{Actor: a.auditActor(r), Action: action, Target: target, Result: result, Metadata: metadata}); err != nil && a.log != nil {
		a.log.Printf("audit append failed action=%s target=%s error=%v", action, target, err)
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
	a.recordAudit(r, "admin.setup.create_owner", "admin", "success", map[string]string{"username_fp": security.Fingerprint(a.cfg.InstanceKey, username)[:20]})
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
	a.recordAudit(r, "admin.login", "admin", "success", nil)
	http.SetCookie(w, &http.Cookie{Name: "hp_admin", Value: id, Path: a.cfg.AdminPath, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.adminCookieSecure(r), MaxAge: 8 * 3600})
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
	a.recordAudit(r, "admin.recovery.reset", "admin", "success", nil)
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
	http.SetCookie(w, &http.Cookie{Name: "hp_admin", Value: "", Path: a.cfg.AdminPath, MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.adminCookieSecure(r)})
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
	if path == "health" && r.Method == http.MethodGet {
		a.adminHealth(w)
		return
	}
	if _, ok := a.adminSession(r); !ok {
		a.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "admin authentication required"})
		return
	}
	if a.handleAdminPackAPI(w, r, path) {
		return
	}
	switch {
	case path == "dashboard":
		a.adminDashboard(w)
	case path == "import-sources" || strings.HasPrefix(path, "import-sources/"):
		a.adminImportSourceRoute(w, r, path)
	case path == "exports" && r.Method == http.MethodPost:
		a.adminExportCreate(w, r)
	case strings.HasPrefix(path, "exports/") && r.Method == http.MethodGet:
		a.adminExportRoute(w, r, path)
	case path == "events":
		a.adminEvents(w, r)
	case strings.HasPrefix(path, "events/") && r.Method == http.MethodGet:
		a.adminEventDetail(w, r, strings.TrimPrefix(path, "events/"))
	case path == "sessions" && r.Method == http.MethodGet:
		a.adminSessionsList(w, r)
	case strings.HasPrefix(path, "sessions/") && r.Method == http.MethodGet:
		a.adminSessionDetail(w, r, strings.TrimPrefix(path, "sessions/"))
	case path == "invocations":
		a.adminInvocations(w, r)
	case strings.HasPrefix(path, "invocations/") && r.Method == http.MethodGet:
		a.adminInvocationDetail(w, r, strings.TrimPrefix(path, "invocations/"))
	case path == "interaction-chains":
		a.adminInteractionChains(w, r)
	case strings.HasPrefix(path, "interaction-chains/") && r.Method == http.MethodGet:
		a.adminInteractionChainDetail(w, r, strings.TrimPrefix(path, "interaction-chains/"))
	case strings.HasPrefix(path, "actors/") && r.Method == http.MethodGet:
		a.adminActorDetail(w, r, strings.TrimPrefix(path, "actors/"))
	case path == "indicators" || path == "indicators/ips":
		a.adminIndicators(w, r)
	case strings.HasPrefix(path, "indicators/") && r.Method == http.MethodPost:
		a.adminIndicatorAction(w, r, strings.TrimPrefix(path, "indicators/"))
	case path == "identity-indicators" && r.Method == http.MethodGet:
		a.adminIdentityIndicators(w, r)
	case strings.HasPrefix(path, "identity-indicators/") && r.Method == http.MethodPost:
		a.adminIdentityIndicatorAction(w, r, strings.TrimPrefix(path, "identity-indicators/"))
	case strings.HasPrefix(path, "identity-policies/") && r.Method == http.MethodPost:
		a.adminIdentityPolicyAction(w, r, strings.TrimPrefix(path, "identity-policies/"))
	case path == "instances" && r.Method == http.MethodGet:
		a.adminInstances(w)
	case path == "instances" && r.Method == http.MethodPost:
		a.adminInstanceCreate(w, r)
	case path == "instances":
		a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	case path == "packs":
		a.adminPacks(w)
	case path == "audit":
		a.adminAudit(w, r)
	case path == "identity-policies":
		a.writeJSON(w, http.StatusOK, map[string]any{"providers": []map[string]string{{"provider": "github", "mode": "local_only", "cross_site": "disabled_by_default"}, {"provider": "discord", "mode": "local_only", "cross_site": "blocked"}, {"provider": "linuxdo", "mode": "local_only", "cross_site": "pending_approval"}}})
	case path == "identities" && r.Method == http.MethodGet:
		a.adminIdentities(w)
	case strings.HasPrefix(path, "identities/"):
		a.adminIdentityAction(w, r, strings.TrimPrefix(path, "identities/"))
	case strings.HasPrefix(path, "instances/") && (r.Method == http.MethodGet || r.Method == http.MethodPatch):
		a.adminInstanceRoute(w, r, strings.TrimPrefix(path, "instances/"))
	case path == "auth/change-password" && r.Method == http.MethodPost:
		a.adminChangePassword(w, r)
	case path == "admin-entry:rotate" && r.Method == http.MethodPost:
		if !sameOriginRequest(r) {
			a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
			return
		}
		a.rotateAdminEntry(w, r)
	case strings.HasPrefix(path, "instances/") && r.Method == http.MethodPost:
		a.adminInstanceAction(w, r, path)
	default:
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "admin route not found"})
	}
}

func (a *App) adminHealth(w http.ResponseWriter) {
	a.serverMu.RLock()
	adminReady := a.adminServer != nil
	listeners := make(map[string]map[string]any, len(a.cfg.EnabledProfiles))
	allReady := adminReady
	for _, name := range a.cfg.EnabledProfiles {
		listener := a.profilePorts[name]
		server := a.profileServers[name]
		actualPort := a.actualProfilePortLocked(name)
		expectedPort := a.cfg.ProfilePorts[name]
		ready := listener != nil && server != nil && actualPort == expectedPort && expectedPort > 0
		state := "running"
		if !ready {
			state = "degraded"
			allReady = false
		}
		listeners[name] = map[string]any{"ready": ready, "state": state, "expected_port": expectedPort, "actual_port": actualPort, "revision": a.portRevisionLocked(name, actualPort)}
	}
	a.serverMu.RUnlock()
	status := http.StatusOK
	if !allReady {
		status = http.StatusServiceUnavailable
	}
	a.writeJSON(w, status, map[string]any{"healthy": allReady, "admin_ready": adminReady, "listeners": listeners, "expected_profiles": a.cfg.EnabledProfiles, "synthetic_only": true})
}

func (a *App) adminIdentities(w http.ResponseWriter) {
	items := make([]map[string]any, 0)
	for _, identity := range a.store.ListHoneyIdentities() {
		items = append(items, safeIdentityView(identity))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"identities": items, "count": len(items), "raw_provider_id": false, "email": false, "token": false})
}

func safeIdentityView(identity model.HoneyIdentity) map[string]any {
	return map[string]any{
		"id":            identity.ID,
		"provider":      identity.Provider,
		"subject_hmac":  identity.SubjectHMAC,
		"honey_user_id": identity.HoneyUserID,
		"scopes":        identity.Scopes,
		"policy_mode":   identity.PolicyMode,
		"linked_at":     identity.LinkedAt,
		"last_seen_at":  identity.LastSeenAt,
		"revoked_at":    identity.RevokedAt,
	}
}

func (a *App) adminAudit(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	if limit < 1 || limit > 1000 {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 1000"})
		return
	}
	entries, err := a.store.AuditEntries(limit)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "audit query failed"})
		return
	}
	chainValid := a.store.VerifyAuditChain() == nil
	a.writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": len(entries), "chain_valid": chainValid, "remote_replication": false})
}

func (a *App) adminIdentityAction(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity not found"})
		return
	}
	id, err := url.PathUnescape(parts[0])
	if err != nil || id == "" || strings.Contains(id, "/") {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity not found"})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodGet {
		for _, identity := range a.store.ListHoneyIdentities() {
			if identity.ID != id {
				continue
			}
			a.writeJSON(w, http.StatusOK, map[string]any{"identity": safeIdentityView(identity), "raw_provider_id": false, "email": false, "token": false})
			return
		}
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity not found"})
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		if !sameOriginRequest(r) {
			a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
			return
		}
		if !a.allowRate("admin-identity-delete:"+requestSourceIP(r), 30, time.Minute) {
			rateLimited(w)
			return
		}
		if err := a.store.DeleteHoneyIdentity(id); err != nil {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity not found"})
			return
		}
		a.recordAudit(r, "identity.delete", id, "success", nil)
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": true, "id": id})
		return
	}
	if len(parts) == 2 && parts[1] == "revoke" && r.Method == http.MethodPost {
		if !sameOriginRequest(r) {
			a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
			return
		}
		if !a.allowRate("admin-identity-revoke:"+requestSourceIP(r), 30, time.Minute) {
			rateLimited(w)
			return
		}
		if err := a.store.RevokeHoneyIdentity(id); err != nil {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "identity not found"})
			return
		}
		a.recordAudit(r, "identity.revoke", id, "success", nil)
		a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "revoked": true, "id": id})
		return
	}
	a.writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
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
	a.recordAudit(r, "admin.password.change", "admin", "success", nil)
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "message": "password changed; sign in again"})
}

func (a *App) adminInstanceAction(w http.ResponseWriter, r *http.Request, path string) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "instances" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance route not found"})
		return
	}
	name, action := parts[1], ""
	if len(parts) == 3 {
		action = parts[2]
	} else {
		var ok bool
		name, action, ok = strings.Cut(parts[1], ":")
		if !ok {
			a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "instance route not found"})
			return
		}
	}
	name = strings.TrimPrefix(name, "inst_")
	if _, ok := a.profiles[name]; !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "profile not found"})
		return
	}
	if action == "move-port" || action == "dry-run" {
		a.adminMovePort(w, r, name, action == "dry-run")
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
	a.recordAudit(r, "instance."+action, "inst_"+name, "success", map[string]string{"profile": name})
	a.adminInstances(w)
}

func (a *App) adminMovePort(w http.ResponseWriter, r *http.Request, profile string, dryRun bool) {
	if !a.allowRate("admin-instance-port:"+profile, 20, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 8*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
		return
	}
	var request portMoveRequest
	if err := decodeStrictValue(body, &request); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid port change request"})
		return
	}
	result, err := a.moveProfilePort(profile, request, dryRun)
	if err != nil {
		status := http.StatusConflict
		if strings.Contains(err.Error(), "must be") || strings.Contains(err.Error(), "outside") || strings.Contains(err.Error(), "not found") {
			status = http.StatusUnprocessableEntity
		}
		a.writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	if !dryRun && result.Applied {
		a.recordAudit(r, "instance.move_port", "inst_"+profile, "success", map[string]string{
			"from_port": strconv.Itoa(result.CurrentPort), "to_port": strconv.Itoa(result.DesiredPort), "revision": result.DesiredRevision,
		})
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"plan": result, "dry_run": dryRun, "safe": true})
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
	items, decisions, err := a.filteredIndicators(r)
	if err != nil {
		status := http.StatusInternalServerError
		var validationErr *indicatorQueryError
		if errors.As(err, &validationErr) {
			status = http.StatusBadRequest
		}
		a.writeJSON(w, status, map[string]string{"error": err.Error()})
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format != "" {
		if format == "nftables" && r.URL.Query().Get("status") != "approved" {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nftables export requires status=approved"})
			return
		}
		content, contentType, err := renderIndicatorExport(items, decisions, format, a.cfg.InstanceKey)
		if err != nil {
			status := http.StatusInternalServerError
			if strings.Contains(err.Error(), "unsupported") {
				status = http.StatusBadRequest
			}
			a.writeJSON(w, status, map[string]string{"error": err.Error()})
			return
		}
		checksum := security.Fingerprint(a.cfg.InstanceKey, content)
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", "attachment; filename=indicators."+indicatorExportExtension(format))
		w.Header().Set("X-Content-SHA256", checksum)
		a.recordAudit(r, "indicator.export", "indicators", "success", map[string]string{"format": format, "min_score": strconv.Itoa(queryInt(r, "min_score", 0)), "status": r.URL.Query().Get("status")})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
		return
	}
	views := make([]map[string]any, 0, len(items))
	for _, item := range items {
		views = append(views, indicatorView(item, decisions[item.IP], a.cfg.InstanceKey))
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": views, "count": len(views), "approved_only": r.URL.Query().Get("status") == "approved", "note": "Standalone decisions require manual approval and always carry a TTL; no permanent block is emitted."})
}

func (a *App) adminInstances(w http.ResponseWriter) {
	configured := make(map[string]bool, len(a.cfg.EnabledProfiles))
	for _, name := range a.cfg.EnabledProfiles {
		configured[name] = true
	}
	a.serverMu.RLock()
	running := make(map[string]bool, len(a.profileServers))
	actualPorts := make(map[string]int, len(a.profileServers))
	portRevisions := make(map[string]string, len(a.profileServers))
	for name := range a.profileServers {
		running[name] = true
	}
	for name := range a.profiles {
		port := a.actualProfilePortLocked(name)
		actualPorts[name] = port
		portRevisions[name] = a.portRevisionLocked(name, port)
	}
	a.serverMu.RUnlock()
	instances := make([]map[string]any, 0, len(a.profiles))
	for _, name := range []string{model.ProductNewAPI, model.ProductVLLM, model.ProductOllama, model.ProductSGLang, model.ProductLocalAI} {
		profile := a.profiles[name]
		profile = a.applyRuntimePacks(profile)
		state := "stopped"
		if running[name] {
			state = "running"
		}
		port := actualPorts[name]
		if port == 0 {
			port = profile.DefaultPort
		}
		instances = append(instances, map[string]any{"id": "inst_" + name, "product": name, "profile_id": profile.ID, "port": port, "port_pool": a.cfg.PortPools[name], "port_revision": portRevisions[name], "scenario": profile.Scenario, "effect_scope": profile.EffectScope, "effect_ttl_seconds": int(profile.EffectTTL / time.Second), "state": state, "enabled": configured[name], "endpoint": fmt.Sprintf("%s:%d", a.cfg.PublicBind, port), "version": profile.DisplayVersion, "synthetic_only": true})
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"instances": instances})
}

func (a *App) adminPacks(w http.ResponseWriter) {
	items := make([]map[string]any, 0)
	for _, kind := range []string{model.PackKindFingerprint, model.PackKindModel, model.PackKindScenario, model.PackKindDetector} {
		for _, pack := range a.store.ListPacks(kind) {
			items = append(items, packSummary(pack))
		}
	}
	bindings := a.store.PackBindings()
	boundRevisions := make(map[string]string)
	for _, name := range []string{model.ProductNewAPI, model.ProductVLLM, model.ProductOllama, model.ProductSGLang, model.ProductLocalAI} {
		for _, kind := range []string{model.PackKindFingerprint, model.PackKindModel, model.PackKindScenario, model.PackKindDetector} {
			if pack, ok := a.store.BoundPack(kind, "inst_"+name); ok {
				boundRevisions[name+"/"+kind] = pack.Revision
			}
		}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"fingerprint_revision": "builtin-v1", "model_catalog_revision": "seed-2026q3", "scenario_revision": "builtin-safe-v1", "detector_revision": "builtin-rules-v1", "lifecycle": []string{model.PackDraft, model.PackValidated, model.PackUnitTest, model.PackReplay, model.PackShadow, model.PackCanary, model.PackActive, model.PackRollback}, "items": items, "bindings": bindings, "bound_revisions": boundRevisions, "data_only": true})
}

func (a *App) rotateAdminEntry(w http.ResponseWriter, r *http.Request) {
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
	a.recordAudit(r, "admin.entry.rotate", "admin", "success", map[string]string{"path_fp": security.Fingerprint(a.cfg.InstanceKey, a.cfg.AdminPath)[:20]})
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

func (a *App) adminCookieSecure(r *http.Request) bool {
	return r.TLS != nil || a.cfg.RequireAdminTLS || os.Getenv("HP_COOKIE_SECURE") == "1"
}

func (a *App) adminHostAllowed(value string) bool {
	host, port, hasPort, ok := parseAdminHost(value)
	if !ok {
		return false
	}
	if len(a.cfg.AdminHostAllowlist) == 0 {
		return true
	}
	for _, allowed := range a.cfg.AdminHostAllowlist {
		allowedHost, allowedPort, allowedHasPort, allowedOK := parseAdminHost(allowed)
		if !allowedOK {
			continue
		}
		if strings.EqualFold(host, allowedHost) && (!allowedHasPort || hasPort && port == allowedPort) {
			return true
		}
	}
	return false
}

func parseAdminHost(value string) (host, port string, hasPort, ok bool) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n,/\\?# \t") {
		return "", "", false, false
	}
	if strings.HasPrefix(value, "[") {
		if parsedHost, parsedPort, err := net.SplitHostPort(value); err == nil {
			if parsedHost == "" || !validHostPort(parsedPort) {
				return "", "", false, false
			}
			return parsedHost, parsedPort, true, true
		}
		if strings.HasSuffix(value, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
			return host, "", false, host != "" && net.ParseIP(host) != nil
		}
		return "", "", false, false
	}
	if strings.Count(value, ":") == 1 {
		parsedHost, parsedPort, err := net.SplitHostPort(value)
		if err != nil || parsedHost == "" || !validHostPort(parsedPort) {
			return "", "", false, false
		}
		return parsedHost, parsedPort, true, true
	}
	if strings.Contains(value, ":") {
		// Host headers must bracket IPv6 literals when a port is absent too.
		return "", "", false, false
	}
	return value, "", false, true
}

func validHostPort(value string) bool {
	port, err := strconv.Atoi(value)
	return err == nil && port >= 1 && port <= 65535
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
