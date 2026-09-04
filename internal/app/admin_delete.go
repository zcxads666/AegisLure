package app

import (
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func decodeAdminTarget(raw, kind string) (string, bool) {
	target, err := url.PathUnescape(strings.TrimSpace(raw))
	if err != nil || target == "" || strings.Contains(target, "/") {
		return "", false
	}
	return target, true
}

func (a *App) allowAdminDelete(w http.ResponseWriter, r *http.Request, bucket string) bool {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return false
	}
	if !a.allowRate("admin-"+bucket+"-delete:"+requestSourceIP(r), 60, time.Minute) {
		rateLimited(w)
		return false
	}
	return true
}

func (a *App) adminDeleteEvent(w http.ResponseWriter, r *http.Request, rawID string) {
	eventID, ok := decodeAdminTarget(rawID, "event")
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
		return
	}
	if !a.allowAdminDelete(w, r, "event") {
		return
	}
	ids := []string{eventID}
	events, err := a.store.Events(-1, "", "")
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "event delete failed"})
		return
	}
	for _, event := range adminDisplayEvents(events) {
		if event.EventID == eventID {
			ids = adminDisplayEventIDs(event)
			break
		}
	}
	deleted, err := a.store.SoftDeleteEventIDs(ids)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "event delete failed"})
		return
	}
	if deleted == 0 {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
		return
	}
	a.recordAudit(r, "event.delete", eventID, "success", map[string]string{"deleted_events": strconv.Itoa(deleted), "logical": "true"})
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": true, "deleted_events": deleted, "id": eventID, "logical": true})
}

func (a *App) adminDeleteInvocation(w http.ResponseWriter, r *http.Request, rawID string) {
	invocationID, ok := decodeAdminTarget(rawID, "invocation")
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "invocation not found"})
		return
	}
	if !a.allowAdminDelete(w, r, "invocation") {
		return
	}
	ids, err := a.store.EventIDsForInvocation(invocationID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invocation delete failed"})
		return
	}
	deleted, err := a.store.SoftDeleteEventIDs(ids)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "invocation delete failed"})
		return
	}
	if deleted == 0 {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "invocation not found"})
		return
	}
	a.recordAudit(r, "invocation.delete", invocationID, "success", map[string]string{"deleted_events": strconv.Itoa(deleted), "logical": "true"})
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": true, "deleted_events": deleted, "id": invocationID, "logical": true})
}

func (a *App) adminDeleteInteractionChain(w http.ResponseWriter, r *http.Request, rawID string) {
	chainID, ok := decodeAdminTarget(rawID, "interaction chain")
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "interaction chain not found"})
		return
	}
	if !a.allowAdminDelete(w, r, "interaction-chain") {
		return
	}
	events, err := a.store.Events(-1, "", "")
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "chain delete failed"})
		return
	}
	events = adminDisplayEvents(events)
	var ids []string
	for _, view := range a.buildInteractionChainViews(events, a.store.InteractionChainConfig()) {
		if view.ID != chainID {
			continue
		}
		ids = make([]string, 0, len(view.Events))
		for _, event := range view.Events {
			ids = append(ids, adminDisplayEventIDs(event)...)
		}
		ids = uniqueStrings(ids)
		break
	}
	if len(ids) == 0 {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "interaction chain not found"})
		return
	}
	deleted, err := a.store.SoftDeleteEventIDs(ids)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "chain delete failed"})
		return
	}
	a.recordAudit(r, "interaction-chain.delete", chainID, "success", map[string]string{"deleted_events": strconv.Itoa(deleted), "logical": "true"})
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": true, "deleted_events": deleted, "id": chainID, "logical": true})
}

func (a *App) adminDeleteIndicator(w http.ResponseWriter, r *http.Request, rawID string) {
	identifier, ok := decodeAdminTarget(rawID, "indicator")
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "indicator not found"})
		return
	}
	if !a.allowAdminDelete(w, r, "indicator") {
		return
	}
	items, err := a.store.Indicators()
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "indicator delete failed"})
		return
	}
	ip := ""
	if parsed := net.ParseIP(identifier); parsed != nil {
		ip = parsed.String()
	} else {
		for _, item := range items {
			if indicatorID(a.cfg.InstanceKey, item.IP) == identifier {
				ip = item.IP
				break
			}
		}
	}
	if ip == "" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "indicator not found"})
		return
	}
	ids, err := a.store.EventIDsForSourceIP(ip)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "indicator delete failed"})
		return
	}
	deleted, err := a.store.SoftDeleteEventIDs(ids)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "indicator delete failed"})
		return
	}
	if deleted == 0 {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "indicator not found"})
		return
	}
	a.recordAudit(r, "indicator.delete", ip, "success", map[string]string{"deleted_events": strconv.Itoa(deleted), "logical": "true"})
	a.writeJSON(w, http.StatusOK, map[string]any{"success": true, "deleted": true, "deleted_events": deleted, "ip": ip, "logical": true})
}
