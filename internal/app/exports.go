package app

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/zcxads666/AegisLure/internal/security"
)

const (
	localExportTTL       = 15 * time.Minute
	localExportMaxBytes  = 16 << 20
	localExportMaxStored = 16
)

// localExportJob is intentionally transient and bounded. The generated
// document contains only the already-filtered local indicator projection; it
// is not a support bundle and is never written to the SQLite or JSONL state.
type localExportJob struct {
	ID          string
	Format      string
	ContentType string
	Content     string
	Checksum    string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

type indicatorExportRequest struct {
	Status         string `json:"status"`
	MinScore       *int   `json:"min_score"`
	Confidence     string `json:"confidence"`
	SiteID         string `json:"site_id"`
	MinSensorCount *int   `json:"min_sensor_count"`
	SeenSince      string `json:"seen_since"`
	Format         string `json:"format"`
}

func (a *App) adminExportCreate(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		a.writeJSON(w, http.StatusForbidden, map[string]string{"error": "cross-site request rejected"})
		return
	}
	if !a.allowRate("admin-export-create:"+requestSourceIP(r), 30, time.Minute) {
		rateLimited(w)
		return
	}
	body, tooLarge := readBoundedBody(r, 16*1024)
	if tooLarge {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "export request too large"})
		return
	}
	var request indicatorExportRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := decodeStrictValue(body, &request); err != nil {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid export request"})
			return
		}
	}

	filters := r.URL.Query()
	if request.Status != "" {
		filters.Set("status", request.Status)
	}
	if request.MinScore != nil {
		filters.Set("min_score", strconv.Itoa(*request.MinScore))
	}
	if request.Confidence != "" {
		filters.Set("confidence", request.Confidence)
	}
	if request.SiteID != "" {
		filters.Set("site_id", request.SiteID)
	}
	if request.MinSensorCount != nil {
		filters.Set("min_sensor_count", strconv.Itoa(*request.MinSensorCount))
	}
	if request.SeenSince != "" {
		filters.Set("seen_since", request.SeenSince)
	}
	if request.Format != "" {
		filters.Set("format", request.Format)
	}
	format := strings.ToLower(strings.TrimSpace(filters.Get("format")))
	if format == "" {
		format = "json"
		filters.Set("format", format)
	}
	statusFilter := strings.ToLower(strings.TrimSpace(filters.Get("status")))
	if format == "nftables" && statusFilter != "approved" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nftables export requires status=approved"})
		return
	}
	filterRequest := &http.Request{URL: &url.URL{RawQuery: filters.Encode()}}
	items, decisions, err := a.filteredIndicators(filterRequest)
	if err != nil {
		status := http.StatusInternalServerError
		var validationErr *indicatorQueryError
		if errors.As(err, &validationErr) {
			status = http.StatusBadRequest
		}
		a.writeJSON(w, status, map[string]string{"error": err.Error()})
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
	if len(content) > localExportMaxBytes {
		a.writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "generated export exceeds the local size limit"})
		return
	}
	id, err := security.RandomToken(12)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "export id generation failed"})
		return
	}
	now := time.Now().UTC()
	job := localExportJob{ID: "export_" + id, Format: format, ContentType: contentType, Content: content, Checksum: security.Fingerprint(a.cfg.InstanceKey, content), CreatedAt: now, ExpiresAt: now.Add(localExportTTL)}
	a.exportMu.Lock()
	if a.exports == nil {
		a.exports = make(map[string]localExportJob)
	}
	for existingID, existing := range a.exports {
		if !existing.ExpiresAt.After(now) {
			delete(a.exports, existingID)
		}
	}
	for len(a.exports) >= localExportMaxStored {
		oldestID := ""
		var oldest time.Time
		for existingID, existing := range a.exports {
			if oldestID == "" || existing.CreatedAt.Before(oldest) {
				oldestID, oldest = existingID, existing.CreatedAt
			}
		}
		if oldestID == "" {
			break
		}
		delete(a.exports, oldestID)
	}
	a.exports[job.ID] = job
	a.exportMu.Unlock()
	a.recordAudit(r, "indicator.export.create", job.ID, "success", map[string]string{"format": format, "item_count": strconv.Itoa(len(items))})
	a.writeJSON(w, http.StatusAccepted, map[string]any{"id": job.ID, "status": "ready", "format": job.Format, "size_bytes": len(job.Content), "checksum": job.Checksum, "created_at": job.CreatedAt, "expires_at": job.ExpiresAt, "download_url": "exports/" + job.ID + "/download", "count": len(items), "synthetic_only": true})
}

func (a *App) adminExportRoute(w http.ResponseWriter, r *http.Request, path string) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 2 && len(parts) != 3 || parts[0] != "exports" || r.Method != http.MethodGet {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "export route not found"})
		return
	}
	id, err := url.PathUnescape(parts[1])
	if err != nil || id == "" || strings.Contains(id, "/") {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "export not found"})
		return
	}
	a.exportMu.Lock()
	job, ok := a.exports[id]
	if ok && !job.ExpiresAt.After(time.Now().UTC()) {
		delete(a.exports, id)
		ok = false
	}
	a.exportMu.Unlock()
	if !ok {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "export not found or expired"})
		return
	}
	if len(parts) == 2 {
		a.writeJSON(w, http.StatusOK, map[string]any{"id": job.ID, "status": "ready", "format": job.Format, "size_bytes": len(job.Content), "checksum": job.Checksum, "created_at": job.CreatedAt, "expires_at": job.ExpiresAt, "download_url": "exports/" + job.ID + "/download", "synthetic_only": true})
		return
	}
	if parts[2] != "download" {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "export route not found"})
		return
	}
	a.recordAudit(r, "indicator.export.download", job.ID, "success", map[string]string{"format": job.Format})
	w.Header().Set("Content-Type", job.ContentType)
	w.Header().Set("Content-Disposition", "attachment; filename=indicators."+indicatorExportExtension(job.Format))
	w.Header().Set("X-Content-SHA256", job.Checksum)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(job.Content))
}
