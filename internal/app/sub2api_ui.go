package app

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/zcxads666/AegisLure/internal/profiles"
)

// The Sub2API public application is built directly from the official
// /Volumes/1/code/sub2api/frontend checkout. The generated files are kept in
// the repository so the honeypot binary remains self-contained; the build
// script records the exact upstream commit in SOURCE.txt.
//
//go:embed ui/sub2api-dist
var sub2APIDist embed.FS

var sub2APIStaticFS = func() fs.FS {
	root, err := fs.Sub(sub2APIDist, "ui/sub2api-dist")
	if err != nil {
		panic(err)
	}
	return root
}()

func (a *App) writeSub2APIIndex(w *captureWriter, _ *http.Request, _ profiles.Profile) {
	index, err := fs.ReadFile(sub2APIStaticFS, "index.html")
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false,
			"message": "frontend unavailable",
		})
		return
	}
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"base-uri 'none'",
		"connect-src 'self'",
		"style-src 'self' 'unsafe-inline'",
		"script-src 'self'",
		"img-src 'self' data: blob:",
		"font-src 'self' data:",
		"worker-src 'self' blob:",
		"manifest-src 'self'",
		"media-src 'self' blob:",
		"form-action 'self'",
		"frame-ancestors 'none'",
		"object-src 'none'",
	}, "; "))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(index)
}

func (a *App) writeSub2APIAsset(w *captureWriter, r *http.Request) {
	prefix := "/assets/"
	root := "assets"
	if strings.HasPrefix(r.URL.Path, "/static/") {
		prefix = "/static/"
		root = "static"
	}
	name := strings.TrimPrefix(r.URL.Path, prefix)
	if name == r.URL.Path || name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, "\\\r\n") {
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": "asset not found"})
		return
	}
	name = path.Clean(name)
	if name == "." || strings.HasPrefix(name, "../") {
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": "asset not found"})
		return
	}
	content, err := fs.ReadFile(sub2APIStaticFS, path.Join(root, name))
	if err != nil {
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": "asset not found"})
		return
	}
	setSecurityHeaders(w)
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (a *App) writeSub2APILogo(w *captureWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name != "logo.svg" && name != "logo.png" && name != "favicon.ico" {
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": "asset not found"})
		return
	}
	content, err := fs.ReadFile(sub2APIStaticFS, name)
	if err != nil {
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": "asset not found"})
		return
	}
	setSecurityHeaders(w)
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}
