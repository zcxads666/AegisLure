package app

import (
	"embed"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// The public New API surface is built from the real React application in the
// separately maintained /Volumes/1/code/newapi checkout. The checked-in
// artifact keeps the standalone binary and container image self-contained;
// scripts/build-newapi-web.sh documents and reproduces the source-to-artifact
// sync without importing the upstream server or its data plane.
//
//go:embed ui/newapi-dist
var newAPIDist embed.FS

var newAPIStaticFS = func() fs.FS {
	root, err := fs.Sub(newAPIDist, "ui/newapi-dist")
	if err != nil {
		panic(err)
	}
	return root
}()

func (a *App) writeNewAPIIndex(w *captureWriter, status int) {
	index, err := fs.ReadFile(newAPIStaticFS, "index.html")
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
	// The copied New API build has no inline scripts. Same-origin assets and
	// API calls are sufficient, while remote frames, plugins and connections
	// remain unavailable to the public tenant.
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
	w.WriteHeader(status)
	_, _ = w.Write(index)
}

func (a *App) writeNewAPIAsset(w *captureWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/static/")
	if name == r.URL.Path || name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, "\\\r\n") {
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": "asset not found"})
		return
	}
	name = path.Clean(name)
	if name == "." || strings.HasPrefix(name, "../") {
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": "asset not found"})
		return
	}
	content, err := fs.ReadFile(newAPIStaticFS, path.Join("static", name))
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

func (a *App) writeNewAPILogo(w *captureWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name != "logo.png" && name != "favicon.ico" {
		a.writeJSON(w, http.StatusNotFound, map[string]any{"error": "asset not found"})
		return
	}
	content, err := fs.ReadFile(newAPIStaticFS, name)
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

func (a *App) writeNewAPINotFound(w *captureWriter) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = fmt.Fprint(w, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>New API</title></head><body><h1>404</h1></body></html>")
}
