package app

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/zcxads666/AegisLure/internal/security"
)

// These assets are intentionally embedded so the admin console keeps the
// standalone, single-binary deployment model of the service.
//
//go:embed ui/index.html
var adminIndexHTML string

//go:embed ui/app.js
var adminAppJS []byte

//go:embed ui/styles.css
var adminStylesCSS []byte

//go:embed ui/vendor/htm-preact.module.js
var adminRuntimeJS []byte

//go:embed ui/vendor/THIRD_PARTY_NOTICES.txt
var adminThirdPartyNotices []byte

func (a *App) adminPage(w http.ResponseWriter) {
	nonce := security.MustRandomToken(18)
	body := strings.ReplaceAll(adminIndexHTML, "{{ADMIN_BASE}}", htmlEscape(a.cfg.AdminPath))
	body = strings.ReplaceAll(body, "{{NONCE}}", htmlEscape(nonce))
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; connect-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; script-src 'nonce-"+nonce+"' 'self'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func isAdminUIPath(path string) bool {
	switch strings.Trim(path, "/") {
	case "", "setup", "login", "dashboard", "observations", "invocations", "chains", "indicators", "instances", "packs", "settings":
		return true
	default:
		return false
	}
}

func (a *App) writeAdminAsset(w http.ResponseWriter, path string) {
	var content []byte
	contentType := "application/octet-stream"
	switch strings.TrimPrefix(path, "/") {
	case "assets/app.js":
		content, contentType = adminAppJS, "text/javascript; charset=utf-8"
	case "assets/styles.css":
		content, contentType = adminStylesCSS, "text/css; charset=utf-8"
	case "assets/htm-preact.module.js":
		content, contentType = adminRuntimeJS, "text/javascript; charset=utf-8"
	case "assets/THIRD_PARTY_NOTICES.txt":
		content, contentType = adminThirdPartyNotices, "text/plain; charset=utf-8"
	default:
		silentClose(w)
		return
	}
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", contentType)
	// The UI assets are embedded in the binary and can change between local
	// restarts. Do not let a stale app.js survive a server upgrade and keep
	// executing an older route renderer in an already-open admin console.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}
