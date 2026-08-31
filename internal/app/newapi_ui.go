package app

import (
	_ "embed"
	"strings"

	"github.com/zcxads666/AegisLure/internal/security"
)

// newAPIUI is a small, self-contained public shell. It intentionally does not
// embed the upstream production bundle: the honey tenant needs the same
// interaction language while keeping payment, channel, relay and system
// administration surfaces out of the artifact.
//
//go:embed ui/newapi.html
var newAPIUI string

func (a *App) writeNewAPIPage(w *captureWriter, status int, route string) {
	nonce, err := security.RandomToken(18)
	if err != nil {
		nonce = security.MustRandomToken(18)
	}
	body := strings.NewReplacer(
		"{{NONCE}}", nonce,
		"{{PAGE_ROUTE}}", htmlEscape(route),
	).Replace(newAPIUI)
	a.writeHTMLWithNonce(w, status, "New API", body, nonce)
}
