package profiles

import (
	"testing"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestVulnerabilitySurfaceRoutes(t *testing.T) {
	cases := []struct {
		product string
		method  string
		path    string
		want    string
	}{
		{model.ProductNewAPI, "GET", "/api/user/", "newapi.user.list"},
		{model.ProductNewAPI, "GET", "/api/video/task-1", "newapi.video.proxy"},
		{model.ProductNewAPI, "POST", "/api/stripe/webhook", "newapi.payment.webhook"},
		{model.ProductNewAPI, "GET", "/api/user/bind", "newapi.user.binding"},
		{model.ProductNewAPI, "GET", "/api/user/oauth/bindings", "newapi.user.oauth-bindings"},
		{model.ProductSGLang, "POST", "/dumper", "sglang.dumper"},
		{model.ProductSub2API, "GET", "/api/v1/settings/public", "sub2api.settings.public"},
		{model.ProductSub2API, "GET", "/api/v1/model-plaza", "sub2api.model.plaza"},
		{model.ProductSub2API, "POST", "/api/v1/auth/revoke-all-sessions", "sub2api.auth.revoke_sessions"},
		{model.ProductSub2API, "GET", "/api/v1/auth/oauth/google/bind/start", "sub2api.auth.oauth"},
		{model.ProductSub2API, "POST", "/api/v1/auth/oauth/pending/create-account", "sub2api.auth.oauth"},
		{model.ProductSub2API, "POST", "/v1/messages/count_tokens", "sub2api.gateway.count_tokens"},
		{model.ProductSub2API, "GET", "/v1/sub2api/billing", "sub2api.gateway.billing"},
		{model.ProductSub2API, "POST", "/v1/alpha/search", "sub2api.gateway.alpha_search"},
		{model.ProductSub2API, "GET", "/backend-api/codex/models", "sub2api.gateway.codex.models"},
		{model.ProductSub2API, "POST", "/backend-api/codex/responses", "sub2api.gateway.responses"},
		{model.ProductSub2API, "POST", "/backend-api/codex/responses/compact", "sub2api.gateway.responses"},
		{model.ProductSub2API, "POST", "/backend-api/codex/alpha/search", "sub2api.gateway.alpha_search"},
		{model.ProductSub2API, "GET", "/api/v1/usage/dashboard/snapshot-v2", "sub2api.usage.dashboard.snapshot"},
		{model.ProductSub2API, "GET", "/home", "sub2api.spa"},
		{model.ProductSub2API, "GET", "/email-verify", "sub2api.spa"},
		{model.ProductSub2API, "GET", "/auth/oauth/callback", "sub2api.spa"},
		{model.ProductSub2API, "GET", "/available-channels", "sub2api.spa"},
		{model.ProductSub2API, "GET", "/admin/risk-control", "sub2api.spa"},
		{model.ProductSub2API, "GET", "/legal/privacy-policy", "sub2api.spa"},
		{model.ProductSub2API, "GET", "/custom/landing", "sub2api.spa"},
		{model.ProductSub2API, "GET", "/logo.svg", "sub2api.logo"},
	}
	for _, test := range cases {
		if got := Route(test.product, test.method, test.path); got != test.want {
			t.Errorf("Route(%q, %q, %q) = %q, want %q", test.product, test.method, test.path, got, test.want)
		}
	}
}
