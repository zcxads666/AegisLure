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
	}
	for _, test := range cases {
		if got := Route(test.product, test.method, test.path); got != test.want {
			t.Errorf("Route(%q, %q, %q) = %q, want %q", test.product, test.method, test.path, got, test.want)
		}
	}
}
