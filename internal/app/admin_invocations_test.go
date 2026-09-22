package app

import (
	"net/http"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
)

func TestAdminInvocationsFilterByHoneypot(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()

	base := time.Date(2026, time.September, 22, 8, 0, 0, 0, time.UTC)
	for _, event := range []model.Event{
		{EventID: "invoke-ollama", InvocationID: "inv-ollama", Product: model.ProductOllama, SourceIP: "192.0.2.10", ObservedAt: base},
		{EventID: "invoke-sub2api", InvocationID: "inv-sub2api", Product: model.ProductSub2API, SourceIP: "192.0.2.11", ObservedAt: base.Add(time.Minute)},
	} {
		if err := st.AppendEvent(event); err != nil {
			t.Fatal(err)
		}
	}

	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	resp, body := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/invocations?product="+model.ProductOllama, nil)
	if resp.StatusCode != http.StatusOK || body["product"] != model.ProductOllama {
		t.Fatalf("invocation honeypot filter = %d %#v", resp.StatusCode, body)
	}
	items, ok := body["invocations"].([]any)
	if !ok || len(items) != 1 || items[0].(map[string]any)["product"] != model.ProductOllama {
		t.Fatalf("filtered invocations = %#v", body["invocations"])
	}
}
