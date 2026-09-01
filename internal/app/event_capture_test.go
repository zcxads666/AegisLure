package app

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
)

func TestNewAPIUserListCanaryReuseBuildsDetectionChain(t *testing.T) {
	a, cfg, st := newTestApp(t, false)
	defer st.Close()
	public := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductNewAPI]), cookies: map[string]string{}}
	if resp, _ := doJSON(t, public, http.MethodPost, "/api/user/register", map[string]string{"username": "list-chain-user", "password": "a-longer-safe-password"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("register status = %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, public, http.MethodPost, "/api/user/login", map[string]string{"username": "list-chain-user", "password": "a-longer-safe-password"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, public, http.MethodPost, "/api/user/checkin", map[string]any{}); resp.StatusCode != http.StatusOK {
		t.Fatalf("checkin status = %d", resp.StatusCode)
	}
	resp, listed := doJSON(t, public, http.MethodGet, "/api/user/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("user list status = %d, body = %#v", resp.StatusCode, listed)
	}
	data, ok := listed["data"].(map[string]any)
	if !ok {
		t.Fatalf("user list data = %#v", listed["data"])
	}
	items, ok := data["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("user list items = %#v", data["items"])
	}
	entry, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("user list entry = %#v", items[0])
	}
	key, ok := entry["access_token"].(string)
	if !ok || !strings.HasPrefix(key, "sk-root-") {
		t.Fatalf("user list canary key = %#v", entry["access_token"])
	}
	resp, _ = doRawJSON(t, public, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "gpt-5.6-sol", "messages": []map[string]string{{"role": "user", "content": "hello"}}}, map[string]string{"Authorization": "Bearer " + key})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("canary invoke status = %d", resp.StatusCode)
	}
	events, err := st.Events(20, model.ProductNewAPI, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.EventType == "newapi.honey_key.reused" && containsString(event.MatchedRuleIDs, "NEWAPI_USER_LIST_TOKEN_LEAK_V1") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("user-list leak chain was not detected; events=%s", fmt.Sprint(events))
	}
}

func TestEventCapturesBoundedQueryAndOriginClass(t *testing.T) {
	a, cfg, st := newTestApp(t, false)
	defer st.Close()
	public := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductOllama]), cookies: map[string]string{}}
	resp, _ := doRawJSON(t, public, http.MethodGet, "/api/tags?search=%25", nil, map[string]string{"Origin": "https://scanner.example"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public request status = %d", resp.StatusCode)
	}
	events, err := st.Events(10, model.ProductOllama, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("event count = %d, events = %#v", len(events), events)
	}
	if events[0].QueryPreview != "search=%25" || events[0].OriginClass != "cross_site" {
		t.Fatalf("request context was not captured safely: %#v", events[0])
	}
}
