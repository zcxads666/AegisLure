package app

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
	"github.com/zcxads666/AegisLure/internal/security"
)

func TestRawRequestCapturePreservesFullRequestAndBoundedPrefixes(t *testing.T) {
	body := []byte(`{"token":"raw-secret","prompt":"reply with ok"}`)
	req := httptest.NewRequest(http.MethodPost, "https://api.example.test/v1/chat/completions?stream=false", bytes.NewReader(body))
	req.Host = "api.example.test"
	req.Header.Add("X-Repeated", "first")
	req.Header.Add("X-Repeated", "second")
	req.Header.Set("Content-Type", "application/json")
	raw := captureRawRequest(req, body, "")
	if raw == nil {
		t.Fatal("normal request did not produce a raw request envelope")
	}
	if raw.URL != req.RequestURI || raw.Route != "/v1/chat/completions" || raw.Host != "api.example.test" {
		t.Fatalf("raw request target/path/host = %#v", raw)
	}
	if got := raw.Headers["X-Repeated"]; !reflect.DeepEqual(got, []string{"first", "second"}) {
		t.Fatalf("repeated header values were lost: %#v", got)
	}
	if raw.BodyBase64 != base64.StdEncoding.EncodeToString(body) || raw.Truncated {
		t.Fatalf("normal raw body was not lossless: %#v", raw)
	}
	empty := captureRawRequest(httptest.NewRequest(http.MethodGet, "https://api.example.test/health", nil), nil, "")
	if empty == nil || empty.BodyBase64 != "" || empty.Truncated {
		t.Fatalf("empty-body request was not represented: %#v", empty)
	}

	largeBodyRequest := httptest.NewRequest(http.MethodPost, "https://api.example.test/upload", strings.NewReader(strings.Repeat("x", 1<<20+1)))
	boundedBody, bodyTruncated := readBoundedBody(largeBodyRequest, 1<<20)
	if !bodyTruncated || len(boundedBody) != 1<<20 {
		t.Fatalf("bounded body = len(%d), truncated=%t", len(boundedBody), bodyTruncated)
	}
	bodyPrefix := captureRawRequest(largeBodyRequest, boundedBody, "body_limit_exceeded")
	if !bodyPrefix.Truncated || bodyPrefix.TruncationReason != "body_limit_exceeded" || len(bodyPrefix.BodyBase64) == 0 {
		t.Fatalf("body truncation metadata missing: %#v", bodyPrefix)
	}

	headerRequest := httptest.NewRequest(http.MethodGet, "https://api.example.test/headers", nil)
	for index := 0; index < 110; index++ {
		headerRequest.Header.Add(fmt.Sprintf("X-Header-%03d", index), "header-value")
	}
	headerPrefix := captureRawRequest(headerRequest, nil, "header_limit_exceeded")
	count := 0
	for _, values := range headerPrefix.Headers {
		count += len(values)
	}
	if !headerPrefix.Truncated || headerPrefix.TruncationReason != "header_limit_exceeded" || count > 100 {
		t.Fatalf("header truncation limits not enforced: count=%d raw=%#v", count, headerPrefix)
	}
}

func TestPublicEventRawRequestAndLegacyDetailMarker(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	profile := profiles.Build(cfg)[model.ProductOllama]
	body := []byte(`{"model":"qwen3.6:35b-a3b","prompt":"raw body"}`)
	req := httptest.NewRequest(http.MethodPost, "https://ollama.example.test/api/generate?stream=false", bytes.NewReader(body))
	req.RemoteAddr = "198.51.100.42:4242"
	req.Header.Add("X-Raw-Header", "one")
	req.Header.Add("X-Raw-Header", "two")
	recorder := httptest.NewRecorder()
	a.publicHandler(profile).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("public request status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	events, err := st.Events(-1, "", "")
	if err != nil || len(events) != 1 {
		t.Fatalf("captured events = %#v, %v", events, err)
	}
	if events[0].RawRequest == nil || events[0].RawRequest.URL != req.RequestURI || events[0].RawRequest.Route != "/api/generate" || !reflect.DeepEqual(events[0].RawRequest.Headers["X-Raw-Header"], []string{"one", "two"}) || events[0].RawRequest.BodyBase64 != base64.StdEncoding.EncodeToString(body) {
		t.Fatalf("public raw request was incomplete: %#v", events[0].RawRequest)
	}

	oldID := "legacy-without-raw"
	if err := st.AppendEvent(model.Event{EventID: oldID, Product: model.ProductOllama, ProfileID: profile.ID, RouteTemplate: "ollama.unknown", SourceIP: "198.51.100.99", ObservedAt: time.Now().UTC(), Status: 200}); err != nil {
		t.Fatal(err)
	}
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	resp, detail := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events/"+oldID, nil)
	if resp.StatusCode != http.StatusOK || detail["raw_payload_available"] != false || detail["payload_view"] != "legacy_missing_raw_request" || detail["raw_request_note"] != "历史事件未记录原始请求" {
		t.Fatalf("legacy event detail = %d %#v", resp.StatusCode, detail)
	}
}

func TestAdminPaginationSearchBoundaryAndLogicalDelete(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	for index := 0; index < 21; index++ {
		if err := st.AppendEvent(model.Event{EventID: fmt.Sprintf("page-event-%02d", index), Product: model.ProductOllama, RouteTemplate: "ollama.home", SourceIP: fmt.Sprintf("198.51.100.%d", index+1), ObservedAt: time.Date(2026, 9, 1, 0, index, 0, 0, time.UTC), Score: index}); err != nil {
			t.Fatal(err)
		}
	}
	resp, pageOne := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events?page=1&page_size=10", nil)
	if resp.StatusCode != http.StatusOK || len(pageOne["events"].([]any)) != 10 || pageOne["total"].(float64) != 21 || pageOne["total_pages"].(float64) != 3 || pageOne["has_next"] != true || pageOne["page_size"].(float64) != 10 {
		t.Fatalf("page one = %d %#v", resp.StatusCode, pageOne)
	}
	resp, search := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events?page=1&q=page-event-20", nil)
	if resp.StatusCode != http.StatusOK || len(search["events"].([]any)) != 1 || search["total"].(float64) != 1 {
		t.Fatalf("search page = %d %#v", resp.StatusCode, search)
	}
	resp, _ = doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events?page=1&page_size=11", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("non-fixed page size status = %d", resp.StatusCode)
	}
	resp, lastPage := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events?page=3", nil)
	if resp.StatusCode != http.StatusOK || len(lastPage["events"].([]any)) != 1 {
		t.Fatalf("last page = %d %#v", resp.StatusCode, lastPage)
	}
	lastID := lastPage["events"].([]any)[0].(map[string]any)["event_id"].(string)
	resp, deletion := doJSON(t, admin, http.MethodDelete, cfg.AdminPath+"admin/api/v1/events/"+lastID, nil)
	if resp.StatusCode != http.StatusOK || deletion["logical"] != true || deletion["deleted_events"].(float64) != 1 {
		t.Fatalf("event logical delete = %d %#v", resp.StatusCode, deletion)
	}
	resp, afterDelete := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events?page=3", nil)
	if resp.StatusCode != http.StatusOK || len(afterDelete["events"].([]any)) != 0 || afterDelete["total"].(float64) != 20 || afterDelete["total_pages"].(float64) != 2 {
		t.Fatalf("deleted last page = %d %#v", resp.StatusCode, afterDelete)
	}
	resp, pageTwo := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events?page=2", nil)
	if resp.StatusCode != http.StatusOK || len(pageTwo["events"].([]any)) != 10 {
		t.Fatalf("fallback page = %d %#v", resp.StatusCode, pageTwo)
	}

	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var eventRows, tombstones int
	if err := db.QueryRow("SELECT count(*) FROM events").Scan(&eventRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("SELECT count(*) FROM event_tombstones WHERE event_id = ?", lastID).Scan(&tombstones); err != nil {
		t.Fatal(err)
	}
	if eventRows != 21 || tombstones != 1 {
		t.Fatalf("logical delete changed authoritative rows: events=%d tombstones=%d", eventRows, tombstones)
	}
	if err := st.VerifyAuditChain(); err != nil {
		t.Fatalf("delete audit chain invalid: %v", err)
	}
	if restored, err := st.RestoreEventIDs([]string{lastID}); err != nil || restored != 1 {
		t.Fatalf("restore event = %d, %v", restored, err)
	}
	resp, restoredPage := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events?page=3", nil)
	if resp.StatusCode != http.StatusOK || len(restoredPage["events"].([]any)) != 1 || restoredPage["total"].(float64) != 21 {
		t.Fatalf("restored last page = %d %#v", resp.StatusCode, restoredPage)
	}
}

func TestAdminDerivedDeletesTombstoneUnderlyingEventsAndKeepAuditChain(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	base := time.Date(2026, 9, 2, 1, 0, 0, 0, time.UTC)
	for _, event := range []model.Event{
		{EventID: "derived-invocation-1", Product: model.ProductOllama, RouteTemplate: "ollama.generate", SourceIP: "203.0.113.80", SessionID: "inv-session-a", InvocationID: "inv-derived", InvocationAttempted: true, InvocationLevel: model.L2, ExecutionOutcome: "synthetic_accepted", ObservedAt: base, Score: 45},
		{EventID: "derived-invocation-2", Product: model.ProductVLLM, RouteTemplate: "openai.chat.completions", SourceIP: "203.0.113.80", SessionID: "inv-session-b", InvocationID: "inv-derived", InvocationAttempted: true, InvocationLevel: model.L1, ExecutionOutcome: "rejected_before_dispatch", RejectionReason: "missing_authentication", ObservedAt: base.Add(time.Minute), Score: 30},
		{EventID: "derived-chain", Product: model.ProductSGLang, RouteTemplate: "sglang.generate", SourceIP: "203.0.113.81", SessionID: "chain-session", ObservedAt: base.Add(2 * time.Minute), Score: 50},
		{EventID: "derived-indicator", Product: model.ProductLocalAI, RouteTemplate: "localai.home", SourceIP: "203.0.113.82", SessionID: "indicator-session", ObservedAt: base.Add(3 * time.Minute), Score: 70},
	} {
		if err := st.AppendEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	if resp, body := doJSON(t, admin, http.MethodDelete, cfg.AdminPath+"admin/api/v1/invocations/inv-derived", nil); resp.StatusCode != http.StatusOK || body["deleted_events"].(float64) != 2 {
		t.Fatalf("invocation delete = %d %#v", resp.StatusCode, body)
	}
	chainResp, chains := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/interaction-chains", nil)
	if chainResp.StatusCode != http.StatusOK || len(chains["chains"].([]any)) != 2 {
		t.Fatalf("chains after invocation delete = %d %#v", chainResp.StatusCode, chains)
	}
	var chainID string
	for _, raw := range chains["chains"].([]any) {
		chain := raw.(map[string]any)
		if chain["source_ip"] == "203.0.113.81" {
			chainID = chain["id"].(string)
		}
	}
	if chainID == "" {
		t.Fatalf("chain for derived delete was not returned: %#v", chains)
	}
	if resp, body := doJSON(t, admin, http.MethodDelete, cfg.AdminPath+"admin/api/v1/interaction-chains/"+chainID, nil); resp.StatusCode != http.StatusOK || body["deleted_events"].(float64) != 1 {
		t.Fatalf("chain delete = %d %#v", resp.StatusCode, body)
	}
	indicatorResp, indicators := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators?q=203.0.113.82", nil)
	if indicatorResp.StatusCode != http.StatusOK || len(indicators["items"].([]any)) != 1 {
		t.Fatalf("indicator search before delete = %d %#v", indicatorResp.StatusCode, indicators)
	}
	indicatorID := indicators["items"].([]any)[0].(map[string]any)["id"].(string)
	if resp, body := doJSON(t, admin, http.MethodDelete, cfg.AdminPath+"admin/api/v1/indicators/"+indicatorID, nil); resp.StatusCode != http.StatusOK || body["deleted_events"].(float64) != 1 {
		t.Fatalf("indicator delete = %d %#v", resp.StatusCode, body)
	}
	active, err := st.Events(-1, "", "")
	if err != nil || len(active) != 0 {
		t.Fatalf("derived deletes left active events: %#v, %v", active, err)
	}
	db, err := sql.Open("sqlite", st.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var eventRows int
	if err := db.QueryRow("SELECT count(*) FROM events").Scan(&eventRows); err != nil {
		t.Fatal(err)
	}
	if eventRows != 4 {
		t.Fatalf("derived delete physically removed event rows: %d", eventRows)
	}
	if err := st.VerifyAuditChain(); err != nil {
		t.Fatalf("derived delete audit chain invalid: %v", err)
	}
	entries, err := st.AuditEntries(20)
	if err != nil {
		t.Fatal(err)
	}
	seenActions := map[string]bool{}
	for _, entry := range entries {
		seenActions[entry.Action] = true
	}
	for _, action := range []string{"invocation.delete", "interaction-chain.delete", "indicator.delete"} {
		if !seenActions[action] {
			t.Fatalf("audit action %q missing: %#v", action, entries)
		}
	}
}

func TestInteractionChainsAggregateSameIPByShanghaiDay(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	dayBeforeMidnight := time.Date(2026, 9, 1, 15, 59, 0, 0, time.UTC)
	dayAfterMidnight := time.Date(2026, 9, 1, 16, 1, 0, 0, time.UTC)
	events := []model.Event{
		{EventID: "same-day-ollama", Product: model.ProductOllama, SourceIP: "203.0.113.77", SessionID: "session-a", ObservedAt: dayBeforeMidnight.Add(-30 * time.Minute), Score: 10},
		{EventID: "same-day-vllm", Product: model.ProductVLLM, SourceIP: "203.0.113.77", SessionID: "session-b", ObservedAt: dayBeforeMidnight, Score: 45},
		{EventID: "next-day-sglang", Product: model.ProductSGLang, SourceIP: "203.0.113.77", SessionID: "session-c", ObservedAt: dayAfterMidnight, Score: 70},
	}
	config := model.DefaultInteractionChainConfig()
	views := a.buildInteractionChainViews(events, config)
	if len(views) != 2 {
		t.Fatalf("same IP day aggregation produced %d chains: %#v", len(views), views)
	}
	if views[0].CalendarDay != "2026-09-02" || views[0].SourceIP != "203.0.113.77" || views[0].SessionCount != 1 || !reflect.DeepEqual(views[0].Products, []string{model.ProductSGLang}) {
		t.Fatalf("post-midnight chain metadata = %#v", views[0])
	}
	if views[1].CalendarDay != "2026-09-01" || views[1].SessionCount != 2 || !reflect.DeepEqual(views[1].Products, []string{model.ProductOllama, model.ProductVLLM}) || views[1].EventCount != 2 {
		t.Fatalf("same-day cross-session/product chain metadata = %#v", views[1])
	}
	second := a.buildInteractionChainViews(events, config)
	if len(second) != len(views) || second[0].ID != views[0].ID || second[1].ID != views[1].ID {
		t.Fatalf("chain IDs are not stable: first=%#v second=%#v", views, second)
	}
	if config.Mode != model.InteractionChainBySourceIPDay || st.InteractionChainConfig().Mode != model.InteractionChainBySourceIPDay {
		t.Fatalf("default chain mode changed: config=%#v store=%#v", config, st.InteractionChainConfig())
	}
}

func addPlanHoneyToken(t *testing.T, st interface{ AddToken(model.HoneyToken) error }, cfgKey, id, raw string) {
	t.Helper()
	if err := st.AddToken(model.HoneyToken{ID: id, HoneyUserID: "plan-user-" + id, Hash: security.Fingerprint(cfgKey, raw), PrefixHint: raw[:minPlanInt(8, len(raw))], UnlimitedQuota: true, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
}

func minPlanInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func publicPlanJSON(t *testing.T, a *App, profile profiles.Profile, method, path string, value any, headers map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	return doJSONWithHeaders(t, client, method, path, value, headers)
}

func publicPlanRaw(t *testing.T, a *App, profile profiles.Profile, method, path, body string, headers map[string]string) (int, []byte) {
	t.Helper()
	client := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	resp := client.doWithHeaders(t, method, path, strings.NewReader(body), "application/json", headers)
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, data
}

func latestPlanInvocation(t *testing.T, st interface {
	Events(int, string, string) ([]model.Event, error)
}) model.Event {
	t.Helper()
	events, err := st.Events(-1, "", "")
	if err != nil || len(events) == 0 {
		t.Fatalf("no invocation event: %v", err)
	}
	if !events[0].InvocationAttempted || events[0].InvocationID == "" {
		t.Fatalf("latest event was not an invocation attempt: %#v", events[0])
	}
	return events[0]
}

func assertPlanInvocation(t *testing.T, event model.Event, reason string, accepted bool) {
	t.Helper()
	if event.Score < 20 || !containsPlanString(event.ReasonCodes, "model_call_attempted") {
		t.Fatalf("model call risk evidence missing: %#v", event)
	}
	if reason != "" && event.RejectionReason != reason {
		t.Fatalf("rejection reason = %q, want %q; event=%#v", event.RejectionReason, reason, event)
	}
	if accepted && event.ExecutionOutcome != "synthetic_accepted" {
		t.Fatalf("accepted invocation outcome = %q", event.ExecutionOutcome)
	}
	if !accepted && event.ExecutionOutcome != "rejected_before_dispatch" {
		t.Fatalf("rejected invocation outcome = %q", event.ExecutionOutcome)
	}
}

func containsPlanString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestModelInvocationAuthenticationMatrixAndRiskReasons(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	openModel := "Qwen/Qwen3.6-35B-A3B"
	newAPIKey := "new-api-plan-key"
	vllmKey := "vllm-plan-key"
	sglangKey := "sglang-plan-key"
	localAIKey := "localai-plan-key"
	if err := st.CreateHoneyUser(model.HoneyUser{ID: "plan-user-plan-newapi", VirtualQuota: 100000}); err != nil {
		t.Fatal(err)
	}
	addPlanHoneyToken(t, st, cfg.InstanceKey, "plan-newapi", newAPIKey)
	addPlanHoneyToken(t, st, cfg.InstanceKey, "plan-vllm", vllmKey)
	addPlanHoneyToken(t, st, cfg.InstanceKey, "plan-sglang", sglangKey)
	addPlanHoneyToken(t, st, cfg.InstanceKey, "plan-localai", localAIKey)

	newAPIProfile := profiles.Build(cfg)[model.ProductNewAPI]
	if resp, _ := publicPlanJSON(t, a, newAPIProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "gpt-5.6-sol", "messages": []any{}}, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("New API missing-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "missing_authentication", false)
	if resp, _ := publicPlanJSON(t, a, newAPIProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "gpt-5.6-sol", "messages": []any{}}, map[string]string{"Authorization": "Bearer wrong-new-api-key"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("New API wrong-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "invalid_authentication", false)
	if resp, _ := publicPlanJSON(t, a, newAPIProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "gpt-5.6-sol", "messages": []any{}}, map[string]string{"Authorization": "Bearer " + newAPIKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("New API correct-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "", true)
	if resp, _ := publicPlanJSON(t, a, newAPIProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "does-not-exist", "messages": []any{}}, map[string]string{"Authorization": "Bearer " + newAPIKey}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("New API unknown-model status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "model_not_found", false)
	if status, _ := publicPlanRaw(t, a, newAPIProfile, http.MethodPost, "/v1/chat/completions", "{", map[string]string{"Authorization": "Bearer " + newAPIKey}); status != http.StatusBadRequest {
		t.Fatalf("New API invalid-request status = %d", status)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "invalid_request", false)

	cfg.Scenario[model.ProductVLLM] = "no-key"
	vllmNoKey := profiles.Build(cfg)[model.ProductVLLM]
	if resp, _ := publicPlanJSON(t, a, vllmNoKey, http.MethodPost, "/v1/chat/completions", map[string]any{"model": openModel, "messages": []any{map[string]string{"role": "user", "content": "ok"}}}, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("vLLM no-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "", true)
	cfg.Scenario[model.ProductVLLM] = "api-key"
	vllmKeyProfile := profiles.Build(cfg)[model.ProductVLLM]
	if resp, _ := publicPlanJSON(t, a, vllmKeyProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": openModel, "messages": []any{map[string]string{"role": "user", "content": "ok"}}}, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("vLLM missing-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "missing_authentication", false)
	if resp, _ := publicPlanJSON(t, a, vllmKeyProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": openModel, "messages": []any{map[string]string{"role": "user", "content": "ok"}}}, map[string]string{"Authorization": "Bearer wrong-vllm-key"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("vLLM wrong-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "invalid_authentication", false)
	if resp, _ := publicPlanJSON(t, a, vllmKeyProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": openModel, "messages": []any{map[string]string{"role": "user", "content": "ok"}}}, map[string]string{"Authorization": "Bearer " + vllmKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("vLLM correct-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "", true)
	if resp, _ := publicPlanJSON(t, a, vllmKeyProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "does-not-exist", "messages": []any{map[string]string{"role": "user", "content": "ok"}}}, map[string]string{"Authorization": "Bearer " + vllmKey}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("vLLM unknown-model status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "model_not_found", false)

	ollamaProfile := profiles.Build(cfg)[model.ProductOllama]
	if resp, _ := publicPlanJSON(t, a, ollamaProfile, http.MethodPost, "/api/generate", map[string]any{"model": "qwen3.6:35b-a3b", "prompt": "ok", "stream": false}, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("Ollama no-key status = %d", resp.StatusCode)
	}
	ollamaAccepted := latestPlanInvocation(t, st)
	if ollamaAccepted.AuthOutcome != "not_required" {
		t.Fatalf("Ollama no-key auth outcome = %q", ollamaAccepted.AuthOutcome)
	}
	assertPlanInvocation(t, ollamaAccepted, "", true)
	if resp, _ := publicPlanJSON(t, a, ollamaProfile, http.MethodPost, "/api/generate", map[string]any{"model": "does-not-exist", "prompt": "ok", "stream": false}, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("Ollama unknown-model status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "model_not_found", false)
	if status, _ := publicPlanRaw(t, a, ollamaProfile, http.MethodPost, "/api/generate", "{", nil); status != http.StatusBadRequest {
		t.Fatalf("Ollama invalid-request status = %d", status)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "invalid_request", false)

	cfg.Scenario[model.ProductSGLang] = "no-key"
	sglangNoKey := profiles.Build(cfg)[model.ProductSGLang]
	if resp, _ := publicPlanJSON(t, a, sglangNoKey, http.MethodPost, "/generate", map[string]any{"model": openModel}, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("SGLang no-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "", true)
	cfg.Scenario[model.ProductSGLang] = "api-key"
	sglangKeyProfile := profiles.Build(cfg)[model.ProductSGLang]
	if resp, _ := publicPlanJSON(t, a, sglangKeyProfile, http.MethodPost, "/generate", map[string]any{"model": openModel}, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SGLang missing-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "missing_authentication", false)
	if resp, _ := publicPlanJSON(t, a, sglangKeyProfile, http.MethodPost, "/generate", map[string]any{"model": openModel}, map[string]string{"Authorization": "Bearer wrong-sglang-key"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("SGLang wrong-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "invalid_authentication", false)
	if resp, _ := publicPlanJSON(t, a, sglangKeyProfile, http.MethodPost, "/generate", map[string]any{"model": openModel}, map[string]string{"Authorization": "Bearer " + sglangKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("SGLang correct-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "", true)
	if resp, _ := publicPlanJSON(t, a, sglangKeyProfile, http.MethodPost, "/generate", map[string]any{"model": "does-not-exist"}, map[string]string{"Authorization": "Bearer " + sglangKey}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("SGLang unknown-model status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "model_not_found", false)
	if status, _ := publicPlanRaw(t, a, sglangKeyProfile, http.MethodPost, "/generate", "{", map[string]string{"Authorization": "Bearer " + sglangKey}); status != http.StatusBadRequest {
		t.Fatalf("SGLang invalid-request status = %d", status)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "invalid_request", false)

	cfg.Scenario[model.ProductLocalAI] = "legacy-unauth"
	localAINoAuth := profiles.Build(cfg)[model.ProductLocalAI]
	if resp, _ := publicPlanJSON(t, a, localAINoAuth, http.MethodPost, "/v1/chat/completions", map[string]any{"model": openModel, "messages": []any{}}, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("LocalAI no-auth status = %d", resp.StatusCode)
	}
	localAINoAuthEvent := latestPlanInvocation(t, st)
	if localAINoAuthEvent.AuthOutcome != "not_required" {
		t.Fatalf("LocalAI no-auth auth outcome = %q", localAINoAuthEvent.AuthOutcome)
	}
	assertPlanInvocation(t, localAINoAuthEvent, "", true)
	cfg.Scenario[model.ProductLocalAI] = "current-rbac"
	localAIProfile := profiles.Build(cfg)[model.ProductLocalAI]
	if resp, _ := publicPlanJSON(t, a, localAIProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": openModel, "messages": []any{}}, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("LocalAI missing-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "missing_authentication", false)
	if resp, _ := publicPlanJSON(t, a, localAIProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": openModel, "messages": []any{}}, map[string]string{"Authorization": "Bearer wrong-localai-key"}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("LocalAI wrong-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "invalid_authentication", false)
	if resp, _ := publicPlanJSON(t, a, localAIProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": openModel, "messages": []any{}}, map[string]string{"Authorization": "Bearer " + localAIKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("LocalAI correct-key status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "", true)
	if resp, _ := publicPlanJSON(t, a, localAIProfile, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "does-not-exist", "messages": []any{}}, map[string]string{"Authorization": "Bearer " + localAIKey}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("LocalAI unknown-model status = %d", resp.StatusCode)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "model_not_found", false)
	if status, _ := publicPlanRaw(t, a, localAIProfile, http.MethodPost, "/v1/chat/completions", "{", map[string]string{"Authorization": "Bearer " + localAIKey}); status != http.StatusBadRequest {
		t.Fatalf("LocalAI invalid-request status = %d", status)
	}
	assertPlanInvocation(t, latestPlanInvocation(t, st), "invalid_request", false)
}
