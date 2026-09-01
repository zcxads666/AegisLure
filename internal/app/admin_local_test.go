package app

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/profiles"
)

func TestLocalAdminDetailRoutesAndInstancePatch(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/change-password", map[string]string{"current_password": "correct horse battery staple", "new_password": "another-password", "confirm_password": "another-password"}); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("change-password route should be unavailable, status = %d", resp.StatusCode)
	}

	public := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductOllama]), cookies: map[string]string{}}
	resp, _ := doJSON(t, public, http.MethodGet, "/api/tags", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public event status = %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, public, http.MethodPost, "/api/generate", map[string]any{"model": "qwen3.6:35b-a3b", "prompt": "hello", "stream": false})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public invocation status = %d", resp.StatusCode)
	}

	resp, events := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events?limit=20", nil)
	if resp.StatusCode != http.StatusOK || len(events["events"].([]any)) < 2 {
		t.Fatalf("admin events status = %d %#v", resp.StatusCode, events)
	}
	eventID := events["events"].([]any)[0].(map[string]any)["event_id"].(string)
	resp, eventDetail := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/events/"+eventID, nil)
	if resp.StatusCode != http.StatusOK || eventDetail["event"] == nil || eventDetail["raw_payload_available"] != false {
		t.Fatalf("event detail status = %d %#v", resp.StatusCode, eventDetail)
	}

	resp, sessions := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/sessions?limit=20", nil)
	if resp.StatusCode != http.StatusOK || len(sessions["sessions"].([]any)) == 0 {
		t.Fatalf("admin sessions status = %d %#v", resp.StatusCode, sessions)
	}
	sessionID := sessions["sessions"].([]any)[0].(map[string]any)["id"].(string)
	resp, sessionDetail := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/sessions/"+sessionID, nil)
	if resp.StatusCode != http.StatusOK || sessionDetail["session"] == nil || len(sessionDetail["events"].([]any)) == 0 {
		t.Fatalf("session detail status = %d %#v", resp.StatusCode, sessionDetail)
	}

	resp, invocations := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/invocations?limit=20", nil)
	if resp.StatusCode != http.StatusOK || len(invocations["invocations"].([]any)) == 0 {
		t.Fatalf("admin invocations status = %d %#v", resp.StatusCode, invocations)
	}
	invocationID := invocations["invocations"].([]any)[0].(map[string]any)["invocation_id"].(string)
	resp, invocationDetail := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/invocations/"+invocationID, nil)
	if resp.StatusCode != http.StatusOK || invocationDetail["event_count"] == nil || invocationDetail["real_inference"] != false {
		t.Fatalf("invocation detail status = %d %#v", resp.StatusCode, invocationDetail)
	}

	resp, chains := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/interaction-chains?limit=20", nil)
	if resp.StatusCode != http.StatusOK || len(chains["chains"].([]any)) == 0 {
		t.Fatalf("admin chains status = %d %#v", resp.StatusCode, chains)
	}
	chainID := chains["chains"].([]any)[0].(map[string]any)["id"].(string)
	resp, chainDetail := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/interaction-chains/"+chainID, nil)
	if resp.StatusCode != http.StatusOK || chainDetail["chain"] == nil {
		t.Fatalf("chain detail status = %d %#v", resp.StatusCode, chainDetail)
	}

	resp, instance := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/instances/inst_ollama", nil)
	if resp.StatusCode != http.StatusOK || instance["instance"] == nil {
		t.Fatalf("instance detail status = %d %#v", resp.StatusCode, instance)
	}
	resp, compatibility := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/instances/ollama/compatibility", nil)
	if resp.StatusCode != http.StatusOK || compatibility["routes"] == nil || compatibility["synthetic_only"] != true {
		t.Fatalf("instance compatibility status = %d %#v", resp.StatusCode, compatibility)
	}
	resp, patched := doJSON(t, admin, http.MethodPatch, cfg.AdminPath+"admin/api/v1/instances/ollama", map[string]string{"scenario": "custom-safe"})
	if resp.StatusCode != http.StatusOK || patched["instance"] == nil {
		t.Fatalf("instance patch status = %d %#v", resp.StatusCode, patched)
	}
	resp, createdInstance := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/instances", map[string]any{"product": model.ProductOllama, "enabled": false, "scenario": "custom-safe"})
	if resp.StatusCode != http.StatusOK || createdInstance["instance"] == nil {
		t.Fatalf("instance create status = %d %#v", resp.StatusCode, createdInstance)
	}

	resp, actor := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/actors/192.0.2.1", nil)
	if resp.StatusCode != http.StatusOK || actor["indicator"] == nil {
		t.Fatalf("actor detail status = %d %#v", resp.StatusCode, actor)
	}
	resp, policy := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/identity-policies/discord:validate", nil)
	if resp.StatusCode != http.StatusOK || policy["mode"] != "blocked" || policy["cross_site_feed"] != false {
		t.Fatalf("identity policy validation status = %d %#v", resp.StatusCode, policy)
	}
}

func TestNewAPICriticalPathAggregatesOutOfOrderStepsAndExposesStrategyConfig(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}

	profile := profiles.Build(cfg)[model.ProductNewAPI]
	public := &inProcessClient{handler: a.publicHandler(profile), cookies: map[string]string{}}
	password := "Password123!"
	if resp, _ := doJSON(t, public, http.MethodPost, "/api/user/register", map[string]string{"username": "critical-path-user", "password": password}); resp.StatusCode != http.StatusOK {
		t.Fatalf("registration status = %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, public, http.MethodPost, "/api/user/login", map[string]string{"username": "critical-path-user", "password": password}); resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, public, http.MethodPost, "/api/user/checkin", map[string]any{}); resp.StatusCode != http.StatusOK {
		t.Fatalf("check-in status = %d", resp.StatusCode)
	}
	resp, tokenBody := doJSON(t, public, http.MethodPost, "/api/token", map[string]any{"name": "critical-path"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token creation status = %d %#v", resp.StatusCode, tokenBody)
	}
	tokenData := tokenBody["data"].(map[string]any)
	rawKey := tokenData["key"].(string)
	tokenID := tokenData["id"].(string)
	if resp, _ := doJSON(t, public, http.MethodPost, "/api/token/"+tokenID+"/key", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("key reveal status = %d", resp.StatusCode)
	}
	if resp, _ := doJSON(t, public, http.MethodGet, "/api/user/models", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("model list status = %d", resp.StatusCode)
	}
	if resp, _ := doRawJSON(t, public, http.MethodPost, "/v1/chat/completions", map[string]any{"model": "gpt-5.6-sol", "messages": []any{map[string]string{"role": "user", "content": "reply with ok"}}}, map[string]string{"Authorization": "Bearer " + rawKey}); resp.StatusCode != http.StatusOK {
		t.Fatalf("model invocation status = %d", resp.StatusCode)
	}

	resp, chains := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/interaction-chains?limit=20", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chain list status = %d %#v", resp.StatusCode, chains)
	}
	chainItems := chains["chains"].([]any)
	if len(chainItems) != 1 {
		t.Fatalf("critical path was split into multiple chains: %#v", chains)
	}
	chain := chainItems[0].(map[string]any)
	if chain["aggregation_mode"] != "session" || chain["event_count"].(float64) < 7 || chain["latest_observed_at"] == "" {
		t.Fatalf("chain aggregation metadata is incomplete: %#v", chain)
	}
	matched := false
	for _, value := range chain["matched_rule_ids"].([]any) {
		if value == "NEWAPI_NORMAL_USE_V1" {
			matched = true
		}
	}
	if !matched {
		t.Fatalf("critical New API path did not match the unordered rule: %#v", chain)
	}

	resp, configBody := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/chain-config", nil)
	if resp.StatusCode != http.StatusOK || configBody["config"].(map[string]any)["mode"] != "session" {
		t.Fatalf("chain config GET = %d %#v", resp.StatusCode, configBody)
	}
	resp, updated := doJSON(t, admin, http.MethodPut, cfg.AdminPath+"admin/api/v1/chain-config", map[string]any{"mode": "source_ip_product", "window_seconds": 600, "max_events": 100})
	if resp.StatusCode != http.StatusOK || updated["config"].(map[string]any)["mode"] != "source_ip_product" {
		t.Fatalf("chain config PUT = %d %#v", resp.StatusCode, updated)
	}
	resp, packsBody := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/packs", nil)
	if resp.StatusCode != http.StatusOK || packsBody["strategies"] == nil || packsBody["chain_aggregation"].(map[string]any)["mode"] != "source_ip_product" {
		t.Fatalf("pack strategy overview = %d %#v", resp.StatusCode, packsBody)
	}
	strategies := packsBody["strategies"].([]any)
	var newAPIStrategy map[string]any
	for _, value := range strategies {
		strategy := value.(map[string]any)
		if strategy["product"] == model.ProductNewAPI {
			newAPIStrategy = strategy
		}
	}
	if newAPIStrategy == nil || newAPIStrategy["rule_count"].(float64) < 6 {
		t.Fatalf("New API strategy rules missing: %#v", newAPIStrategy)
	}
	resp, invalid := doJSON(t, admin, http.MethodPut, cfg.AdminPath+"admin/api/v1/chain-config", map[string]any{"mode": "session", "window_seconds": 30, "max_events": 1})
	if resp.StatusCode != http.StatusUnprocessableEntity || invalid["error"] == nil {
		t.Fatalf("invalid chain config status = %d %#v", resp.StatusCode, invalid)
	}
}

func TestInteractionChainRefreshOrdersByLatestRecordDeterministically(t *testing.T) {
	a, _, st := newTestApp(t, true)
	defer st.Close()
	base := time.Now().UTC()
	events := []model.Event{
		{EventID: "newer-last", Sequence: 4, SessionID: "session-new", Product: model.ProductOllama, ObservedAt: base.Add(4 * time.Second), EventType: "http.request.classified"},
		{EventID: "older-last", Sequence: 3, SessionID: "session-old", Product: model.ProductOllama, ObservedAt: base.Add(3 * time.Second), EventType: "http.request.classified"},
		{EventID: "newer-first", Sequence: 2, SessionID: "session-new", Product: model.ProductOllama, ObservedAt: base.Add(2 * time.Second), EventType: "http.request.classified"},
		{EventID: "older-first", Sequence: 1, SessionID: "session-old", Product: model.ProductOllama, ObservedAt: base, EventType: "http.request.classified"},
	}
	views := a.buildInteractionChainViews(events, model.DefaultInteractionChainConfig())
	if len(views) != 2 || views[0].SessionID != "session-new" || views[1].SessionID != "session-old" {
		t.Fatalf("chain ordering was not latest-first: %#v", views)
	}
	if len(views[0].Events) != 2 || views[0].Events[0].EventID != "newer-first" || views[0].Events[1].EventID != "newer-last" {
		t.Fatalf("chain events were not chronological: %#v", views[0].Events)
	}
	if config := st.InteractionChainConfig(); config.Mode != model.InteractionChainBySession {
		t.Fatalf("default interaction chain config changed unexpectedly: %#v", config)
	}
}

func TestLocalAdminImportSourcesIndicatorsAndIdentityDecisions(t *testing.T) {
	a, cfg, st := newTestApp(t, true)
	defer st.Close()
	admin := &inProcessClient{handler: a.adminHandler(), cookies: map[string]string{}}
	if resp, _ := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/auth/login", map[string]string{"username": "owner", "password": "correct horse battery staple"}); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin login status = %d", resp.StatusCode)
	}

	resp, created := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/import-sources", map[string]string{"id": "promptpot-local", "source_type": "promptpot-jsonl", "root_path_alias": "promptpot_exports", "product": model.ProductOllama, "schema_version": "promptpot-jsonl-v1"})
	if resp.StatusCode != http.StatusCreated || created["source"] == nil {
		t.Fatalf("import source create = %d %#v", resp.StatusCode, created)
	}
	if source := created["source"].(map[string]any); source["filesystem_access"] != false || source["online_fetch"] != false || source["read_only"] != true {
		t.Fatalf("import source safety contract missing: %#v", source)
	}
	for _, action := range []string{"validate", "dry-run", "enable", "disable"} {
		resp, result := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/import-sources/promptpot-local:"+action, nil)
		if resp.StatusCode != http.StatusOK || result["source"] == nil {
			t.Fatalf("import source %s = %d %#v", action, resp.StatusCode, result)
		}
	}
	resp, _ = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/import-sources", map[string]string{"id": "unsafe", "source_type": "promptpot-jsonl", "root_path_alias": "/etc", "product": model.ProductOllama, "schema_version": "promptpot-jsonl-v1"})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("unsafe import source status = %d", resp.StatusCode)
	}

	public := &inProcessClient{handler: a.publicHandler(profiles.Build(cfg)[model.ProductOllama]), cookies: map[string]string{}}
	resp, _ = doJSON(t, public, http.MethodPost, "/api/generate", map[string]any{"model": "qwen3.6:35b-a3b", "prompt": "fetch http://127.0.0.1/canary", "stream": false})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("indicator seed request status = %d", resp.StatusCode)
	}
	resp, indicators := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators", nil)
	if resp.StatusCode != http.StatusOK || len(indicators["items"].([]any)) == 0 {
		t.Fatalf("indicator list = %d %#v", resp.StatusCode, indicators)
	}
	indicator := indicators["items"].([]any)[0].(map[string]any)
	indicatorID := indicator["id"].(string)
	resp, _ = doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators?min_score=not-an-integer", nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid indicator filter status = %d", resp.StatusCode)
	}
	resp, decision := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/indicators/"+url.PathEscape(indicatorID)+":approve?status=approved", map[string]any{"reason": "local test review", "ttl_seconds": 3600})
	if resp.StatusCode != http.StatusOK || decision["permanent_block"] != false {
		t.Fatalf("indicator approve = %d %#v", resp.StatusCode, decision)
	}
	resp, approved := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators?status=approved&min_score=30&min_sensor_count=1", nil)
	if resp.StatusCode != http.StatusOK || len(approved["items"].([]any)) != 1 || approved["items"].([]any)[0].(map[string]any)["status"] != "approved" {
		t.Fatalf("approved indicator filter = %d %#v", resp.StatusCode, approved)
	}
	raw := admin.do(t, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators/ips?status=approved&format=nftables", nil, "")
	body, _ := io.ReadAll(raw.Body)
	_ = raw.Body.Close()
	if raw.StatusCode != http.StatusOK || !strings.Contains(string(body), "approved_ipv4") || !strings.Contains(string(body), "203.0.113.0") && !strings.Contains(string(body), "192.0.2.1") {
		t.Fatalf("nftables export = %d %s", raw.StatusCode, body)
	}
	raw = admin.do(t, http.MethodGet, cfg.AdminPath+"admin/api/v1/indicators/ips?status=approved&format=stix2", nil, "")
	body, _ = io.ReadAll(raw.Body)
	_ = raw.Body.Close()
	if raw.StatusCode != http.StatusOK || !strings.Contains(string(body), `"type": "bundle"`) || !strings.Contains(string(body), `"type": "indicator"`) {
		t.Fatalf("stix2 export = %d %s", raw.StatusCode, body)
	}
	resp, export := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/exports", map[string]any{"status": "approved", "format": "csv"})
	if resp.StatusCode != http.StatusAccepted || export["status"] != "ready" || export["id"] == nil {
		t.Fatalf("export create = %d %#v", resp.StatusCode, export)
	}
	exportID := export["id"].(string)
	resp, exportStatus := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/exports/"+url.PathEscape(exportID), nil)
	if resp.StatusCode != http.StatusOK || exportStatus["checksum"] != export["checksum"] {
		t.Fatalf("export status = %d %#v", resp.StatusCode, exportStatus)
	}
	raw = admin.do(t, http.MethodGet, cfg.AdminPath+"admin/api/v1/exports/"+url.PathEscape(exportID)+"/download", nil, "")
	body, _ = io.ReadAll(raw.Body)
	_ = raw.Body.Close()
	if raw.StatusCode != http.StatusOK || !strings.Contains(string(body), "ip,score") || raw.Header.Get("X-Content-SHA256") != export["checksum"] {
		t.Fatalf("export download = %d %s", raw.StatusCode, body)
	}

	user := model.HoneyUser{ID: "user_identity_test", InstanceID: cfg.InstanceID, UsernameFP: "user-fp", PasswordFP: "password-fp"}
	identity, err := st.BindHoneyIdentity(model.HoneyIdentity{ID: "identity-test", Provider: "github", SubjectHMAC: "subject-hmac-test", PolicyMode: "local_only"}, user)
	if err != nil {
		t.Fatal(err)
	}
	resp, identityDetail := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/identities/"+url.PathEscape(identity.ID), nil)
	if resp.StatusCode != http.StatusOK || identityDetail["identity"].(map[string]any)["honey_user_id"] != user.ID {
		t.Fatalf("identity detail = %d %#v", resp.StatusCode, identityDetail)
	}
	resp, identityDecision := doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/identity-indicators/"+url.PathEscape(identity.ID)+":challenge", map[string]any{"reason": "needs local review", "ttl_seconds": 3600})
	if resp.StatusCode != http.StatusOK || identityDecision["cross_site_feed"] != false {
		t.Fatalf("identity challenge = %d %#v", resp.StatusCode, identityDecision)
	}
	resp, identityDecision = doJSON(t, admin, http.MethodPost, cfg.AdminPath+"admin/api/v1/identity-indicators/"+url.PathEscape(identity.ID)+":revoke", map[string]string{"reason": "local revoke"})
	if resp.StatusCode != http.StatusOK || identityDecision["permanent_block"] != false {
		t.Fatalf("identity revoke = %d %#v", resp.StatusCode, identityDecision)
	}
	resp, identityList := doJSON(t, admin, http.MethodGet, cfg.AdminPath+"admin/api/v1/identity-indicators", nil)
	if resp.StatusCode != http.StatusOK || identityList["items"].([]any)[0].(map[string]any)["status"] != "revoked" {
		t.Fatalf("identity indicator list = %d %#v", resp.StatusCode, identityList)
	}
}
