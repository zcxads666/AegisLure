package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zcxads666/AegisLure/internal/detect"
	"github.com/zcxads666/AegisLure/internal/model"
	"github.com/zcxads666/AegisLure/internal/packs"
)

func TestCheckedInDefaultDetectorRulePackMatchesCompiled(t *testing.T) {
	var checked packs.DetectorRulePack
	if err := packs.LoadJSON("../../configs/detector-rules.json", &checked, 1<<20); err != nil {
		t.Fatal(err)
	}
	want := defaultDetectorRulePack()
	if err := packs.ValidateDetectorRulePack(checked); err != nil {
		t.Fatalf("checked-in detector pack is invalid: %v", err)
	}
	gotJSON, err := json.Marshal(checked)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("checked-in detector pack drifted from compiled default")
	}
}

func TestBuiltinDetectorRulesDefaultToLatestCoveragePack(t *testing.T) {
	a, _, st := newTestApp(t, false)
	defer st.Close()
	pack, ok := a.activePack(model.PackKindDetector)
	if !ok || pack.ID != "builtin-rules-v3" || pack.Revision != "builtin-rules-v3" {
		t.Fatalf("active detector pack = %#v, found=%v", pack, ok)
	}
	var document packs.DetectorRulePack
	if err := json.Unmarshal(pack.Definition, &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Rules) != 48 {
		t.Fatalf("active detector rule count = %d, want 48", len(document.Rules))
	}
}

func TestDefaultDetectorRulePackCoversReferenceBehaviors(t *testing.T) {
	pack := defaultDetectorRulePack()
	if err := packs.ValidateDetectorRulePack(pack); err != nil {
		t.Fatalf("default detector pack is invalid: %v", err)
	}

	fixtures := map[string][]model.Event{
		"SSRF_URL_CLASS_V1":                       {ruleEvent("ollama", "ollama.tags", `{"url":"http://127.0.0.1"}`)},
		"PATH_TRAVERSAL_V1":                       {ruleEventWithMethod("localai", "localai.models.delete", "POST", `{"path":"../../etc/passwd"}`)},
		"SERIALIZATION_PROBE_V1":                  {ruleEventWithMethod("vllm", "openai.chat.completions", "POST", `{"payload":"pickle __reduce__"}`)},
		"VLLM_KEY_GAP_BYPASS_V1":                  vLLMKeyGapFixture(),
		"HONEY_TOKEN_REUSE_V1":                    {{Product: model.ProductNewAPI, AuthOutcome: "leaked_key_reused"}},
		"NEWAPI_NORMAL_USE_V1":                    newAPINormalUseFixture(),
		"NEWAPI_AUTH_SSRF_V1":                     {ruleEvent(model.ProductNewAPI, "openai.chat.completions", `{"image_url":"http://127.0.0.1"}`)},
		"NEWAPI_SSRF_REDIRECT_BYPASS_V1":          {ruleEvent(model.ProductNewAPI, "openai.responses", `{"url":"https://public.example/redirect","redirect":"http://127.0.0.1"}`)},
		"NEWAPI_UNSPECIFIED_SSRF_V1":              {ruleEvent(model.ProductNewAPI, "openai.chat.completions", `{"url":"http://0.0.0.0/metadata"}`)},
		"NEWAPI_TOKEN_SEARCH_WILDCARD_DOS_V1":     {ruleEventWithQuery(model.ProductNewAPI, "newapi.token.list", "search=%25")},
		"NEWAPI_VIDEO_PROXY_IDOR_V1":              {ruleEventWithQuery(model.ProductNewAPI, "newapi.video.proxy", "task=other-task")},
		"NEWAPI_USER_LIST_TOKEN_LEAK_V1":          newAPIUserListLeakFixture(),
		"NEWAPI_QUOTA_OVERFLOW_V1":                {ruleEvent(model.ProductNewAPI, "openai.chat.completions", `{"max_tokens":1000001}`)},
		"NEWAPI_QUOTA_CONCURRENCY_V1":             newAPIQuotaConcurrencyFixture(),
		"NEWAPI_PAYMENT_WEBHOOK_BODY_DOS_V1":      {{Product: model.ProductNewAPI, RouteTemplate: "newapi.payment.webhook", RequestBytes: 300 * 1024}},
		"NEWAPI_BINDING_CSRF_V1":                  {{Product: model.ProductNewAPI, RouteTemplate: "newapi.user.oauth-bindings", Method: "GET", OriginClass: "cross_site"}},
		"VLLM_MEDIACONNECTOR_SSRF_V1":             {ruleEvent(model.ProductVLLM, "openai.chat.completions", `{"url":"http://169.254.169.254/latest"}`)},
		"VLLM_EMBEDDING_DESERIALIZATION_V1":       {ruleEvent(model.ProductVLLM, "openai.chat.completions", `{"embedding":"serialized tensor payload"}`)},
		"VLLM_VIDEO_FRAME_DOS_V1":                 {ruleEvent(model.ProductVLLM, "openai.chat.completions", `{"video":"jpeg frame 1000"}`)},
		"VLLM_REQUEST_SIZE_DOS_V1":                {{Product: model.ProductVLLM, RouteTemplate: "openai.chat.completions", RequestBytes: 300 * 1024}},
		"VLLM_PROMPT_FANOUT_DOS_V1":               {ruleEvent(model.ProductVLLM, "openai.completions", `{"prompts":[1,2,3,4]}`)},
		"VLLM_STRUCTURED_OUTPUT_REGEX_DOS_V1":     {ruleEvent(model.ProductVLLM, "openai.chat.completions", `{"response_format":{"regex":"a+a+"}}`)},
		"VLLM_MULTIMODAL_VIDEO_RCE_V1":            {ruleEvent(model.ProductVLLM, "openai.chat.completions", `{"video":{"image_url":"http://example.test/media"}}`)},
		"VLLM_AUDIO_RESOURCE_DOS_V1":              {ruleEvent(model.ProductVLLM, "openai.chat.completions", `{"audio":"gzip","sample_rate":1000000}`)},
		"OLLAMA_DNS_REBINDING_V1":                 {{Product: model.ProductOllama, OriginClass: "cross_site"}},
		"OLLAMA_MODEL_PATH_PROBE_V1":              {ruleEvent(model.ProductOllama, "ollama.create", `{"digest":"../../etc/passwd"}`)},
		"OLLAMA_GGUF_PARSE_DOS_V1":                {ruleEvent(model.ProductOllama, "ollama.blob", `{"gguf":"invalid header magic"}`)},
		"OLLAMA_PULL_GZIP_BOMB_V1":                {ruleEvent(model.ProductOllama, "ollama.pull", `{"registry":"https://registry.example","compression":"gzip"}`)},
		"OLLAMA_MANIFEST_ARRAY_DOS_V1":            {ruleEvent(model.ProductOllama, "ollama.pull", `{"manifest":{"layers":10000}}`)},
		"OLLAMA_REGISTRY_TOKEN_EXPOSURE_V1":       {ruleEvent(model.ProductOllama, "ollama.pull", `{"registry":"registry.example","realm":"auth","token":"probe"}`)},
		"OLLAMA_GGUF_LOADER_DISCLOSURE_V1":        {ruleEvent(model.ProductOllama, "ollama.create", `{"gguf":"metadata quantize push export"}`)},
		"OLLAMA_GGUF_ALLOCATION_DOS_V1":           {ruleEvent(model.ProductOllama, "ollama.blob", `{"gguf":"dimension length 1000000"}`)},
		"SGLANG_LORA_DESERIALIZATION_V1":          {ruleEvent(model.ProductSGLang, "sglang.lora.load", `{"tensor":"serialized base64 object"}`)},
		"SGLANG_DUMPER_RCE_PROBE_V1":              {ruleEvent(model.ProductSGLang, "sglang.dumper", `{"dump":"pickle worker command"}`)},
		"SGLANG_MULTIMODAL_SSRF_V1":               {ruleEvent(model.ProductSGLang, "openai.chat.completions", `{"image_url":"http://10.0.0.4/internal"}`)},
		"SGLANG_WEIGHT_UPDATE_DESERIALIZATION_V1": {ruleEvent(model.ProductSGLang, "sglang.weights.update", `{"model_path":"/models","torch":"load weights"}`)},
		"SGLANG_SERVER_INFO_ENUM_V1":              {{Product: model.ProductSGLang, RouteTemplate: "sglang.server_info", Status: 200}},
		"SGLANG_SERVER_INFO_KEY_REUSE_V1":         {{Product: model.ProductSGLang, RouteTemplate: "sglang.server_info", AuthOutcome: "leaked_key_reused"}},
		"SGLANG_WEIGHT_EXFILTRATION_V1":           {ruleEvent(model.ProductSGLang, "sglang.weights.get", `{"weight":"broadcast rank tensor transfer"}`)},
		"SGLANG_ZMQ_PICKLE_PROBE_V1":              {ruleEvent(model.ProductSGLang, "sglang.zmq", `{"zmq":"pickle serialized frame broker"}`)},
		"LOCALAI_AUDIO_COMMAND_INJECTION_V1":      {ruleEvent(model.ProductLocalAI, "localai.audio.transcriptions", `{"filename":"x;ffmpeg"}`)},
		"LOCALAI_MODEL_DELETE_TRAVERSAL_V1":       {ruleEvent(model.ProductLocalAI, "localai.models.delete", `{"model":"../../etc/passwd"}`)},
		"LOCALAI_MODEL_APPLY_SSRF_V1":             {ruleEvent(model.ProductLocalAI, "localai.models.apply", `{"url":"file:///etc/passwd"}`)},
		"LOCALAI_ARCHIVE_TRAVERSAL_V1":            {ruleEvent(model.ProductLocalAI, "localai.models.apply", `{"archive":"tar entry ../etc/passwd"}`)},
		"LOCALAI_BACKEND_EXECUTION_V1":            {ruleEvent(model.ProductLocalAI, "localai.models.apply", `{"backend":"x.so","executable":"true"}`)},
		"LOCALAI_LEGACY_CSRF_V1":                  {{Product: model.ProductLocalAI, RouteTemplate: "localai.models.apply", OriginClass: "cross_site"}},
		"LOCALAI_SEARCH_XSS_V1":                   {ruleEventWithQuery(model.ProductLocalAI, "localai.models.available", "search=%3Cscript%3E")},
		"LOCALAI_RBAC_ENUMERATION_V1":             {{Product: model.ProductLocalAI, RouteTemplate: "localai.models.apply", AuthOutcome: "missing"}},
	}

	if len(pack.Rules) != len(fixtures) {
		t.Fatalf("default detector pack has %d rules but %d fixtures", len(pack.Rules), len(fixtures))
	}
	for _, rule := range pack.Rules {
		events, ok := fixtures[rule.ID]
		if !ok {
			t.Errorf("missing fixture for default rule %s", rule.ID)
			continue
		}
		result := detect.EvaluateRuleSet([]packs.DetectorRule{rule}, events)
		if len(result.MatchedRuleIDs) != 1 || result.MatchedRuleIDs[0] != rule.ID {
			t.Errorf("rule %s did not match fixture: events=%+v result=%+v", rule.ID, events, result)
		}
	}
}

func ruleEvent(product, route, body string) model.Event {
	return ruleEventWithMethod(product, route, "POST", body)
}

func ruleEventWithMethod(product, route, method, body string) model.Event {
	return model.Event{Product: product, RouteTemplate: route, Method: method, BodyPreview: body, Status: 200, ObservedAt: time.Now().UTC()}
}

func ruleEventWithQuery(product, route, query string) model.Event {
	return model.Event{Product: product, RouteTemplate: route, Method: "GET", QueryPreview: query, Status: 200, ObservedAt: time.Now().UTC()}
}

func vLLMKeyGapFixture() []model.Event {
	base := time.Now().UTC()
	return []model.Event{
		{Product: model.ProductVLLM, RouteTemplate: "openai.chat.completions", EventType: "llm.invoke.rejected", ObservedAt: base},
		{Product: model.ProductVLLM, RouteTemplate: "vllm.invocations", EventType: "llm.invoke.accepted", ExecutionOutcome: "synthetic_accepted", ObservedAt: base.Add(time.Second)},
		{Product: model.ProductVLLM, RouteTemplate: "vllm.invocations", EventType: "llm.stream.completed", ObservedAt: base.Add(2 * time.Second)},
	}
}

func newAPINormalUseFixture() []model.Event {
	base := time.Now().UTC()
	steps := []string{"newapi.user.register.success", "newapi.user.login.success", "newapi.checkin.success", "newapi.token.created", "newapi.models.listed", "llm.invoke.accepted"}
	events := make([]model.Event, 0, len(steps))
	for index, step := range steps {
		events = append(events, model.Event{Product: model.ProductNewAPI, EventType: step, ObservedAt: base.Add(time.Duration(index) * time.Second)})
	}
	return events
}

func newAPIUserListLeakFixture() []model.Event {
	base := time.Now().UTC()
	return []model.Event{
		{Product: model.ProductNewAPI, RouteTemplate: "newapi.user.list", EventType: "http.request.classified", ObservedAt: base},
		{Product: model.ProductNewAPI, RouteTemplate: "openai.chat.completions", EventType: "newapi.honey_key.reused", AuthOutcome: "leaked_key_reused", ObservedAt: base.Add(time.Second)},
	}
}

func newAPIQuotaConcurrencyFixture() []model.Event {
	base := time.Now().UTC()
	return []model.Event{
		{Product: model.ProductNewAPI, EventType: "llm.invoke.accepted", ObservedAt: base},
		{Product: model.ProductNewAPI, RouteTemplate: "newapi.user.setting", EventType: "http.request.classified", ObservedAt: base.Add(time.Second)},
		{Product: model.ProductNewAPI, EventType: "llm.invoke.accepted", ObservedAt: base.Add(2 * time.Second)},
	}
}
